import re
import hashlib
from core.ui import vuln, found, CYN, RED, GRY, RESET, info
from core.http import http_probe
from . import BaseScanner
import logging
logger = logging.getLogger("bb-recon")

UNKEYED_HEADERS = [
    ("X-Forwarded-Host", "bbr3c0n-cache-poison.evil.com", "X-Forwarded-Host"),
    ("X-Host", "bbr3c0n-cache-poison.evil.com", "X-Host"),
    ("X-Forwarded-Server", "bbr3c0n-cache-poison.evil.com", "X-Forwarded-Server"),
    ("X-Original-URL", "/bbr3c0n-poisoned", "X-Original-URL"),
    ("X-Rewrite-URL", "/bbr3c0n-poisoned", "X-Rewrite-URL"),
    ("X-Forwarded-Scheme", "nothttps", "X-Forwarded-Scheme"),
    ("X-Forwarded-Proto", "nothttps", "X-Forwarded-Proto"),
    ("X-Forwarded-Port", "1337", "X-Forwarded-Port"),
    ("X-Original-Host", "bbr3c0n-cache-poison.evil.com", "X-Original-Host"),
    ("Forwarded", "for=127.0.0.1;host=bbr3c0n-cache-poison.evil.com", "Forwarded"),
    ("X-Custom-IP-Authorization", "127.0.0.1", "X-Custom-IP-Auth"),
    ("CF-Connecting-IP", "127.0.0.1", "CF-Connecting-IP"),
    ("True-Client-IP", "127.0.0.1", "True-Client-IP"),
    ("Fastly-Client-IP", "127.0.0.1", "Fastly-Client-IP"),
]

CACHE_BUSTER_PARAM = "bbcb"
POISON_MARKER = "bbr3c0n-cache-poison"

class CachePoisonScanner(BaseScanner):
    async def scan(self, url: str) -> list:
        findings = []
        await self._waf_sleep()
        parsed, _ = self._get_params(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        import random, string
        buster = "".join(random.choices(string.ascii_lowercase, k=8))
        base_test = f"{base}/?{CACHE_BUSTER_PARAM}={buster}"

        code_n, body_n, hdrs_n, ms_n = await http_probe(self.session, base_test, timeout=8)
        if code_n == 0:
            return findings

        has_cache = any(
            h.lower() in ("x-cache", "cf-cache-status", "x-cache-status",
                          "x-varnish", "x-cdn", "age", "x-fastly-request-id",
                          "x-served-by", "x-cache-hit")
            for h in hdrs_n
        )
        age = hdrs_n.get("Age", hdrs_n.get("age", ""))
        cache_ctrl = hdrs_n.get("Cache-Control", "").lower()
        is_cached = has_cache or bool(age) or "public" in cache_ctrl

        if not is_cached:
            info("No caching detected — cache poisoning unlikely")
            return findings

        info(f"Cache indicators detected — testing {len(UNKEYED_HEADERS)} unkeyed headers ...")
        body_n_hash = hashlib.md5(body_n.encode()).hexdigest() if body_n else ""

        for header_name, header_val, tag in UNKEYED_HEADERS:
            buster2 = "".join(random.choices(string.ascii_lowercase, k=8))
            test_url = f"{base}/?{CACHE_BUSTER_PARAM}={buster2}"

            try:
                code1, body1, hdrs1, _ = await http_probe(
                    self.session, test_url, timeout=8,
                    extra_headers={header_name: header_val}
                )
                await self._waf_sleep()

                if code1 == 0:
                    continue

                if POISON_MARKER in body1 or POISON_MARKER in str(hdrs1):
                    code2, body2, hdrs2, _ = await http_probe(
                        self.session, test_url, timeout=8
                    )

                    if POISON_MARKER in body2 or POISON_MARKER in str(hdrs2):
                        vuln(f"WEB CACHE POISONING via {tag}: {base}")
                        print(GRY+"│    "+RESET+CYN+f"Header: {header_name}: {header_val}"+RESET)
                        print(GRY+"│    "+RESET+RED+f"Poisoned value persisted in cache!"+RESET)
                        findings.append({
                            "type": "CachePoisoning", "url": base,
                            "header": header_name, "value": header_val,
                            "technique": tag, "severity": "CRITICAL",
                            "confidence": "CONFIRMED",
                        })
                        continue
                    else:
                        found(f"Cache poisoning reflected but not cached via {tag}")
                        findings.append({
                            "type": "CachePoisoning-reflected", "url": base,
                            "header": header_name, "technique": tag,
                            "severity": "MEDIUM", "confidence": "POSSIBLE",
                        })

                body1_hash = hashlib.md5(body1.encode()).hexdigest() if body1 else ""
                if body1_hash != body_n_hash and abs(len(body1) - len(body_n)) > 100:
                    found(f"Unkeyed header changes response via {tag}")
                    findings.append({
                        "type": "CachePoisoning-diff", "url": base,
                        "header": header_name, "technique": tag,
                        "severity": "MEDIUM", "confidence": "LIKELY",
                        "evidence": f"Response size diff: {abs(len(body1)-len(body_n))}b",
                    })

            except Exception as e:
                logger.debug(f"Cache poison test failed for {tag}: {e}")

        fat_get_url = f"{base}/?{CACHE_BUSTER_PARAM}={''.join(random.choices(string.ascii_lowercase, k=8))}"
        try:
            code_fat, body_fat, _, _ = await http_probe(
                self.session, fat_get_url, timeout=8, method="GET",
                data="x=1&admin=true",
                extra_headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            if code_fat == 200 and ("admin" in body_fat.lower() or len(body_fat) != len(body_n)):
                found(f"Fat GET request accepted: {base}")
                findings.append({
                    "type": "CachePoisoning-FatGET", "url": base,
                    "severity": "MEDIUM", "confidence": "POSSIBLE",
                    "note": "Server processes GET request body — potential cache poisoning vector",
                })
        except Exception:
            pass

        return findings
