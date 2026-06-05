import re
import urllib.parse
import base64
import asyncio
import aiohttp
import logging
logger = logging.getLogger("bb-recon")

from core.ui import *
from core.utils import *
from core.utils import ensure_async
from core.http import http_probe

COMMON_MD5={
    "cfcd208495d565ef66e7dff9f98764da":"0",
    "c4ca4238a0b923820dcc509a6f75849b":"1",
    "c81e728d9d4c2f636f067f89cc14862c":"2",
    "eccbc87e4b5ce2fe28308fd9f2a7baf3":"3",
    "d41d8cd98f00b204e9800998ecf8427e":"(empty string)",
    "21232f297a57a5a743894a0e4a801fc3":"admin",
    "7fa3b767c460b54a2be4d49030b349c7":"password",
    "e10adc3949ba59abbe56e057f20f883e":"123456",
    "827ccb0eea8a706c4c34a16891f84e7b":"12345",
    "5f4dcc3b5aa765d61d8327deb882cf99":"password",
    "25f9e794323b453885f5181f1b624d0b":"123456789",
    "0d107d09f5bbe40cade3de5c71e9e9b7":"letmein",
    "098f6bcd4621d373cade4e832627b4f6":"test",
    "1a1dc91c907325c69271ddf0c944bc72":"pass",
}

@ensure_async
async def run_cookies(domain, out):
    section(6,"COOKIE / SESSION ANALYSIS")
    base_url = f"https://{domain}"
    findings = []
    pages = ["/", "/login", "/admin", "/api/", "/dashboard"]
    all_cookies = {}
    
    async with aiohttp.ClientSession() as session:
        tasks = [http_probe(session, base_url + page, timeout=8) for page in pages]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for i, res in enumerate(results):
            if isinstance(res, Exception):
                continue
            code, body, hdrs, ms = res
            if code == 0: continue
            raw_cookies = hdrs.get("Set-Cookie", "")
            if not raw_cookies: continue
            
            parts = re.split(r',\s*(?=[A-Za-z_][A-Za-z0-9_\-]*=)', raw_cookies)
            for part in parts:
                m = re.match(r"\s*([^=]+)=([^;]*)(.*)", part.strip(), re.DOTALL)
                if m:
                    name = m.group(1).strip()
                    val = m.group(2).strip()
                    flags = m.group(3).lower()
                    if name.lower() not in ('expires', 'path', 'domain', 'max-age'):
                        all_cookies[name] = {"value": val, "flags": flags, "page": pages[i], "code": code}
                        
        if not all_cookies:
            info("No cookies found"); _end(); return findings
            
        info(f"Cookies found: {len(all_cookies)}")
        print(GRY+"│"+RESET)
        for name, cdata in all_cookies.items():
            val = cdata["value"]; flags = cdata["flags"]
            issues = []
            if re.match(r"^[0-9a-f]{32}$", val, re.I):
                if val.lower() in COMMON_MD5:
                    issues.append(f"PREDICTABLE MD5 = md5({COMMON_MD5[val.lower()]})")
                else:
                    issues.append("MD5-format token — may be predictable")
            if len(val) > 8:
                unique_chars = len(set(val.lower()))
                if unique_chars < 8 and len(val) > 16:
                    issues.append(f"LOW ENTROPY (only {unique_chars} unique chars)")
            if "httponly" not in flags:
                issues.append("Missing HttpOnly flag (XSS risk)")
            if "secure" not in flags and base_url.startswith("https"):
                issues.append("Missing Secure flag")
            if "samesite" not in flags:
                issues.append("Missing SameSite flag (CSRF risk)")
            if re.match(r"^[A-Za-z0-9+/]{20,}={0,2}$", val):
                try:
                    decoded = base64.b64decode(val).decode("utf-8", errors="ignore")
                    if re.search(r"[a-z]{3,}", decoded, re.I):
                        issues.append(f"Base64 decodable: {decoded[:60]}")
                except Exception:
                    pass
            if re.match(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*", val):
                issues.append("JWT token — check alg:none and weak secret")
                try:
                    parts = val.split(".")
                    hdr = base64.b64decode(parts[0]+"==").decode("utf-8", errors="ignore")
                    payload = base64.b64decode(parts[1]+"==").decode("utf-8", errors="ignore")
                    issues.append(f"JWT header: {hdr[:80]}")
                    issues.append(f"JWT payload: {payload[:100]}")
                except Exception:
                    pass
            has_critical = any("PREDICTABLE" in i or "Base64" in i or "JWT" in i for i in issues)
            badge = (RED+BOLD+"[VULN]"+RESET if has_critical else
                   YLW+"[WARN]"+RESET if issues else GRY+"[OK]  "+RESET)
            print(GRY+"│  "+RESET+badge+"  "+WHT+f"{name}"+RESET+GRY+f" = {val[:40]}"+RESET)
            for issue in issues:
                col = RED+BOLD if any(x in issue for x in ("PREDICTABLE", "Base64", "JWT header")) else YLW
                print(GRY+"│         "+RESET+col+f"→ {issue}"+RESET)
                findings.append({"cookie": name, "value": val, "issue": issue})
            if not issues:
                print(GRY+"│         "+RESET+GRY+DIM+"→ No issues found"+RESET)
                
        print(GRY+"│"+RESET)
        info("Testing session fixation ...")
        test_sid = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0"
        fixated = False
        for s_name in ["PHPSESSID", "JSESSIONID", "ASPSESSIONID", "ASP.NET_SessionId"]:
            c2, b2, h2, _ = await http_probe(session, f"{base_url}/?{s_name}={test_sid}", timeout=6)
            sc2 = h2.get("Set-Cookie", "")
            if test_sid in sc2:
                found(f"Session fixation possible via GET parameter ({s_name})")
                findings.append({"cookie": s_name, "issue": f"Session Fixation via GET ({s_name})"})
                fixated = True
        
        if not fixated:
            ok("Session fixation: not vulnerable (server regenerates ID or ignores query string)")
            
    print(GRY+"│"+RESET)
    save_json(f"{out}/cookie_analysis.json", findings)
    vuln_count = len([f for f in findings if any(x in f.get("issue","") for x in
                    ("PREDICTABLE", "Base64", "JWT", "Fixation", "HttpOnly", "Secure"))])
    ok(f"Cookie issues found: {BOLD}{len(findings)}{RESET}  "
       f"({BOLD}{vuln_count}{RESET} critical/high)")
    _end()
    return findings

analyze_cookies = run_cookies

