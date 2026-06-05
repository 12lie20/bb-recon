import re
import aiohttp
import asyncio
import logging
logger = logging.getLogger("bb-recon")

from core.ui import *
from core.utils import *
from core.utils import ensure_async
from core.http import http_probe

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "desc": "HSTS — Forces HTTPS connections",
        "severity": "HIGH",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "Content-Security-Policy": {
        "desc": "CSP — Prevents XSS, data injection attacks",
        "severity": "HIGH",
        "recommendation": "Add a strict CSP policy. At minimum: default-src 'self'",
    },
    "X-Frame-Options": {
        "desc": "Clickjacking protection",
        "severity": "MEDIUM",
        "recommendation": "Add: X-Frame-Options: DENY (or SAMEORIGIN)",
    },
    "X-Content-Type-Options": {
        "desc": "Prevents MIME-type sniffing",
        "severity": "MEDIUM",
        "recommendation": "Add: X-Content-Type-Options: nosniff",
    },
    "Permissions-Policy": {
        "desc": "Controls browser feature access (camera, mic, etc.)",
        "severity": "LOW",
        "recommendation": "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
    },
    "Referrer-Policy": {
        "desc": "Controls referrer information leakage",
        "severity": "LOW",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Cache-Control": {
        "desc": "Cache management / Information Disclosure",
        "severity": "MEDIUM",
        "recommendation": "Ensure sensitive endpoints have: Cache-Control: no-store, no-cache, must-revalidate"
    },
    "Access-Control-Allow-Origin": {
        "desc": "CORS Misconfiguration Risk",
        "severity": "HIGH",
        "recommendation": "Ensure this is not extremely permissive (e.g. '*') on authenticated endpoints."
    },
    "Cross-Origin-Embedder-Policy": {
        "desc": "COEP — Prevents loading cross-origin resources without explicit opt-in",
        "severity": "LOW",
        "recommendation": "Add: Cross-Origin-Embedder-Policy: require-corp",
    },
    "Cross-Origin-Opener-Policy": {
        "desc": "COOP — Isolates browsing context to prevent cross-origin attacks",
        "severity": "LOW",
        "recommendation": "Add: Cross-Origin-Opener-Policy: same-origin",
    },
    "Cross-Origin-Resource-Policy": {
        "desc": "CORP — Controls which origins can read resources",
        "severity": "LOW",
        "recommendation": "Add: Cross-Origin-Resource-Policy: same-origin",
    },
}
CSP_DANGEROUS = [
    ("unsafe-inline",  "Allows inline scripts — XSS risk"),
    ("unsafe-eval",    "Allows eval() — XSS risk"),
    ("data:",          "Allows data: URIs — XSS bypass"),
    ("blob:",          "Allows blob: URIs — XSS bypass"),
    ("*",              "Wildcard source — too permissive / bypass"),
    ("http:",          "Allows HTTP — mixed content risk"),
    ("https://*",      "Allows any HTTPS source — XSS risk if CDN compromised"),
    ("'unsafe-hashes'","Allows hash-based inline scripts — potential XSS"),
    ("wasm-unsafe-eval","Allows WebAssembly eval — potential abuse"),
]

DANGEROUS_HEADERS_PRESENT = [
    ("X-Powered-By",      "HIGH",   "Server technology disclosure — remove or obfuscate"),
    ("Server",            "MEDIUM", "Server version disclosure — consider hiding version"),
    ("X-AspNet-Version",  "HIGH",   "ASP.NET version disclosure — remove"),
    ("X-AspNetMvc-Version","HIGH",  "ASP.NET MVC version disclosure — remove"),
    ("X-Debug-Token",     "HIGH",   "Debug token exposed — indicates debug mode"),
    ("X-Debug-Token-Link","HIGH",   "Debug profiler link exposed"),
    ("X-Runtime",         "LOW",    "Runtime info disclosure — timing attacks possible"),
]

@ensure_async
async def run_headers(domain, live_lines, out):
    section(9, "SECURITY HEADERS AUDIT  (11 headers + CSP deep)")
    findings = []
    hosts = set()
    for line in live_lines:
        m = re.match(r"(https?://[^\s\[/]+)", line)
        if m: hosts.add(m.group(1))
    hosts.add(f"https://{domain}")
    
    async with aiohttp.ClientSession() as session:
        async def check_host(host_url):
            code, body, hdrs, _ = await http_probe(session, host_url + "/", timeout=8)
            return host_url, code, hdrs
            
        tasks = [check_host(u) for u in sorted(hosts)[:25]]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for res in results:
            if isinstance(res, Exception): continue
            host_url, code, hdrs = res
            if code == 0: continue
            
            hdrs_lower = {k.lower(): v for k, v in hdrs.items()}
            missing = []
            weak = []
            dangerous_present = []
            
            for header, meta in SECURITY_HEADERS.items():
                h_lower = header.lower()
                if h_lower not in hdrs_lower:
                    missing.append((header, meta))
                else:
                    val = hdrs_lower[h_lower]
                    if h_lower == "content-security-policy":
                        for dangerous, reason in CSP_DANGEROUS:
                            if dangerous in val.lower():
                                weak.append((header, f"Contains '{dangerous}': {reason}"))
                        if "report-uri" not in val.lower() and "report-to" not in val.lower():
                            weak.append((header, "No CSP reporting configured"))
                    if h_lower == "strict-transport-security":
                        m_age = re.search(r"max-age=(\d+)", val)
                        if m_age and int(m_age.group(1)) < 31536000:
                            weak.append((header, f"max-age={m_age.group(1)} (< 1 year)"))
                        if "includesubdomains" not in val.lower():
                            weak.append((header, "Missing includeSubDomains"))
                        if "preload" not in val.lower():
                            weak.append((header, "Missing preload directive"))
                    if h_lower == "x-frame-options" and val.upper() not in ("DENY", "SAMEORIGIN"):
                        weak.append((header, f"Unusual value: {val}"))

            for hdr_name, sev, reason in DANGEROUS_HEADERS_PRESENT:
                if hdr_name.lower() in hdrs_lower:
                    dangerous_present.append((hdr_name, sev, reason, hdrs_lower[hdr_name.lower()]))
                        
            if missing or weak or dangerous_present:
                host_short = host_url.replace("https://", "").replace("http://", "")
                print(GRY+"│  "+RESET+WHT+BOLD+host_short+RESET)
                for header, meta in missing:
                    sev = meta["severity"]
                    col = RED+BOLD if sev == "HIGH" else (YLW if sev == "MEDIUM" else GRY)
                    print(GRY+"│    "+RESET+col+f"MISSING  {header}"+RESET+
                          GRY+DIM+f"  ({meta['desc']})"+RESET)
                    findings.append({"host": host_url, "header": header,
                                     "issue": "missing", "severity": sev,
                                     "recommendation": meta["recommendation"]})
                for header, issue in weak:
                    print(GRY+"│    "+RESET+ORG+f"WEAK     {header}"+RESET+
                          GRY+DIM+f"  ({issue})"+RESET)
                    findings.append({"host": host_url, "header": header,
                                     "issue": f"weak: {issue}", "severity": "MEDIUM"})
                for hdr_name, sev, reason, val in dangerous_present:
                    col = RED+BOLD if sev == "HIGH" else YLW
                    print(GRY+"│    "+RESET+col+f"EXPOSED  {hdr_name}"+RESET+
                          GRY+DIM+f"  ({reason}: {val[:50]})"+RESET)
                    findings.append({"host": host_url, "header": hdr_name,
                                     "issue": f"exposed: {reason}", "severity": sev,
                                     "value": val[:100]})
                print(GRY+"│"+RESET)
                
    save_json(f"{out}/security_headers.json", findings)
    high_count = len([f for f in findings if f.get("severity") == "HIGH"])
    ok(f"Security header issues: {BOLD}{len(findings)}{RESET}  "
       f"({BOLD}{high_count}{RESET} HIGH severity)")
    _end()
    return findings

audit_security_headers = run_headers
