import subprocess
import socket
import re
import asyncio
import aiohttp
import logging
logger = logging.getLogger("bb-recon")

from core.ui import *
from core.utils import *
from core.utils import ensure_async
from core.http import http_probe

TAKEOVER_FINGERPRINTS = [
    (re.compile(r"github\.io"),          "GitHub Pages",       "There isn't a GitHub Pages site here"),
    (re.compile(r"herokuapp\.com"),       "Heroku",             "No such app"),
    (re.compile(r"s3\.amazonaws\.com"),   "AWS S3",             "NoSuchBucket"),
    (re.compile(r"netlify\.app"),         "Netlify",            "Not Found"),
    (re.compile(r"azurewebsites\.net"),   "Azure",              "404 Web Site not found"),
    (re.compile(r"shopify\.com"),         "Shopify",            "Sorry, this shop is currently unavailable"),
    (re.compile(r"fastly\.net"),          "Fastly",             "Fastly error: unknown domain"),
    (re.compile(r"ghost\.io"),            "Ghost",              "The thing you were looking for is no longer here"),
    (re.compile(r"helpscoutdocs\.com"),   "HelpScout",          "No settings were found"),
    (re.compile(r"freshdesk\.com"),       "Freshdesk",          "There is no helpdesk here"),
    (re.compile(r"zendesk\.com"),         "Zendesk",            "Help Center Closed"),
    (re.compile(r"webflow\.io"),          "Webflow",            "The page you are looking for doesn't exist"),
    (re.compile(r"surge\.sh"),            "Surge.sh",           "project not found"),
    (re.compile(r"bitbucket\.io"),        "Bitbucket",          "Repository not found"),
    (re.compile(r"unbouncepages\.com"),   "Unbounce",           "The requested URL was not found"),
    (re.compile(r"statuspage\.io"),       "Statuspage",         "You are being redirected"),
    (re.compile(r"cargocollective\.com"), "Cargo Collective",   "404 Not Found"),
    (re.compile(r"tumblr\.com"),          "Tumblr",             "Whatever you were looking for doesn't live here"),
    (re.compile(r"squarespace\.com"),     "Squarespace",        "No Such Account"),
    (re.compile(r"wordpress\.com"),       "WordPress",          "Do you want to register"),
    (re.compile(r"pantheonsite\.io"),     "Pantheon",           "The gods are wise"),
    (re.compile(r"fly\.dev"),             "Fly.io",             "404 Not Found"),
    (re.compile(r"vercel\.app"),          "Vercel",             "The deployment could not be found on Vercel."),
    (re.compile(r"hubspot\.net"),         "HubSpot",            "HubSpot - Page not found"),
    (re.compile(r"kinsta\.cloud"),        "Kinsta",             "No Site For Domain"),
    (re.compile(r"readthedocs\.io"),      "Read the Docs",      "Project not found"),
]

def _dns_cname(hostname):
    """CNAME lookup without blocking event loop as it is run via to_thread"""
    try:
        import dns.resolver as _dr
        ans = _dr.resolve(hostname, "CNAME", lifetime=5)
        return str(ans[0].target).rstrip(".").lower()
    except ImportError:
        pass
    except Exception:
        pass
    try:
        r = subprocess.run(
            ["nslookup","-type=CNAME", hostname],
            capture_output=True, text=True, timeout=5
        )
        for line in r.stdout.lower().splitlines():
            if "canonical name" in line or "cname" in line:
                parts = line.split("=")
                if len(parts) > 1:
                    return parts[-1].strip().rstrip(".")
    except Exception:
        pass
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_INET)
        if results:
            return ""   # No CNAME
    except socket.gaierror:
        return "NXDOMAIN"
    except Exception:
        pass
    return ""

@ensure_async
async def run_cors_misc(domain, classified, subs, out):
    print()
    print(GRY+"┌─ "+RESET+WHT+BOLD+"STEP 5c"+RESET+GRY+" ─── "+RESET+
          CYN+BOLD+"CORS  ·  HOST HEADER  ·  SUBDOMAIN TAKEOVER"+RESET)
    print(GRY+"│"+RESET)
    findings = []
    base_url = f"https://{domain}"
    
    async with aiohttp.ClientSession() as session:
        # CORS Checks
        info("CORS misconfiguration check (7 origin variants) ...")
        cors_origins = [
            (f"https://attacker.com",                "basic-attacker"),
            ("null",                                  "null-origin"),
            (f"https://{domain}.attacker.com",        "subdomain-suffix"),
            (f"https://attacker.com.{domain}",        "domain-prefix"),
            (f"https://{domain}.evil.com",            "domain-suffix-bypass"),
            (f"https://not{domain}",                  "prefix-bypass"),
            (f"https://{domain}%60.attacker.com",     "backtick-escape"),
            (f"http://{domain}",                      "proto-downgrade"),
            (f"https://{domain}^.attacker.com",       "caret-escape"),
        ]
        
        cors_targets = list(dict.fromkeys(
            [i["url"] for i in classified.get("API Endpoints",[])  if i.get("status")==200][:6] +
            [i["url"] for i in classified.get("Login / Auth",  []) if i.get("status")==200][:3] +
            [base_url + "/"]
        ))
        
        cors_seen = set()
        
        async def check_cors(url, origin, otag):
            code, body, hdrs, _ = await http_probe(session, url, timeout=7, extra_headers={"Origin": origin})
            acao = hdrs.get("Access-Control-Allow-Origin", "")
            acac = hdrs.get("Access-Control-Allow-Credentials", "").lower()
            return url, origin, otag, acao, acac
            
        cors_tasks = [check_cors(u, o, otag) for u in cors_targets for o, otag in cors_origins]
        cors_results = await asyncio.gather(*cors_tasks, return_exceptions=True)
        
        for res in cors_results:
            if isinstance(res, Exception): continue
            url, origin, otag, acao, acac = res
            
            if not acao or acao == "*":
                if acao == "*":
                    info(f"CORS wildcard (*) — {url[:55]} [{otag}]")
                continue
            reflected = (origin.lower() in acao.lower() or acao.lower() == "null" or "attacker" in acao.lower())
            if not reflected:
                continue
            key = f"{url}|{acao}"
            if key in cors_seen: continue
            cors_seen.add(key)
            
            if acac == "true":
                severity = "CRITICAL"
                col = RED+BOLD
                vuln(f"CORS CRITICAL [{otag}]: {url[:60]}")
                vuln(f"Origin reflected + credentials=true → account takeover possible")
            elif "attacker" in acao.lower() or acao.lower() == "null":
                severity = "HIGH"
                col = ORG+BOLD
                found(f"CORS HIGH [{otag}]: {url[:60]}")
            else:
                severity = "MEDIUM"
                col = YLW
                
            print(GRY+"│    "+RESET+GRY+f"Origin sent: {origin[:50]}"+RESET)
            print(GRY+"│    "+RESET+GRY+f"ACAO: {acao}  ACAC: {acac}"+RESET)
            findings.append({"type":f"CORS-{severity}", "url":url, "ACAO":acao, "ACAC":acac, "origin_used":origin, "technique":otag})

        print(GRY+"│"+RESET)
        
        # Host Header Injection Checks
        info("Host header injection check ...")
        evil_host = "attacker-evil.com"
        hh_checks = [
            ({"Host":        evil_host},                      "Host"),
            ({"X-Forwarded-Host": evil_host},                 "X-Forwarded-Host"),
            ({"X-Host":      evil_host},                      "X-Host"),
            ({"Host":        f"{domain}@{evil_host}"},        "Host@evil"),
            ({"X-Forwarded-Server": evil_host},               "X-Forwarded-Server"),
            ({"X-Original-URL": f"http://{evil_host}"},       "X-Original-URL"),
        ]
        
        async def check_host_header(test_hdr, tag):
            # Check for general reflection
            code, body, hdrs, _ = await http_probe(session, base_url+"/", timeout=7, extra_headers=test_hdr)
            body_lower = body.lower()
            if evil_host in body_lower or evil_host in hdrs.get("Location","").lower():
                vuln(f"Host Header Injection via {tag}")
                print(GRY+"│    "+RESET+RED+f"Reflected '{evil_host}' in response"+RESET)
                findings.append({"type":"HostHeaderInjection","header":tag, "url":base_url,"evidence":evil_host})

            # Check for password reset poisoning (crucial for bug bounty)
            reset_paths = ["/forgot", "/reset-password", "/password-reset", "/recover", "/api/reset", "/users/password/new"]
            for rp in reset_paths:
                code2, body2, hdrs2, _ = await http_probe(session, base_url+rp, timeout=6, extra_headers=test_hdr)
                if code2 in (200,302) and evil_host in body2.lower():
                    vuln(f"Password Reset Poisoning via {tag} on {rp}")
                    findings.append({"type":"PasswordResetPoisoning","path":rp,"header":tag})
                    break
                    
        await asyncio.gather(*(check_host_header(h, t) for h, t in hh_checks), return_exceptions=True)

        print(GRY+"│"+RESET)
        
        # Subdomain Takeover Check
        info(f"Subdomain takeover check ({len(subs)} subdomains) ...")
        print(GRY+"│"+RESET)
        
        takeover_hits = []
        sem = asyncio.Semaphore(15)
        
        async def check_takeover(sub):
            async with sem:
                hits = []
                try:
                    cname = await asyncio.to_thread(_dns_cname, sub)
                    if not cname: return hits
                    if cname == "NXDOMAIN":
                        return hits
                    for pat, service, fingerprint in TAKEOVER_FINGERPRINTS:
                        if pat.search(cname):
                            code, body, _, _ = await http_probe(session, f"https://{sub}", timeout=6)
                            if code in (200, 404) and fingerprint.lower() in body.lower():
                                hits.append({"subdomain":sub, "cname":cname, "service":service, "fingerprint":fingerprint})
                            elif code == 0:
                                hits.append({"subdomain":sub, "cname":cname, "service":service, "fingerprint":"No HTTP response — dangling CNAME"})
                except Exception as e:
                    logger.debug(f"Takeover check failed for {sub}: {e}")
                return hits

        to_tasks = [check_takeover(s) for s in subs[:100]]
        to_results = await asyncio.gather(*to_tasks, return_exceptions=True)
        
        for res in to_results:
            if isinstance(res, Exception): continue
            for h in res:
                vuln(f"SUBDOMAIN TAKEOVER: {h['subdomain']} → {h['service']}")
                print(GRY+"│    "+RESET+RED+f"CNAME: {h['cname']}"+RESET)
                print(GRY+"│    "+RESET+RED+f"Fingerprint: {h['fingerprint'][:70]}"+RESET)
                takeover_hits.append(h)
                findings.append({"type":"SubdomainTakeover", **h})

    if not takeover_hits:
        ok("Subdomain takeover: no dangling CNAMEs found")
    print(GRY+"│"+RESET)
    save_json(f"{out}/misc_findings.json", findings)
    critical = len([f for f in findings if f.get("type") in
                    ("CORS-CRITICAL","SubdomainTakeover","HostHeaderInjection",
                     "PasswordResetPoisoning")])
    ok(f"Misc findings: {BOLD}{len(findings)}{RESET}  ({BOLD}{critical}{RESET} critical)")
    print(GRY+"└"+"─"*70+RESET)
    return findings

cors_and_misc_checks = run_cors_misc

