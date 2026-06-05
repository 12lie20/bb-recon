import re
import urllib.parse
import hashlib
import asyncio
import aiohttp
from collections import defaultdict
import logging
logger = logging.getLogger("bb-recon")

from core.config import CONFIG
from core.ui import *
from core.utils import *
from core.utils import ensure_async
from core.http import http_probe

BUCKETS = {
    "Admin / Dashboard":  re.compile(r"/(admin|administrator|dashboard|manage|console|cpanel|wp-admin|phpmyadmin|backend|portal|sys|system|manager|control|sysadmin|intranet)(/|\?|\.php|$)",re.I),
    "Login / Auth":       re.compile(r"/(login|signin|sign-in|authenticate|auth|sso|oauth|saml|account/login)(/|\?|$)",re.I),
    "API Endpoints":      re.compile(r"/(api/v\d|graphql|rest/|/v\d+/|swagger|openapi\.json|api-docs|_api/)(/|\?|$)",re.I),
    "File Upload":        re.compile(r"/(upload|file-upload|import|attach|media/upload|document/upload)(/|\?|$)",re.I),
    "Sensitive Files":    re.compile(r"\.(bak|sql|backup|config|conf|env|log|dump|db|sqlite|zip|pem|key|old|orig|tmp|swp|pfx|crt|rsa|cer|pgp|tar\.gz|tgz)(\?.*)?$",re.I),
    "Cloud Storage":      re.compile(r"(s3\.amazonaws|s3-[a-z0-9-]+\.amazonaws|storage\.googleapis|blob\.core\.windows|digitaloceanspaces|r2\.cloudflarestorage|oss\.aliyuncs|storage\.yandexcloud)",re.I),
    "Firebase / RTDB":    re.compile(r"firebaseio\.com|firebaseapp\.com",re.I),
    "SSRF / Redirect":    re.compile(r"[?&](url|redirect|return|next|dest|uri|path|to|target|link|out|view|show|img|file|hostname|host|site|domain)=https?://",re.I),
    "Open Redirect":      re.compile(r"[?&](redirect|return_url|returnto|goto|dest|url)=[^&]{1,200}",re.I),
    "SQLi Candidates":    re.compile(r"[?&](id|item_id|product_id|user_id|order_id|cat|category_id|page_id|post_id|pid|nid|search|q|query)=\d+",re.I),
    "LFI Candidates":     re.compile(r"[?&](file|page|lang|language|template|include|path|dir|folder|document|load|read|view|image|src)=",re.I),
    "Debug / Dev":        re.compile(r"/(debug|test|dev|staging|phpinfo\.php|info\.php|server-status|\.git/|\.env|\.svn/|__tests__/)",re.I),
    "Password Reset":     re.compile(r"/(forgot|reset-password|password-reset|recover|change-password)(/|\?|$)",re.I),
    "User Profile":       re.compile(r"/(user|profile|account|member|me)(/\d+|/edit|/settings|$)",re.I),
}

SENSITIVE_URL_RE = re.compile(
    r"(\.(env|json|yml|yaml|xml|conf|config|cfg|ini|bak|sql|log|key|pem|db|sqlite|swp|rsa|pfx|tar\.gz|tgz)"
    r"|/\.git/|/\.svn/|/wp-config|/settings\.py|/appsettings"
    r"|/api-docs|/swagger|/openapi|/phpinfo|/server-status)(\?.*)?$", re.I)

BYPASS_HEADERS = [
    ("X-Original-URL",          "/{path}",    "X-Orig-URL"),
    ("X-Rewrite-URL",           "/{path}",    "X-Rewrite"),
    ("X-Forwarded-For",         "127.0.0.1",  "XFF:127"),
    ("X-Forwarded-For",         "localhost",  "XFF:localhost"),
    ("X-Forwarded-For",         "8.8.8.8",    "XFF:8.8.8.8"),
    ("X-Real-IP",               "127.0.0.1",  "X-Real-IP"),
    ("X-Custom-IP-Authorization","127.0.0.1", "X-CustomIP"),
    ("X-Originating-IP",        "127.0.0.1",  "X-Orig-IP"),
    ("X-Remote-IP",             "127.0.0.1",  "X-Remote-IP"),
    ("X-Remote-Addr",           "127.0.0.1",  "X-Remote-Addr"),
    ("X-Client-IP",             "127.0.0.1",  "X-Client-IP"),
    ("X-Forwarded-Host",        "localhost",  "X-Fwd-Host"),
    ("X-Host",                  "localhost",  "X-Host"),
    ("Referer",                 "https://127.0.0.1/","Ref:127"),
    ("X-WAP-Profile",           "127.0.0.1",  "X-WAP"),
    ("True-Client-IP",          "127.0.0.1",  "True-Client"),
    ("Client-IP",               "127.0.0.1",  "Client-IP"),
    ("Base-Url",                "127.0.0.1",  "Base-Url"),
]
BYPASS_PATHS = [
    ("{url}/",          "slash-append"),
    ("{url}/.",         "slash-dot"),
    ("{url}//",         "double-slash"),
    ("{url}/%2f",       "url-encode-slash"),
    ("{url}/%20",       "space-append"),
    ("{url}%09",        "tab-append"),
    ("{url}?",          "question-mark"),
    ("{url}??",         "double-question"),
    ("{url}?any=1",     "junk-param"),
    ("{url}#",          "hash-append"),
    ("{url}/*",         "asterisk-append"),
    ("{url}.html",      "html-ext"),
    ("{url}.json",      "json-ext"),
    ("{url}..;/",       "dot-dot-semicolon"),
    ("{base}/%2e/{leaf}","dot-encode"),
    ("{base}/%2e%2e/{leaf}","dot-dot-encode"),
    ("{base}/./{leaf}", "dot-slash-prepend"),
    ("{base}/;/{leaf}", "semicolon-prepend"),
    ("{base}/{leaf}/.", "dot-append"),
    ("{base}/{leaf};/", "semicolon-append"),
    ("{base}//{leaf}//", "double-slash-wrap"),
    ("{base}/./{leaf}/./", "dot-slash-wrap"),
    ("{base}/%20{leaf}%20/", "space-wrap"),
]

async def try_403_bypass(session, url, orig_body=""):
    parsed = urllib.parse.urlparse(url)
    path = parsed.path.lstrip("/")
    base = f"{parsed.scheme}://{parsed.netloc}"
    leaf = path.split("/")[-1] if "/" in path else path
    base_dir = "/".join(path.split("/")[:-1]) if "/" in path else ""
    base_full = f"{base}/{base_dir}".rstrip("/")
    if not leaf:
        leaf = ""
        
    results = []
    orig_len = len(orig_body) if orig_body else 0
    
    async def bp_probe(test_url, extra_hdrs, method="GET"):
        try:
            c, b, _, _ = await http_probe(session, test_url, extra_headers=dict(extra_hdrs), timeout=5, method=method)
            return c, b
        except:
            return None, ""

    def is_bypassed(c2, b2):
        if not c2 or c2 in (403, 401, 400, 500, 502, 503): return False
        b2_len = len(b2) if b2 else 0
        if c2 in (200, 201, 204, 301, 302, 307, 308):
            if orig_len == 0 or abs(b2_len - orig_len) > 50: return True
            if b2 and orig_body and b2[:100] != orig_body[:100]: return True
        return False

    # 1. Header Bypasses
    for hk, hv_tpl, tag in BYPASS_HEADERS:
        hv = hv_tpl.replace("{path}", "/"+path)
        c2, b2 = await bp_probe(url, [(hk, hv)])
        if is_bypassed(c2, b2):
            results.append({"technique": tag, "code": c2})
            
    # 2. Path/URL Bypasses
    for tpl, tag in BYPASS_PATHS:
        test = tpl.replace("{url}",url).replace("{base}", base_full).replace("{leaf}", leaf)
        c2, b2 = await bp_probe(test, [])
        if is_bypassed(c2, b2):
            results.append({"technique": tag, "code": c2})

    # 3. HTTP Method Bypasses (POST, HEAD, PUT, TRACE, OPTIONS)
    for meth in ["POST", "HEAD", "PUT", "TRACE", "OPTIONS", "PATCH"]:
        c2, b2 = await bp_probe(url, [], method=meth)
        if c2 and c2 in (200, 201, 204):
            results.append({"technique": f"method-{meth}", "code": c2})

    return results

SENSITIVE_KEYWORDS = re.compile(
    r"DB_PASSWORD|DB_HOST|DB_USER|DATABASE_URL|SECRET_KEY|APP_KEY|API_KEY"
    r"|AWS_SECRET|AWS_ACCESS|PRIVATE_KEY"
    r"|password\s*=|passwd\s*=|pwd\s*=|secret\s*="
    r"|mysql://|postgres://|mongodb://|redis://|smtp://"
    r"|-{5}BEGIN|AKIA[0-9A-Z]{16}"
    r"|root:[x*]:0:0|bin/bash"
    r"|access_token|refresh_token|client_secret"
    r"|DB_NAME|DB_PASS|APP_SECRET|JWT_SECRET"
    r"|swagger|openapi|paths:|definitions:"
    r"|\"schema\":|\"type\":\s*\"object\"",
    re.I
)
HTML_START_RE = re.compile(r"^\s*(<\?xml|<!doctype|<html|<head|<body|<!--|<\!)",re.I)
CLOUDFLARE_BLOCK_RE = re.compile(r"(cloudflare|attention required|access denied|security check|ray id)", re.I)

def validate_200(url, body, ct, size, code, baseline):
    is_sens = bool(SENSITIVE_URL_RE.search(url))
    soft_404 = baseline.get("soft_404", False)
    
    if not body:
        return False, "empty-body"
        
    # Extremely aggressive WAF/Block validation
    if code in (403, 401) or CLOUDFLARE_BLOCK_RE.search(body[:1500]):
        return False, "waf-block-page"
        
    if is_sens and "text/html" in ct:
        # If it's supposed to be a sensitive file (env, key) but returns HTML, it's 99% a false positive
        if HTML_START_RE.search(body[:500]):
            return False, "html-content-type"
            
    if soft_404:
        baseline_size = baseline.get("soft_404_size", 0)
        threshold     = baseline.get("soft_404_threshold", 150)
        if baseline_size > 0 and abs(size - baseline_size) <= threshold:
            return False, f"size-match-baseline (|{size}-{baseline_size}|≤{threshold})"
            
        body_hash = hashlib.md5(body.encode()).hexdigest()
        if body_hash in baseline.get("soft_404_hashes", []):
            return False, "hash-match-baseline"
            
        clean_body = re.sub(r"<[^>]+>", "", body).strip()[:100].lower()
        for snip in baseline.get("soft_404_snippets", []):
            if snip and len(snip) > 20 and snip in clean_body:
                return False, "snippet-match-baseline"
                
    if is_sens and "text/html" not in ct:
        # Require actual sensitive content if it's not HTML
        if not SENSITIVE_KEYWORDS.search(body[:15000]):
            return False, "no-sensitive-keywords"
            
    return True, "validated"

@ensure_async
async def run_classifier(urls, baselines, out):
    section(5,"URL CLASSIFIER  +  STATUS PROBE  (validated)")
    
    extra = set()
    for u in urls:
        base = urllib.parse.urlparse(u).scheme + "://" + urllib.parse.urlparse(u).netloc
        extra.update([f"{base}/.git/config", f"{base}/.env", f"{base}/.svn/entries", f"{base}/info.php"])
    urls = list(set(urls) | extra)
    
    soft_404_count = sum(1 for bl in baselines.values() if bl.get("soft_404"))
    if soft_404_count:
        info(f"Soft-404 active on {soft_404_count} host(s) — per-host baseline in effect")
        
    classified=defaultdict(list)
    for u in urls:
        for label, pat in BUCKETS.items():
            if pat.search(u):
                classified[label].append(u); break
                
    targets=[]
    for label, items in classified.items():
        seen=set()
        for u in items:
            try:
                p=urllib.parse.urlparse(u).path
                if p not in seen: seen.add(p); targets.append((label,u))
            except Exception:
                targets.append((label,u))
                
    info(f"Probing {len(targets)} URLs ...")
    print(GRY+"│"+RESET)
    
    results = defaultdict(list)
    filtered_count = 0
    sem = asyncio.Semaphore(CONFIG.max_threads)

    async def probe(session, label, url):
        nonlocal filtered_count
        async with sem:
            has_been_bypassed = False
            code, body, hdrs, ms = await http_probe(session, url, timeout=8)
            
            # Auto-trigger 403 bypass early for ALL endpoints returning 401/403
            bypass = []
            if code in (401, 403):
                bypass = await try_403_bypass(session, url, orig_body=body)
                if bypass:
                    has_been_bypassed = True
                    found(f"401/403 bypass successfully exploited → {url}")
                    # Adopt the best bypassed response for analysis
                    bph = [b for b in bypass if b["code"] == 200]
                    if bph: code = 200

            if code == 404:
                return
            redir = hdrs.get("Location", "")
            ct = hdrs.get("Content-Type", "").lower()
            size = len(body) if body else 0
            if code == 200:
                host = urllib.parse.urlparse(url).netloc
                host_bl = baselines.get(host) or next(iter(baselines.values()), {})
                is_real, reason = validate_200(url, body, ct, size, code, host_bl)
                if not is_real and not has_been_bypassed:
                    filtered_count += 1
                    return
            results[label].append((url, code, redir, ms, bypass))

    async with aiohttp.ClientSession() as session:
        tasks = [probe(session, label, url) for label, url in targets]
        await asyncio.gather(*tasks, return_exceptions=True)

    if filtered_count:
        info(f"False positives filtered: {filtered_count} URLs (soft-404/HTML/no-keywords)")
        
    full={}
    for label in BUCKETS:
        items=results.get(label,[])
        if not items: continue
        items = [(u,c,r,m,b) for u,c,r,m,b in items if c != 404]
        if not items: continue
        items.sort(key=lambda x: x[1] not in (200,403,401,500))
        print(GRY+"│  "+RESET+YLW+BOLD+f"[{label}]"+RESET+GRY+f"  ({len(items)})"+RESET)
        for url,code,redir,ms,bypass in items:
            ms_s=GRY+DIM+f"  {ms}ms"+RESET if ms else ""
            rd_s=GRY+DIM+f"  → {redir[:50]}"+RESET if redir and code in(301,302) else ""
            print(GRY+"│    "+RESET+sbadge(code)+"  "+WHT+url+RESET+ms_s+rd_s)
            for bp in bypass:
                bc=bp["code"]; tag=bp["technique"]
                col=GRN+BOLD if bc==200 else YLW
                print(GRY+"│         "+RESET+col+f"↳ [{tag}] {sbadge(bc)}"+RESET)
        print(GRY+"│"+RESET)
        full[label]=[{"url":u,"status":c,"redirect":r,"ms":m,"bypass":b}
                     for u,c,r,m,b in items]
                     
    save_json(f"{out}/classified_urls.json",full)
    v200=sum(1 for v in full.values() for i in v if i["status"]==200)
    ok(f"Interesting URLs : {BOLD}{sum(len(v) for v in full.values())}{RESET}  "
       f"({BOLD}{v200}{RESET} validated 200)")
    _end()
    return full

classify_and_probe = run_classifier
