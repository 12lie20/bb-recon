import re
import urllib.parse
import asyncio
import aiohttp
import logging
logger = logging.getLogger("bb-recon")
from core.ui import *
from core.utils import *
from core.utils import ensure_async
from core.http import http_probe

@ensure_async
async def run_urls(domain, live_lines, out):
    section(4,"URL COLLECTION  +  SMART DEDUP  (uro)")
    raw=set()
    if t_ok("waybackurls"):
        info("waybackurls ...")
        # run_cmd is synchronous, consider running in executor
        loop = asyncio.get_running_loop()
        r = await loop.run_in_executor(None, lambda: run_cmd(["waybackurls"], 90, input_data=domain+"\n"))
        new={l.strip() for l in r.splitlines() if domain in l and l.startswith("http")}
        raw|=new; ok(f"waybackurls  → {len(new):>6}")
    else:
        warn("waybackurls missing")
        
    if t_ok("gau"):
        info("gau ...")
        loop = asyncio.get_running_loop()
        r = await loop.run_in_executor(None, lambda: run_cmd(["gau", domain, "--threads", "5", "--timeout", "30"], 90))
        new={l.strip() for l in r.splitlines() if domain in l and l.startswith("http")}
        raw|=new; ok(f"gau          → {len(new):>6}")
        
    if t_ok("katana"):
        info("katana crawl — all live hosts ...")
        live_hosts_urls = set()
        for line in live_lines:
            m = re.match(r"(https?://[^\s\[/]+)", line)
            if m: live_hosts_urls.add(m.group(1))
        live_hosts_urls.add(f"https://{domain}")
        katana_list = f"{out}/_katana_targets.txt"
        save_txt(katana_list, sorted(live_hosts_urls))
        _kt = min(900, max(300, len(live_hosts_urls) * 8))
        loop = asyncio.get_running_loop()
        r = await loop.run_in_executor(None, lambda: run_cmd(["katana", "-list", katana_list, "-silent", "-depth", "4", "-js-crawl", "-jsluice",
                   "-k", "-no-color", "-timeout", "15", "-concurrency", "25", "-retry", "2"], _kt))
        new={l.strip() for l in r.splitlines() if l.startswith("http")}
        raw|=new; ok(f"katana       → {len(new):>6}  ({len(live_hosts_urls)} hosts)")

    # Deep JS parsing fallback if JSluice wasn't available
    info("Deep JS URL Extraction ...")
    js_urls = {u for u in raw if u.endswith(".js")}
    js_endpoints = set()
    async with aiohttp.ClientSession() as session:
        async def fetch_js(js_url):
            code, body, _, _ = await http_probe(session, js_url, timeout=5)
            if code == 200:
                # Look for typical API endpoints or paths within JS
                paths = re.findall(r"(?:\"|\')(((?:[a-zA-Z]{1,10}://|/)[^\"\'<>]+))(?:\"|\')", body)
                return [p for p in paths if not p.endswith((".png", ".jpg", ".css"))]
            return []
            
        js_tasks = [fetch_js(u) for u in list(js_urls)[:50]] # Limit to avoid extreme memory usage
        js_results = await asyncio.gather(*js_tasks, return_exceptions=True)
        for res in js_results:
            if not isinstance(res, Exception):
                for p in res:
                    if p.startswith("http"):
                        js_endpoints.add(p)
                    else:
                        js_endpoints.add(f"https://{domain}{p}")
        raw |= js_endpoints
        ok(f"JS Extracted → {len(js_endpoints):>6} endpoints")
        
    raw_count=len(raw)
    ok(f"Raw total    : {BOLD}{raw_count}{RESET}")
    print(GRY+"│"+RESET)
    raw_list=sorted(raw)
    raw_file=f"{out}/_raw_urls.txt"
    save_txt(raw_file,raw_list)
    
    info("robots.txt / sitemap.xml / security.txt ...")
    base = f"https://{domain}"
    extra_urls = set()
    
    async with aiohttp.ClientSession() as session:
        code_r, body_r, _, _ = await http_probe(session, base + "/robots.txt", timeout=8)
        if code_r == 200 and "disallow" in body_r.lower():
            for rm in re.finditer(r"(?:Dis)?allow:\s*(/\S+)", body_r, re.I):
                rp = rm.group(1).strip()
                if rp != "/":
                    extra_urls.add(base + rp)
            ok(f"robots.txt   → {len(extra_urls)} paths")
            
        for sm_path in ["/sitemap.xml", "/sitemap_index.xml"]:
            code_s, body_s, _, _ = await http_probe(session, base + sm_path, timeout=8)
            if code_s == 200 and "<loc>" in body_s.lower():
                sm_urls = re.findall(r"<loc>([^<]+)</loc>", body_s)
                extra_urls.update(u.strip() for u in sm_urls if u.strip().startswith("http"))
                ok(f"{sm_path[1:]:<13}→ {len(sm_urls)} URLs")
                
        for sec_path in ["/.well-known/security.txt", "/security.txt"]:
            code_sec, body_sec, _, _ = await http_probe(session, base + sec_path, timeout=6)
            if code_sec == 200 and ("contact:" in body_sec.lower() or "policy:" in body_sec.lower()):
                found(f"security.txt found → {sec_path}")
                
    if extra_urls:
        scope_extra = {u for u in extra_urls if in_target_domain(u, domain)}
        raw_list = sorted(set(raw_list) | scope_extra)
        ok(f"Extra from robots/sitemap: {len(scope_extra)} in-scope URLs")
        
    print(GRY+"│"+RESET)
    if t_ok("uro"):
        info("uro deduplication ...")
        loop = asyncio.get_running_loop()
        lines=await loop.run_in_executor(None, lambda: pipe_cmd(["uro"],60,input_data=("\n".join(raw_list)+"\n") if raw_list else ""))
        urls=[l for l in lines if l.startswith("http")]
        info(f"{raw_count} → {len(urls)}  (removed {raw_count-len(urls)})")
    else:
        warn("uro missing → pip install uro")
        STATIC=re.compile(
            r"\.(png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|otf|css|map"
            r"|mp4|mp3|webm|pdf|avi|mov|wmv|flv|swf|webp|bmp|tif|tiff|wav|ogg|midi|m4a|weba|apk|ipa)(\?.*)?$",re.I)
        seen=set(); urls=[]
        for u in raw:
            if STATIC.search(u): continue
            try:
                key=urllib.parse.urlparse(u).netloc+urllib.parse.urlparse(u).path
                if key in seen: continue
                seen.add(key); urls.append(u)
            except Exception: urls.append(u)
            
    urls=sorted({u for u in urls if u.startswith("http") and in_target_domain(u, domain)})
    save_txt(f"{out}/urls.txt",urls)
    ok(f"Final URLs   : {BOLD}{len(urls)}{RESET}")
    _end()
    return urls

collect_and_dedup = run_urls

