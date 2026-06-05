import re
import asyncio
import aiohttp
import json
import logging
import urllib.parse
logger = logging.getLogger("bb-recon")

from core.ui import *
from core.utils import *
from core.http import http_probe

async def run_sourcemap_analyzer(domain, urls, live_lines, out):
    section(12, "SOURCE MAP ANALYZER")
    
    js_urls = set()
    for u in urls:
        parsed = u.split("?")[0]
        if parsed.endswith(".js"):
            js_urls.add(u.split("?")[0])
    
    live_hosts = set()
    for line in live_lines[:15]:
        m = re.match(r"(https?://[^\s\[/]+)", line)
        if m: live_hosts.add(m.group(1))
    live_hosts.add(f"https://{domain}")
    
    async with aiohttp.ClientSession() as session:
        sem = asyncio.Semaphore(10)
        
        async def extract_js_from_page(base_url):
            found_js = set()
            async with sem:
                try:
                    code, body, _, _ = await http_probe(session, base_url + "/", timeout=8)
                    if not body or code == 0: return found_js
                    for src in re.findall(r"""src=["']([^"']{3,200}\.js(?:\?[^"']*)?)["']""", body):
                        src = src.strip()
                        if src.startswith("http"): found_js.add(src.split("?")[0])
                        elif src.startswith("//"): found_js.add("https:" + src.split("?")[0])
                        elif src.startswith("/"): found_js.add(base_url.rstrip("/") + src.split("?")[0])
                except Exception:
                    pass
            return found_js
        
        page_tasks = [extract_js_from_page(h) for h in sorted(live_hosts)]
        page_results = await asyncio.gather(*page_tasks, return_exceptions=True)
        for res in page_results:
            if isinstance(res, set):
                js_urls.update(res)
        
        info(f"Total JS files to probe for .map: {len(js_urls)}")
        
        map_found = []
        extracted_endpoints = set()
        
        async def check_sourcemap(js_url):
            map_url = js_url + ".map"
            async with sem:
                try:
                    code, body, hdrs, _ = await http_probe(session, map_url, timeout=8)
                    if code != 200 or not body or len(body) < 50:
                        return None
                    ct = hdrs.get("Content-Type", "").lower()
                    if "text/html" in ct:
                        return None
                    try:
                        data = json.loads(body)
                    except (json.JSONDecodeError, ValueError):
                        return None
                    
                    if "sources" not in data and "mappings" not in data:
                        return None
                    
                    sources = data.get("sources", [])
                    source_content = data.get("sourcesContent", [])
                    
                    endpoints = set()
                    
                    for src_path in sources:
                        if not isinstance(src_path, str): continue
                        clean = src_path.replace("webpack://", "").replace("../", "").lstrip("./")
                        if clean.startswith("node_modules/"): continue
                        if clean.startswith("~/"): continue
                        
                        api_match = re.search(r"(?:api|routes|endpoints|controllers|services)/(.+?)\.(?:js|ts|tsx|jsx)", clean)
                        if api_match:
                            route = "/" + api_match.group(0).rsplit(".", 1)[0].replace("\\", "/")
                            endpoints.add(route)
                    
                    api_patterns = [
                        re.compile(r"""["'](/api/[a-zA-Z0-9/_\-]+)["']"""),
                        re.compile(r"""["'](/v[0-9]+/[a-zA-Z0-9/_\-]+)["']"""),
                        re.compile(r"""(?:fetch|axios|get|post|put|delete|patch)\s*\(\s*["'`](/[a-zA-Z0-9/_\-]+)["'`]"""),
                        re.compile(r"""(?:url|endpoint|path|route)\s*[:=]\s*["'`](/[a-zA-Z0-9/_\-]+)["'`]"""),
                        re.compile(r"""["'](/(?:admin|dashboard|internal|private|debug|config|settings|users|auth)/[a-zA-Z0-9/_\-]*)["']"""),
                        re.compile(r"""["'](/graphql|/ws|/socket|/webhook)["']"""),
                    ]
                    
                    search_text = " ".join(sources[:200])
                    for sc in source_content[:50]:
                        if isinstance(sc, str):
                            search_text += " " + sc[:5000]
                    
                    for pat in api_patterns:
                        for m in pat.finditer(search_text):
                            ep = m.group(1)
                            if len(ep) > 3 and not ep.endswith((".js", ".css", ".svg", ".png", ".jpg")):
                                endpoints.add(ep)
                    
                    return {
                        "map_url": map_url,
                        "js_url": js_url,
                        "sources_count": len(sources),
                        "endpoints": list(endpoints),
                    }
                except Exception as e:
                    logger.debug(f"Sourcemap check failed for {js_url}: {e}")
                    return None
        
        map_tasks = [check_sourcemap(js_url) for js_url in sorted(js_urls)]
        map_results = await asyncio.gather(*map_tasks, return_exceptions=True)
        
        for res in map_results:
            if isinstance(res, dict):
                map_found.append(res)
                extracted_endpoints.update(res["endpoints"])
                vuln(f"SOURCE MAP FOUND: {res['map_url'][:80]}")
                print(GRY+"\u2502    "+RESET+GRY+DIM+f"Sources: {res['sources_count']} files"+RESET)
                if res["endpoints"]:
                    print(GRY+"\u2502    "+RESET+CYN+f"Extracted {len(res['endpoints'])} hidden endpoints:"+RESET)
                    for ep in sorted(res["endpoints"])[:10]:
                        print(GRY+"\u2502      "+RESET+WHT+f"\u2192 {ep}"+RESET)
                    if len(res["endpoints"]) > 10:
                        print(GRY+"\u2502      "+RESET+GRY+DIM+f"... +{len(res['endpoints'])-10} more"+RESET)
    
    new_urls = []
    if extracted_endpoints:
        base_url = f"https://{domain}"
        for ep in extracted_endpoints:
            full_url = base_url + ep
            if full_url not in urls:
                new_urls.append(full_url)
    
    print(GRY+"\u2502"+RESET)
    
    save_json(f"{out}/sourcemaps.json", {
        "maps_found": map_found,
        "extracted_endpoints": sorted(extracted_endpoints),
        "new_urls_added": len(new_urls),
    })
    
    if not map_found:
        ok("No source maps found")
    else:
        ok(f"Source maps: {BOLD}{len(map_found)}{RESET}  "
           f"Endpoints extracted: {BOLD}{len(extracted_endpoints)}{RESET}  "
           f"New URLs added: {BOLD}{len(new_urls)}{RESET}")
    
    _end()
    return new_urls
