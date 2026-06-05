import asyncio
import aiohttp
import logging
logger = logging.getLogger("bb-recon")
from core.ui import section, info, GRY, WHT, RESET, CYN, ok, vuln, BOLD, warn
from core.utils import save_json
from core.utils import ensure_async
from .sqli import SQLiScanner
from .lfi import LFIScanner
from .xss import XSSScanner
from .ssrf_cmd import SSRFandCmdScanner
from .misc import MiscScanner
from .xxe import XXEScanner
from .smuggling import HTTPSmugglingScanner
from .cache_poison import CachePoisonScanner
from .deserialization import DeserializationScanner
import urllib.parse

def _get_bl(url, baselines):
    try:
        h = urllib.parse.urlparse(url).netloc
        return baselines.get(h) or next(iter(baselines.values()), {})
    except Exception:
        return {}

async def _run_scanner_on_urls(scanner_class, session, urls, waf_detected, waf_delay, name):
    scanner = scanner_class(session, waf_detected, waf_delay)
    all_findings = []
    
    sem = asyncio.Semaphore(5)
    async def bound_scan(url):
        async with sem:
            try:
                return await asyncio.wait_for(scanner.scan(url), timeout=45)
            except asyncio.TimeoutError:
                logger.debug(f"{name} timed out on {url[:80]}")
                return []
            except Exception as e:
                logger.debug(f"{name} failed on {url[:80]}: {e}")
                return []
            
    tasks = [bound_scan(url) for url in urls]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    for res in results:
        if isinstance(res, list):
            all_findings.extend(res)
        elif isinstance(res, Exception):
            logger.debug(f"{name} task exception: {res}")
    return all_findings

@ensure_async
async def run_active_scans(classified, baselines, waf_detected, waf_delay, out):
    section_title = "ACTIVE PARAM TESTING  (SQLi · LFI · XSS · SSTI · CRLF · Redirect · SSRF · CMD · XXE · Smuggling · Cache Poison · Deserialization)"
    print()
    print(GRY+"┌─ "+RESET+WHT+BOLD+"STEP 5b"+RESET+GRY+" ─── "+RESET+CYN+BOLD+section_title+RESET)
    print(GRY+"│"+RESET)
    
    findings = []
    
    sqli_urls = [i["url"] for i in classified.get("SQLi Candidates",[]) if i.get("status")==200]
    lfi_urls  = [i["url"] for i in classified.get("LFI Candidates",[])  if i.get("status")==200]
    redir_urls= [i["url"] for i in classified.get("Open Redirect",[])   if i.get("status") in (200,301,302)]
    
    param_urls = set()
    for label, items in classified.items():
        for item in items:
            u = item.get("url","")
            if "?" in u and item.get("status") in (200, 301, 302):
                param_urls.add(u)
    param_urls = sorted(param_urls)[:40]
    
    idor_urls = [i["url"] for i in classified.get("SQLi Candidates",[]) if i.get("status")==200]
    idor_urls += [i["url"] for i in classified.get("User Profile",[]) if i.get("status")==200]

    xml_urls = [u for u in param_urls if any(kw in u.lower() for kw in ["xml", "soap", "wsdl", "feed", "rss", "api"])]
    if not xml_urls:
        xml_urls = param_urls[:5]

    all_live = set()
    for label, items in classified.items():
        for item in items:
            u = item.get("url", "")
            if item.get("status") == 200 and u:
                parsed = urllib.parse.urlparse(u)
                base = f"{parsed.scheme}://{parsed.netloc}"
                all_live.add(base)
    live_bases = sorted(all_live)[:10]
    
    has_candidates = sqli_urls or lfi_urls or param_urls or redir_urls or idor_urls or xml_urls or live_bases

    if not has_candidates:
        info("No candidates to actively test")
        print(GRY+"└"+"─"*70+RESET)
        return findings

    async with aiohttp.ClientSession() as session:
        tasks = []
        if sqli_urls:
            info(f"SQLi — testing {len(sqli_urls[:20])} candidates ...")
            tasks.append(_run_scanner_on_urls(SQLiScanner, session, sqli_urls[:20], waf_detected, waf_delay, "SQLi"))
            
        if lfi_urls:
            info(f"LFI — testing {len(lfi_urls[:15])} candidates ...")
            tasks.append(_run_scanner_on_urls(LFIScanner, session, lfi_urls[:15], waf_detected, waf_delay, "LFI"))
            
        if param_urls:
            info(f"XSS, SSTI, CRLF, SSRF, OS-CMD — testing {len(param_urls)} URLs ...")
            tasks.append(_run_scanner_on_urls(XSSScanner, session, param_urls[:25], waf_detected, waf_delay, "XSS"))
            tasks.append(_run_scanner_on_urls(SSRFandCmdScanner, session, param_urls[:15], waf_detected, waf_delay, "SSRF/OSCMD"))
            tasks.append(_run_scanner_on_urls(MiscScanner, session, param_urls[:20], waf_detected, waf_delay, "Misc"))

        if xml_urls:
            info(f"XXE — testing {len(xml_urls)} XML-related endpoints ...")
            tasks.append(_run_scanner_on_urls(XXEScanner, session, xml_urls[:10], waf_detected, waf_delay, "XXE"))

        if param_urls:
            info(f"Deserialization — testing {len(param_urls[:10])} endpoints ...")
            tasks.append(_run_scanner_on_urls(DeserializationScanner, session, param_urls[:10], waf_detected, waf_delay, "Deserialization"))

        if live_bases:
            info(f"HTTP Smuggling — testing {len(live_bases)} hosts ...")
            tasks.append(_run_scanner_on_urls(HTTPSmugglingScanner, session, live_bases[:5], waf_detected, waf_delay, "Smuggling"))
            info(f"Cache Poisoning — testing {len(live_bases)} hosts ...")
            tasks.append(_run_scanner_on_urls(CachePoisonScanner, session, live_bases[:5], waf_detected, waf_delay, "CachePoison"))

        if redir_urls or idor_urls:
            extra_urls = list(set(redir_urls[:15] + idor_urls[:15]))
            tasks.append(_run_scanner_on_urls(MiscScanner, session, extra_urls, waf_detected, waf_delay, "IDOR/OpenRedirect"))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in results:
            if isinstance(res, list):
                findings.extend(res)

    print(GRY+"│"+RESET)
    save_json(f"{out}/active_param_findings.json", findings)
    confirmed_count = len(findings)
    if confirmed_count:
        vuln(f"Active testing confirmed: {confirmed_count} vulnerabilities!")
    else:
        ok("Active parameter testing: no confirmed vulns")
    print(GRY+"└"+"─"*70+RESET)
    
    return findings

active_param_test = run_active_scans
