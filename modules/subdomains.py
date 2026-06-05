import re
import asyncio
import aiohttp
import logging
import json
logger = logging.getLogger("bb-recon")

from core.config import CONFIG, _interrupted
from core.rate_limit import RATE_LIMITER
from core.ui import *
from core.utils import *
from core.utils import ensure_async
from core.http import http_probe

PASSIVE_SOURCES = {
    "crt.sh": "https://crt.sh/?q=%.{domain}&output=json",
    "hackertarget": "https://api.hackertarget.com/hostsearch/?q={domain}",
    "alienvault": "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
    "urlscan": "https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1000",
    "rapiddns": "https://rapiddns.io/subdomain/{domain}?full=1",
    "webarchive": "https://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=original&collapse=urlkey&limit=5000",
    "threatcrowd": "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}",
    "certspotter": "https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names",
    "bufferover": "https://dns.bufferover.run/dns?q=.{domain}",
    "riddler": "https://riddler.io/search/exportcsv?q=pld:{domain}",
}

async def _query_crtsh(session, domain, subs):
    try:
        async with session.get(f"https://crt.sh/?q=%.{domain}&output=json",
                               headers={"User-Agent": UA}, timeout=aiohttp.ClientTimeout(total=15)) as r:
            if r.status == 200:
                data = await r.json()
                for e in data:
                    for n in e.get("name_value", "").splitlines():
                        n = n.strip().lstrip("*.")
                        if n.endswith(domain) and " " not in n:
                            subs.add(n)
        ok(f"crt.sh → {len(subs)}")
    except Exception as ex:
        warn(f"crt.sh: {ex}")

async def _query_hackertarget(session, domain, subs):
    try:
        async with session.get(f"https://api.hackertarget.com/hostsearch/?q={domain}",
                               headers={"User-Agent": UA}, timeout=aiohttp.ClientTimeout(total=10)) as r:
            if r.status == 200:
                text = await r.text()
                if "error" not in text.lower():
                    for line in text.splitlines():
                        parts = line.split(",")
                        if parts and parts[0].strip().endswith(domain):
                            subs.add(parts[0].strip().lower())
        ok(f"hackertarget → {len(subs)}")
    except Exception:
        pass

async def _query_alienvault(session, domain, subs):
    try:
        async with session.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
                               headers={"User-Agent": UA}, timeout=aiohttp.ClientTimeout(total=10)) as r:
            if r.status == 200:
                data = await r.json()
                for entry in data.get("passive_dns", []):
                    hostname = entry.get("hostname", "").strip().lower()
                    if hostname.endswith(domain) and " " not in hostname:
                        subs.add(hostname)
        ok(f"alienvault → {len(subs)}")
    except Exception:
        pass

async def _query_urlscan(session, domain, subs):
    try:
        async with session.get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1000",
                               headers={"User-Agent": UA}, timeout=aiohttp.ClientTimeout(total=12)) as r:
            if r.status == 200:
                data = await r.json()
                for result in data.get("results", []):
                    page = result.get("page", {})
                    h = page.get("domain", "").strip().lower()
                    if h.endswith(domain) and " " not in h:
                        subs.add(h)
        ok(f"urlscan → {len(subs)}")
    except Exception:
        pass

async def _query_webarchive(session, domain, subs):
    try:
        async with session.get(f"https://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=original&collapse=urlkey&limit=3000",
                               headers={"User-Agent": UA}, timeout=aiohttp.ClientTimeout(total=15)) as r:
            if r.status == 200:
                data = await r.json()
                for row in data[1:]:
                    if row:
                        url = row[0] if isinstance(row, list) else row
                        m = re.search(r"https?://([^/]+)", str(url))
                        if m:
                            h = m.group(1).lower().split(":")[0]
                            if h.endswith(domain) and " " not in h:
                                subs.add(h)
        ok(f"webarchive → {len(subs)}")
    except Exception:
        pass

async def _query_certspotter(session, domain, subs):
    try:
        async with session.get(f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names",
                               headers={"User-Agent": UA}, timeout=aiohttp.ClientTimeout(total=12)) as r:
            if r.status == 200:
                data = await r.json()
                for cert in data:
                    for name in cert.get("dns_names", []):
                        name = name.strip().lstrip("*.").lower()
                        if name.endswith(domain) and " " not in name:
                            subs.add(name)
        ok(f"certspotter → {len(subs)}")
    except Exception:
        pass

async def _query_rapiddns(session, domain, subs):
    try:
        async with session.get(f"https://rapiddns.io/subdomain/{domain}?full=1",
                               headers={"User-Agent": UA}, timeout=aiohttp.ClientTimeout(total=12)) as r:
            if r.status == 200:
                body = await r.text()
                for m in re.finditer(r'<td>([a-z0-9._-]+\.' + re.escape(domain) + r')</td>', body, re.I):
                    h = m.group(1).strip().lower()
                    if h.endswith(domain):
                        subs.add(h)
        ok(f"rapiddns → {len(subs)}")
    except Exception:
        pass

async def _query_threatcrowd(session, domain, subs):
    try:
        async with session.get(f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}",
                               headers={"User-Agent": UA}, timeout=aiohttp.ClientTimeout(total=10)) as r:
            if r.status == 200:
                data = await r.json(content_type=None)
                for h in data.get("subdomains", []):
                    h = h.strip().lower()
                    if h.endswith(domain) and " " not in h:
                        subs.add(h)
        ok(f"threatcrowd → {len(subs)}")
    except Exception:
        pass

async def _attempt_zone_transfer(domain, subs):
    try:
        import dns.resolver
        import dns.query
        import dns.zone
        ns_records = dns.resolver.resolve(domain, 'NS')
        for ns in ns_records:
            try:
                z = dns.zone.from_xfr(dns.query.xfr(str(ns), domain, timeout=5))
                for name, node in z.nodes.items():
                    full = f"{name}.{domain}".strip(".").lower()
                    if full.endswith(domain):
                        subs.add(full)
                ok(f"Zone transfer from {ns} successful! ({len(subs)} total)")
                return True
            except Exception:
                continue
    except Exception:
        pass
    return False

@ensure_async
async def run_subdomains(domain, out):
    section(1,"SUBDOMAIN ENUM  +  LIVE RESOLUTION  (10+ passive sources)")
    subs = set()

    info("Querying passive sources (crt.sh, hackertarget, alienvault, urlscan, certspotter, rapiddns, theatcrowd, webarchive)")
    async with aiohttp.ClientSession() as session:
        await asyncio.gather(
            _query_crtsh(session, domain, subs),
            _query_hackertarget(session, domain, subs),
            _query_alienvault(session, domain, subs),
            _query_urlscan(session, domain, subs),
            _query_webarchive(session, domain, subs),
            _query_certspotter(session, domain, subs),
            _query_rapiddns(session, domain, subs),
            _query_threatcrowd(session, domain, subs),
        )

    info(f"Passive sources combined: {len(subs)} unique subdomains")

    info("Attempting DNS zone transfer ...")
    loop = asyncio.get_running_loop()
    axfr_ok = await _attempt_zone_transfer(domain, subs)
    if not axfr_ok:
        info("Zone transfer not allowed (expected)")

    have_sf = t_ok("subfinder"); have_dnsx = t_ok("dnsx"); have_httpx = t_ok("httpx")
    sf_subs = []
    
    if have_sf:
        info("subfinder ...")
        r = await loop.run_in_executor(None, lambda: run_cmd(["subfinder", "-d", domain, "-silent", "-all"], 90))
        sf_subs = [s.strip().lower() for s in r.splitlines() if s.strip().lower().endswith(domain)]
    else:
        warn("subfinder missing — skipping")
        
    live_lines = []; tech_map = {}; all_subs = set(subs)
    NOISE = {
        "hsts","not found","home","index","error","ok","forbidden","redirect",
        "moved","bad request","unauthorized","server error","page not found",
        "access denied","welcome","login","sign in","dashboard","portal",
        "loading","please wait","vendor portal","green riyadh",
    }
    all_subs.update(sf_subs)

    info(f"Total unique subdomains after all sources: {len(all_subs)}")
    
    if have_dnsx and all_subs:
        info("dnsx resolve ...")
        print(GRY+"│"+RESET)
        dns_in = "\n".join(sorted(all_subs)) + "\n"
        dns_lines = await loop.run_in_executor(None, lambda: pipe_cmd(["dnsx", "-silent"], timeout=180, input_data=dns_in))
        resolved = [h.strip().lower() for h in dns_lines if h.strip()]
        if resolved:
            all_subs = set(resolved)
    elif not have_dnsx:
        warn("dnsx missing — skipping DNS verification")

    if not have_dnsx and not have_httpx:
        info("Trying DNS resolution via Python fallback ...")
        try:
            import dns.resolver
            resolved_py = set()
            for sub in sorted(all_subs)[:500]:
                try:
                    dns.resolver.resolve(sub, 'A', lifetime=3)
                    resolved_py.add(sub)
                except Exception:
                    pass
            if resolved_py:
                all_subs = resolved_py
                ok(f"Python DNS resolved {len(resolved_py)} subdomains")
        except ImportError:
            warn("dnspython not available for fallback resolution")
        
    if have_httpx and all_subs:
        info("httpx probe ...")
        print(GRY+"│"+RESET)
        hx_in = "\n".join(sorted(all_subs)) + "\n"
        lines = await loop.run_in_executor(None, lambda: pipe_cmd(["httpx", "-silent", "-status-code", "-title", "-tech-detect",
                        "-no-color", "-timeout", "8", "-retries", "1", "-threads", "50",
                        "-follow-redirects"], timeout=300, input_data=hx_in))
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if line.startswith("http"):
                live_lines.append(line)
                hm = re.match(r"(https?://[^\s\[]+)", line)
                techs = re.findall(r"\[([A-Za-z][A-Za-z0-9\-. ]{1,28})\]", line)
                if hm and techs:
                    host = re.sub(r"https?://", "", hm.group(1)).rstrip("/")
                    real = [t for t in techs
                          if t.lower() not in NOISE
                          and not re.match(r"^\d+$", t)
                          and len(t) >= 3 and t.count(" ") <= 2
                          and is_likely_tech(t)]
                    if real:
                        tech_map[host] = real
                sc = re.search(r"\[(\d{3})\]", line)
                code = int(sc.group(1)) if sc else 0
                print(GRY+"│  "+RESET+sbadge(code)+"  "+WHT+line[:90]+RESET)
    else:
        if not have_httpx:
            warn("httpx missing — using Python fallback probing")
        
        async with aiohttp.ClientSession() as session:
            sem = asyncio.Semaphore(20)
            async def probe_sub(sub):
                async with sem:
                    code, body, hdrs, ms = await http_probe(session, f"https://{sub}", timeout=6)
                    if code:
                        entry = f"https://{sub} [{code}] [{hdrs.get('Server', '')}]"
                        return entry, code
                    code2, body2, hdrs2, ms2 = await http_probe(session, f"http://{sub}", timeout=6)
                    if code2:
                        entry = f"http://{sub} [{code2}] [{hdrs2.get('Server', '')}]"
                        return entry, code2
                    return None, 0

            tasks = [probe_sub(sub) for sub in sorted(all_subs)[:200]]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, tuple) and r[0]:
                    entry, code = r
                    live_lines.append(entry)
                    print(GRY+"│  "+RESET+sbadge(code)+"  "+WHT+entry[:80]+RESET)
                    
    all_subs_sorted = sorted(all_subs)
    save_txt(f"{out}/subdomains.txt", all_subs_sorted)
    save_txt(f"{out}/live_hosts.txt", live_lines)
    save_json(f"{out}/tech_map.json", tech_map)
    ok(f"Subdomains   : {BOLD}{len(all_subs_sorted)}{RESET}")
    ok(f"Live hosts   : {BOLD}{len(live_lines)}{RESET}")
    ok(f"Tech detected: {BOLD}{len(tech_map)}{RESET}")
    _end()
    return all_subs_sorted, live_lines, tech_map

enum_and_resolve = run_subdomains
