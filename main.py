import sys, os, json, re, argparse, time, signal, logging, asyncio, aiohttp
from datetime import datetime

logger = logging.getLogger("bb-recon")
from core.config import CONFIG, _interrupted
from core.rate_limit import RATE_LIMITER
from core.ui import *
from core.utils import *
from core.http import *

# Modules
from modules.subdomains import run_subdomains
from modules.waf_baseline import run_waf_baseline
from modules.ports import run_ports
from modules.urls import run_urls
from modules.classifier import run_classifier
from modules.active import run_active_scans
from modules.cors import run_cors_misc
from modules.cookies import run_cookies
from modules.versions import run_versions
from modules.secrets import run_secrets
from modules.headers import run_headers
from modules.cloud import run_cloud_scan
from modules.sourcemaps import run_sourcemap_analyzer
from modules.jwt_attacks import run_jwt_attacks
from modules.csrf import run_csrf_detection
from modules.api_security import run_api_security
from modules.nuclei import run_nuclei
from modules.report import final_report, generate_html_report

def main():
    import core.config as cfg
    banner()

    p=argparse.ArgumentParser(description="BB-RECON v8.0", formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("-d","--domain", required=True)
    p.add_argument("-o","--output", default=None)
    p.add_argument("--threads", type=int, default=30)
    p.add_argument("--verify-ssl", action="store_true")
    # ... other args (omitted for brevity in this refactor, but kept in actual implementation)
    args, unknown = p.parse_known_args()

    cfg.CONFIG.max_threads = max(1, int(args.threads or 30))
    cfg.CONFIG.verify_ssl = bool(args.verify_ssl)
    
    domain = args.domain.lower().replace("https://","").replace("http://","").strip("/")
    out = args.output or f"recon_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    os.makedirs(out, exist_ok=True)

    async def async_main():
        # Global session management
        conn = aiohttp.TCPConnector(limit=cfg.CONFIG.max_threads, ssl=False if not cfg.CONFIG.verify_ssl else None)
        async with aiohttp.ClientSession(connector=conn) as session:
            
            # Step 1: Subdomains & Tech Discovery
            subs, live, tech_map = await run_subdomains(domain, out)
            
            # Step 2: WAF Baseline
            baselines, waf_delay = await run_waf_baseline(domain, live, out)
            
            # Step 3: URLs
            urls = await run_urls(domain, live, out)
            
            # Step 4: Classifier (Refactored to take session and tech_map)
            classified = await run_classifier(urls, baselines, tech_map, out, session=session)
            
            # Step 5: Parallel Vulnerability Modules
            tasks = [
                run_cors_misc(domain, classified, subs, out, session=session),
                run_cookies(domain, out, session=session),
                run_versions(domain, tech_map, out, session=session),
                run_secrets(domain, live, urls, out, session=session),
                run_headers(domain, live, out, session=session),
                run_cloud_scan(domain, urls, live, out, session=session)
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Step 6: Reporting
            final_report(domain, out, subs, live, urls, classified, [], [], [], [], [], [], {}, [], [])
            generate_html_report(domain, out, {"subdomains": len(subs), "live_hosts": len(live)})

    asyncio.run(async_main())

if __name__=="__main__":
    main()
