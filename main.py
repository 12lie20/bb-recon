import sys, os, json, re, argparse, time, signal
import logging
from datetime import datetime
logger = logging.getLogger("bb-recon")
from core.config import CONFIG, _interrupted
from core.rate_limit import RATE_LIMITER
from core.ui import *
from core.utils import *
from core.http import *
from modules.subdomains import enum_and_resolve
from modules.waf_baseline import detect_waf_and_baseline
from modules.ports import port_scan
from modules.urls import collect_and_dedup
from modules.classifier import classify_and_probe
from modules.active import active_param_test
from modules.cors import cors_and_misc_checks
from modules.cookies import analyze_cookies
from modules.versions import version_cve_map
from modules.secrets import scan_js
from modules.headers import audit_security_headers
from modules.nuclei import run_nuclei
from modules.report import final_report, generate_html_report
def main():
    import core.config as cfg
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    banner()

    from core.tool_installer import ensure_tools
    ensure_tools(auto_install=True)

    p=argparse.ArgumentParser(description="BB-RECON v8.0",
                              formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("-d","--domain",    required=True,       help="Target domain (e.g. example.com)")
    p.add_argument("-o","--output",    default=None,        help="Output directory (default: auto)")
    p.add_argument("--no-nuclei",      action="store_true", help="Skip nuclei scan")
    p.add_argument("--no-ports",       action="store_true", help="Skip port scan")
    p.add_argument("--no-js",          action="store_true", help="Skip JS secrets scan")
    p.add_argument("--no-cookies",     action="store_true", help="Skip cookie analysis")
    p.add_argument("--no-cve",         action="store_true", help="Skip CVE mapping")
    p.add_argument("--no-headers",     action="store_true", help="Skip security headers audit")
    p.add_argument("--no-cloud",       action="store_true", help="Skip cloud misconfiguration scan")
    p.add_argument("--no-jwt",         action="store_true", help="Skip JWT attack testing")
    p.add_argument("--no-csrf",        action="store_true", help="Skip CSRF detection")
    p.add_argument("--no-api",         action="store_true", help="Skip API security testing")
    p.add_argument("--no-active",      action="store_true", help="Skip active vulnerability scanning")
    p.add_argument("--no-install",     action="store_true", help="Don't auto-install missing tools")
    p.add_argument("--threads",        type=int, default=30,help="Max threads for concurrent probing (default: 30)")
    p.add_argument("--verify-ssl",     action="store_true", help="Verify TLS certificates")
    p.add_argument("--dry-run",        action="store_true", help="Show external commands without executing scans")
    p.add_argument("--scope",          default=None,        help="Scope file (one domain/pattern per line)")
    p.add_argument("--fast",           action="store_true", help="Steps 1-5 only")
    p.add_argument("--deep",           action="store_true", help="Deep scan mode — extra payloads + slower + thorough")
    p.add_argument("--resume",         default=None,        help="Resume from a previous output directory")
    p.add_argument("--auth-cookie",    default=None,        help="Cookie header for authenticated scanning (e.g. 'session=abc123; token=xyz')")
    p.add_argument("--auth-header",    default=None,        help="Custom auth header (e.g. 'Authorization: Bearer eyJ...')")
    p.add_argument("--oob-server",     default=None,        help="OOB interaction server for blind detection (e.g. 'xyz.oast.live')")
    p.add_argument("--custom-header",  action="append",     default=[], help="Extra HTTP header (repeatable, format: 'Key: Value')")
    p.add_argument("--proxy",          default=None,        help="HTTP/SOCKS5 proxy (e.g. 'socks5://127.0.0.1:9050')")
    p.add_argument("--proxy-file",     default=None,        help="File with proxy list for rotation (one per line)")
    p.add_argument("--tor",            action="store_true", help="Route traffic through Tor (requires Tor running on port 9050)")
    p.add_argument("--notify-slack",   default=None,        help="Slack webhook URL for vulnerability alerts")
    p.add_argument("--notify-discord", default=None,        help="Discord webhook URL for vulnerability alerts")
    p.add_argument("--notify-telegram",default=None,        help="Telegram bot:chat_id for alerts (format: 'BOT_TOKEN:CHAT_ID')")
    args=p.parse_args()
    cfg.CONFIG.max_threads=max(1, int(args.threads or 30))
    cfg.CONFIG.original_threads=cfg.CONFIG.max_threads
    cfg.CONFIG.verify_ssl=bool(args.verify_ssl)
    cfg.CONFIG.dry_run=bool(args.dry_run)
    cfg.CONFIG.deep_scan=bool(args.deep)
    if args.auth_cookie:
        cfg.CONFIG.auth_cookie = args.auth_cookie
    if args.auth_header:
        cfg.CONFIG.auth_header = args.auth_header
    if args.oob_server:
        cfg.CONFIG.oob_server = args.oob_server
    for ch in (args.custom_header or []):
        if ":" in ch:
            k, v = ch.split(":", 1)
            cfg.CONFIG.custom_headers[k.strip()] = v.strip()

    if args.proxy or args.proxy_file or args.tor:
        from core.proxy import configure_proxy
        proxy_list = [args.proxy] if args.proxy else None
        configure_proxy(proxy_list=proxy_list, proxy_file=args.proxy_file, use_tor=args.tor)
        if args.tor:
            info("Traffic routed through Tor (socks5://127.0.0.1:9050)")
        elif args.proxy:
            info(f"Using proxy: {args.proxy}")
        elif args.proxy_file:
            info(f"Proxy rotation loaded from: {args.proxy_file}")

    notify_config = {}
    if args.notify_slack:
        notify_config["slack_webhook"] = args.notify_slack
    if args.notify_discord:
        notify_config["discord_webhook"] = args.notify_discord
    if args.notify_telegram:
        parts = args.notify_telegram.rsplit(":", 1)
        if len(parts) == 2:
            notify_config["telegram_bot_token"] = parts[0]
            notify_config["telegram_chat_id"] = parts[1]
    if notify_config:
        from core.notifications import configure_notifications
        configure_notifications(notify_config)
        info(f"Notifications enabled: {', '.join(notify_config.keys())}")

    domain=args.domain.lower().replace("https://","").replace("http://","").strip("/")
    if not re.match(r"^[a-z0-9.-]+$", domain):
        print(RED + "Invalid domain format. Allowed: a-z, 0-9, dot, dash" + RESET)
        sys.exit(2)
    out=args.output or f"recon_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    resume_step = 0
    if args.resume:
        out = args.resume
        cp = load_checkpoint(out)
        if cp:
            resume_step = cp.get("step", 0)
            info(f"Resuming from step {resume_step} in {out}")
        else:
            warn(f"No checkpoint found in {out} — starting fresh")
    os.makedirs(out, exist_ok=True)
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(os.path.join(out, "scan.log"), encoding="utf-8"),
        ]
    )
    _partial = {}
    def _sigint_handler(sig, frame):
        global _interrupted
        cfg._interrupted = True
        warn("\nInterrupted (Ctrl+C) — saving partial results ...")
        try:
            save_checkpoint(out, _partial.get("_last_step", 0), _partial)
        except Exception:
            pass
        print(GRY + DIM + f"\n  Partial results saved to {out}/" + RESET)
        sys.exit(130)
    signal.signal(signal.SIGINT, _sigint_handler)
    scope_patterns = None
    if args.scope and os.path.exists(args.scope):
        with open(args.scope) as sf:
            scope_patterns = [l.strip().lower() for l in sf if l.strip() and not l.startswith("#")]
        info(f"Scope file loaded: {len(scope_patterns)} patterns")
    print(GRY+"  TARGET  : "+RESET+CYN+BOLD+domain+RESET)
    print(GRY+"  OUTPUT  : "+RESET+GRY+out+RESET)
    print(GRY+"  THREADS : "+RESET+GRY+str(cfg.CONFIG.max_threads)+RESET)
    print(GRY+"  VERSION : "+RESET+GRY+"BB-RECON v8.0"+RESET)
    print(GRY+"  SSL     : "+RESET+GRY+("verify" if cfg.CONFIG.verify_ssl else "insecure-skip-verify")+RESET)
    if cfg.CONFIG.deep_scan:
        print(GRY+"  MODE    : "+RESET+ORG+BOLD+"DEEP SCAN"+RESET)
    if cfg.CONFIG.auth_cookie:
        print(GRY+"  AUTH    : "+RESET+YLW+"Cookie authentication active"+RESET)
    if cfg.CONFIG.auth_header:
        print(GRY+"  AUTH    : "+RESET+YLW+"Header authentication active"+RESET)
    if cfg.CONFIG.oob_server:
        print(GRY+"  OOB     : "+RESET+CYN+cfg.CONFIG.oob_server+RESET)
    if not cfg.CONFIG.verify_ssl:
        warn("TLS verification is disabled; results can be affected by MITM/proxying")
    if cfg.CONFIG.dry_run:
        info("Dry-run mode enabled — no external scanner commands will execute")
    if resume_step:
        print(GRY+"  RESUME  : "+RESET+YLW+BOLD+f"from step {resume_step}"+RESET)
    if scope_patterns:
        print(GRY+"  SCOPE   : "+RESET+GRY+args.scope+f" ({len(scope_patterns)} patterns)"+RESET)
    print(GRY+"  STARTED : "+RESET+GRY+DIM+datetime.now().strftime("%Y-%m-%d %H:%M:%S")+RESET)
    print()
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
    import asyncio
    
    t0=time.time()
    
    async def async_main():
        subs, live, tech_map = [], [], {}
        baselines, waf_delay = {}, 0.0
        ports, urls, classified = {}, [], {}
        active_findings, misc_findings, cookies, cves, secrets, sec_hdrs, vulns, cloud_findings = [], [], [], [], [], [], [], []
        jwt_findings, csrf_findings, api_findings = [], [], []
        
        if resume_step < 1:
            try:
                subs, live, tech_map = await run_subdomains(domain, out)
            except Exception as e:
                warn(f"Subdomain enumeration failed: {e}")
                logger.exception("run_subdomains failed")
                subs, live, tech_map = [], [], {}
            _partial["_last_step"] = 1
            save_checkpoint(out, 1, {"subs_count": len(subs), "live_count": len(live)})
        else:
            subs_f = f"{out}/subdomains.txt"
            subs = open(subs_f).read().splitlines() if os.path.exists(subs_f) else []
            live_f = f"{out}/live_hosts.txt"
            live = open(live_f).read().splitlines() if os.path.exists(live_f) else []
            tech_f = f"{out}/tech_map.json"
            tech_map = json.load(open(tech_f)) if os.path.exists(tech_f) else {}
            ok(f"Resumed: {len(subs)} subs, {len(live)} live hosts")
            
        if scope_patterns:
            live = [l for l in live
                    if any(sp in l.lower() for sp in scope_patterns)]
            subs = [s for s in subs
                    if any(sp in s.lower() for sp in scope_patterns)]
            ok(f"Scope filter: {len(subs)} subdomains, {len(live)} live hosts in scope")
            
        if resume_step < 2:
            try:
                baselines, waf_delay = await run_waf_baseline(domain, live, out)
            except Exception as e:
                warn(f"WAF baseline failed: {e}")
                logger.exception("run_waf_baseline failed")
                baselines, waf_delay = {}, 0.0
            _partial["_last_step"] = 2
            save_checkpoint(out, 2, {"waf_delay": waf_delay})
            RATE_LIMITER.delay = max(RATE_LIMITER.delay, waf_delay)
        else:
            bl_f = f"{out}/baseline.json"
            baselines = json.load(open(bl_f)) if os.path.exists(bl_f) else {}
            waf_delay = 0.0
            ok("Resumed: baselines loaded")
            
        if resume_step < 3:
            try:
                ports = await run_ports(live, out) if not (args.no_ports or args.fast) else {}
            except Exception as e:
                warn(f"Port scan failed: {e}")
                logger.exception("run_ports failed")
                ports = {}
            _partial["_last_step"] = 3
            save_checkpoint(out, 3, {})
        else:
            ports = {}
            
        if resume_step < 4:
            try:
                urls = await run_urls(domain, live, out)
            except Exception as e:
                warn(f"URL collection failed: {e}")
                logger.exception("run_urls failed")
                urls = []
            _partial["_last_step"] = 4
            save_checkpoint(out, 4, {"urls_count": len(urls)})
        else:
            urls_f = f"{out}/urls.txt"
            urls = open(urls_f).read().splitlines() if os.path.exists(urls_f) else []
            ok(f"Resumed: {len(urls)} URLs")
        
        try:
            sourcemap_urls = await run_sourcemap_analyzer(domain, urls, live, out)
            if sourcemap_urls:
                urls.extend(sourcemap_urls)
                info(f"Source maps added {len(sourcemap_urls)} new URLs to pipeline")
        except Exception as e:
            logger.debug(f"Source map analysis failed: {e}")
            
        if resume_step < 5:
            try:
                classified = await run_classifier(urls, baselines, out)
            except Exception as e:
                warn(f"URL classification failed: {e}")
                logger.exception("run_classifier failed")
                classified = {}
            _partial["_last_step"] = 5
            save_checkpoint(out, 5, {})
        else:
            cl_f = f"{out}/classified_urls.json"
            classified = json.load(open(cl_f)) if os.path.exists(cl_f) else {}
            
        if not args.fast:
            if not args.no_active:
                try:
                    waf_flag = None
                    if isinstance(baselines, dict) and baselines:
                        first_bl = next(iter(baselines.values()), {})
                        waf_flag = first_bl.get("waf") if isinstance(first_bl, dict) else None
                    active_findings = await run_active_scans(classified, baselines, waf_flag, waf_delay, out)
                except Exception as e:
                    warn(f"Active scanning failed: {e}")
                    logger.exception("run_active_scans failed")
                    active_findings = []
            _partial["_last_step"] = 6
            save_checkpoint(out, 6, {})

            if not args.no_jwt:
                try:
                    target_url = f"https://{domain}"
                    jwt_findings = await run_jwt_attacks(target_url, cookies, {}, classified, out)
                except Exception as e:
                    warn(f"JWT analysis failed: {e}")
                    logger.exception("run_jwt_attacks failed")
                    jwt_findings = []

            if not args.no_csrf:
                try:
                    csrf_findings = await run_csrf_detection(urls, out)
                except Exception as e:
                    warn(f"CSRF detection failed: {e}")
                    logger.exception("run_csrf_detection failed")
                    csrf_findings = []

            if not args.no_api:
                try:
                    target_url = f"https://{domain}"
                    api_findings = await run_api_security(target_url, urls, classified, out)
                except Exception as e:
                    warn(f"API security testing failed: {e}")
                    logger.exception("run_api_security failed")
                    api_findings = []
        
        if not args.fast:
            async def safe_run(coro_func, *argsv, default=None):
                if default is None: default = []
                try:
                    return await coro_func(*argsv)
                except Exception as e:
                    name = getattr(coro_func, '__name__', str(coro_func))
                    warn(f"Module {name} failed: {e}")
                    logger.exception(f"Module {name} failed")
                    return default
            
            async def run_if(cond, coro_func, *argsv, default=[]):
                if cond: return await safe_run(coro_func, *argsv, default=default)
                return default
            
            loop = asyncio.get_running_loop()
            
            r_misc, r_ckie, r_cves, r_secr, r_hdrs, r_nucl, r_cloud = await asyncio.gather(
                safe_run(run_cors_misc, domain, classified, subs, out),
                run_if(not args.no_cookies, run_cookies, domain, out),
                run_if(not args.no_cve, run_versions, domain, tech_map, out),
                run_if(not args.no_js, run_secrets, domain, live, urls, out),
                run_if(not args.no_headers, run_headers, domain, live, out),
                run_if(not args.no_nuclei, loop.run_in_executor, None, run_nuclei, domain, live, tech_map, out),
                run_if(not args.no_cloud, run_cloud_scan, domain, urls, live, out),
            )
            misc_findings, cookies, cves, secrets, sec_hdrs, vulns, cloud_findings = r_misc, r_ckie, r_cves, r_secr, r_hdrs, r_nucl, r_cloud

        elapsed = int(time.time()-t0)
        print(GRY+DIM+f"\n  Completed in {elapsed}s\n"+RESET)
        
        all_extra_findings = active_findings + jwt_findings + csrf_findings + api_findings

        final_report(domain, out, subs, live, urls, classified,
                     all_extra_findings, misc_findings, cookies, cves, secrets, vulns, ports, sec_hdrs, cloud_findings)
                     
        summary_data = {
            "subdomains": len(subs), "live_hosts": len(live),
            "total_urls": len(urls),
            "active_findings": len(active_findings),
            "jwt_findings": len(jwt_findings),
            "csrf_findings": len(csrf_findings),
            "api_findings": len(api_findings),
        }
        generate_html_report(domain, out, summary_data)

        if notify_config:
            try:
                from core.notifications import NOTIFIER
                import asyncio as _aio
                await NOTIFIER.notify_scan_complete(domain, summary_data)
            except Exception as e:
                logger.debug(f"End notification failed: {e}")
        
        cp_file = f"{out}/.checkpoint.json"
        if os.path.exists(cp_file):
            try: os.remove(cp_file)
            except Exception: pass
            
        rl_stats = RATE_LIMITER.stats()
        print(GRY + DIM + f"  Rate limiter stats: {rl_stats['total_blocked']} blocks / "
              f"{rl_stats['total_requests']} requests ({rl_stats['block_rate']}%), "
              f"final delay {rl_stats['final_delay']}s" + RESET)
        print()

    asyncio.run(async_main())

if __name__=="__main__":
    main()
