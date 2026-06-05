import re
import random
import string as _str
import hashlib
import aiohttp
import asyncio
import logging
logger = logging.getLogger("bb-recon")

from core.ui import *
from core.utils import *
from core.utils import ensure_async
from core.http import http_probe
from core.config import CONFIG

WAF_SIGNATURES = {
    "Cloudflare":    ["cloudflare","cf-ray","__cfduid","cf-chl"],
    "AWS WAF":       ["x-amzn-requestid","awswaf","x-amz-cf-id","x-amz-apigw-id"],
    "Akamai":        ["akamai","x-check-cacheable","x-akamai","akamaighost"],
    "F5 BIG-IP":     ["x-cnection","bigip","f5","ts=","x-wa-info","bigipserver"],
    "Sucuri":        ["x-sucuri","sucuri","x-sucuri-id","sucuri-cache"],
    "ModSecurity":   ["mod_security","modsecurity","owasp","mod_defender"],
    "Imperva/Incapsula":["x-iinfo","incapsula","visid_incap","incap_ses","incapsula-incident-id"],
    "Fortinet":      ["fortigate","fortiwebeid","fortiweb","fortiwafsid"],
    "Barracuda":     ["barra_counter_session","barracudabypass","barracuda"],
    "Sophos":        ["x-astaro-id"],
    "Wordfence":     ["wordfence","wfvt_"],
    "DenyAll":       ["sessioncookie","detected","denyall"],
    "Comodo":        ["x-c3-id","comodo"],
    "Palo Alto":     ["x-pan-","panorama"],
    "Radware":       ["x-sl-compstate","rdwr","appwall","shield_redirect"],
    "Citrix/NetScaler":["ns_af","citrix","netscaler","ns-edge"],
    "EdgeCast/Verizon":["x-ec-","ecdf","verizon"],
    "StackPath":     ["x-sp-","stackpath"],
    "Fastly":        ["fastly","x-fastly","fastly-restarts"],
    "KeyCDN":        ["server: keycdn"],
    "Azure WAF/FrontDoor":["x-azure-ref","front-door","x-ms-forbidden-ip"],
    "Google Cloud Armor":["x-recaptcha-token","cloud armor","x-goog-request-id"],
    "Reblaze":       ["rbzid","reblaze"],
    "Safe3WAF":      ["safe3waf","safe3"],
    "NAXSI":         ["naxsi"],
    "ShadowDaemon":  ["shadow daemon"],
    "LiteSpeed":     ["litespeed","x-lsreq-id"],
    "Wallarm":       ["nginx-wallarm","wallarm"],
    "AWS Shield":    ["x-amz-server-side-encryption","aws-shield"],
    "Vercel":        ["x-vercel-id","vercel"],
    "Generic WAF":   ["attack id","attack_id","web page blocked","blocked by","request rejected",
                      "access denied","web application firewall","your request has been blocked",
                      "security module","bot detection","captcha","challenge"],
}

@ensure_async
async def run_waf_baseline(domain, live_lines, out):
    section(2,"WAF DETECTION  +  BASELINE FINGERPRINT  (30+ WAFs)")
    hosts_to_baseline = set()
    for line in live_lines:
        m = re.match(r"https?://([^/\s\[]+)", line)
        if m:
            hosts_to_baseline.add(m.group(1))
    hosts_to_baseline.add(domain)
    baselines = {}
    
    async with aiohttp.ClientSession() as session:
        async def _build_host_baseline(host):
            base_url = f"https://{host}"
            bl = {"host": host}
            code_n, body_n, hdrs_n, ms_n = await http_probe(session, base_url+"/", timeout=10)
            bl["normal_code"] = code_n
            bl["normal_size"] = len(body_n)
            bl["normal_ms"]   = ms_n
            
            fake_bodies, fake_sizes = [], []
            fc = 0
            for i in range(3):
                rand_suffix = "".join(random.choices(_str.ascii_lowercase + _str.digits, k=10))
                fc, fb, _, _ = await http_probe(session, f"{base_url}/nonexistent_{rand_suffix}", timeout=8)
                fake_bodies.append(fb)
                fake_sizes.append(len(fb))
                
            fake_sizes.sort()
            med = fake_sizes[1]
            thr = max(150, int(med * 0.10))
            fake_hashes = {hashlib.md5(b.encode()).hexdigest() for b in fake_bodies if b}
            fake_snippets = set()
            for fb in fake_bodies:
                clean = re.sub(r"<[^>]+>", "", fb).strip()[:100]
                if len(clean) > 20:
                    fake_snippets.add(clean.lower())
                    
            code_404 = fc
            bl["fake_404_code"]     = code_404
            bl["fake_404_size"]     = med
            bl["soft_404"]          = (code_404 == 200)
            bl["soft_404_size"]     = med if code_404 == 200 else 0
            bl["soft_404_threshold"]= thr if code_404 == 200 else 0
            bl["soft_404_hashes"]   = list(fake_hashes)
            bl["soft_404_snippets"] = list(fake_snippets)
            return host, bl

        info(f"Building per-host baselines for {len(hosts_to_baseline)} host(s) ...")
        
        sem = asyncio.Semaphore(10)
        async def bound_build(host):
            async with sem:
                return await _build_host_baseline(host)
                
        tasks = [bound_build(h) for h in hosts_to_baseline]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for res in results:
            if isinstance(res, Exception):
                warn(f"Baseline failed: {res}")
                continue
            _h, _bl = res
            baselines[_h] = _bl
            _s = "SOFT404" if _bl["soft_404"] else "normal"
            ok(f"{_h:<40}  {sbadge(_bl['normal_code'])}  "
               f"fake={_bl['fake_404_size']}b  [{_s}]")
               
        base_url = f"https://{domain}"
        if domain not in baselines:
            _, baseline = await _build_host_baseline(domain)
            baselines[domain] = baseline
        else:
            baseline = baselines[domain]
            
        waf_detected = None
        waf_delay = 0.0
        code_n  = baseline["normal_code"]
        _, body_n, hdrs_n, _ = await http_probe(session, base_url+"/", timeout=8)
        
        info("WAF probe (multi-vector) ...")
        
        waf_probes = [
            base_url+"/index.php?param=../../../../etc/passwd",
            base_url+"/?q=<script>alert(1)</script>",
            base_url+"/?id=1' OR 1=1--",
            base_url+"/wp-admin/../../../etc/shadow",
        ]
        
        for probe_url in waf_probes:
            code_w, body_w, hdrs_w, ms_w = await http_probe(session, probe_url, timeout=8)
            
            all_headers_lower={k.lower():v.lower() for k,v in hdrs_w.items()}
            body_check=(body_w[:3000]).lower()
            
            for waf_name,sigs in WAF_SIGNATURES.items():
                for sig in sigs:
                    sig_l=sig.lower()
                    if (sig_l in body_check or
                        any(sig_l in k or sig_l in v for k,v in all_headers_lower.items())):
                        waf_detected=waf_name
                        break
                if waf_detected: break
            if waf_detected: break
            
            if not waf_detected:
                if code_w in (406,429,503) and code_n==200:
                    waf_detected="Generic WAF (status-based)"
                    break
                elif code_w==200 and len(body_w)<500 and code_n==200 and len(body_n)>500:
                    waf_detected="Generic WAF (response-size anomaly)"
                    break
                 
        if waf_detected:
            found(f"WAF Detected: {waf_detected}")
            from core.rate_limit import RATE_LIMITER
            RATE_LIMITER.adapt_to_waf(waf_detected)
            waf_delay = RATE_LIMITER.delay
            info(f"WAF-adaptive: delay={waf_delay:.1f}s  threads={CONFIG.max_threads}  timeout={CONFIG.scan_timeout}s")
        else:
            ok("No WAF detected — or WAF not triggered by probes")
            
        server_info={}
        for h in ("Server","X-Powered-By","X-AspNet-Version","X-Runtime","X-Generator","Via"):
            if h in hdrs_n: server_info[h]=hdrs_n[h]
            
        if server_info:
            info("Server headers:")
            for k,v in server_info.items():
                print(GRY+"│    "+RESET+CYN+f"{k}: "+RESET+WHT+v+RESET)
                
        baseline["waf"]=waf_detected
        baseline["server_headers"]=server_info
        for _bl in baselines.values():
            _bl["waf"] = waf_detected
        baselines[domain] = baseline
        save_json(f"{out}/baseline.json", baselines)
        _end()
        return baselines, waf_delay

detect_waf_and_baseline = run_waf_baseline
