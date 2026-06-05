import subprocess, os, json, re, time
import logging
logger = logging.getLogger("bb-recon")
from core.config import CONFIG, _interrupted
from core.rate_limit import RATE_LIMITER
from core.ui import *
from core.utils import *
from core.http import *
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
