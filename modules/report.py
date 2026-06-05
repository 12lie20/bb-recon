import os, json, re, logging
from datetime import datetime
logger = logging.getLogger("bb-recon")
from core.config import CONFIG
from core.rate_limit import RATE_LIMITER
from core.ui import *
from core.utils import *
def final_report(domain, out, subs, live, urls, classified, active_findings, misc_findings, cookies,
                 cves, secrets, vulns, ports, sec_hdrs=None, cloud_findings=None):
    if sec_hdrs is None: sec_hdrs = []
    if cloud_findings is None: cloud_findings = []
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
    cloud_critical = len([f for f in cloud_findings if f.get("severity") in ("CRITICAL","HIGH")])
    summary={
        "target":domain,"date":datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "subdomains":len(subs),"live_hosts":len(live),
        "total_urls":len(urls),"validated_200":v200,
        "open_ports":open_ports,"js_secrets":len(secrets),
        "cookie_issues":len(cookies),"cves_mapped":len(cves),
        "cves_critical":crit_cves,
        "confirmed_vulns":confirmed_vulns,
        "misc_critical":misc_critical,
        "cloud_findings":len(cloud_findings),"cloud_critical":cloud_critical,
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
    row("Cloud/Infra Critical", cloud_critical,   RED if cloud_critical else WHT)
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
        ("cloud_findings.json","Cloud/Infra/GraphQL findings"),
        ("nuclei.json","Nuclei findings"),
        ("tech_map.json","Tech fingerprints"),
        ("summary.json","Full summary"),
    ]
    for fname,desc in files:
        e=os.path.exists(f"{out}/{fname}")
        print((DGRN if e else GRY)+f"  {'✔' if e else '✗'}  {fname:<35}{desc}"+RESET)
    print()
def generate_html_report(domain, out, summary_data):
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
    cloud   = _load("cloud_findings.json")
    nuclei  = _load("nuclei.json")
    cve_data= _load("cve_mapping.json")
    headers_data = _load("security_headers.json")
    
    cves = cve_data.get("cves", []) if isinstance(cve_data, dict) else cve_data
    
    vuln_rows = ""
    for fi in (active if isinstance(active, list) else []):
        sev = "CRITICAL" if fi.get("type") in ("SQLi","LFI","XSS","SSTI","OS-CMD","SSRF") else "HIGH"
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
    for fi in (cloud if isinstance(cloud, list) else []):
        sev = fi.get("severity","MEDIUM")
        vuln_rows += (f"<tr><td><span class='sev-{sev.lower()}'>{sev}</span></td>"
                      f"<td>{fi.get('type','')}</td>"
                      f"<td style='word-break:break-all'>{fi.get('url',fi.get('bucket',''))[:100]}</td>"
                      f"<td>{fi.get('description','')[:40]}</td>"
                      f"<td>{fi.get('note','')[:80]}</td></tr>\n")
    
    secret_rows = ""
    for s in (secrets if isinstance(secrets, list) else []):
        secret_rows += (f"<tr><td>{s.get('type','')}</td>"
                        f"<td style='word-break:break-all'>{s.get('value','')[:90]}</td>"
                        f"<td style='word-break:break-all'>{s.get('url','')[:80]}</td></tr>\n")
    
    cve_rows = ""
    for c in cves:
        score = c.get("cvss", 0)
        sev_class = "critical" if score >= 9 else ("high" if score >= 7 else "medium")
        cve_rows += (f"<tr><td><span class='sev-{sev_class}'>{score}</span></td>"
                     f"<td>{c.get('cve','')}</td>"
                     f"<td>{c.get('tech','')}</td>"
                     f"<td>{c.get('version','')}</td>"
                     f"<td>{c.get('desc','')[:80]}</td></tr>\n")
    
    nuclei_rows = ""
    for n in (nuclei if isinstance(nuclei, list) else []):
        sev = n.get("severity","INFO")
        sev_class = sev.lower() if sev.lower() in ("critical","high","medium") else "medium"
        nuclei_rows += (f"<tr><td><span class='sev-{sev_class}'>{sev}</span></td>"
                        f"<td>{n.get('name','')[:60]}</td>"
                        f"<td style='word-break:break-all'>{n.get('matched_at','')[:80]}</td>"
                        f"<td>{', '.join(n.get('cve',[])) if n.get('cve') else ''}</td></tr>\n")
    
    header_rows = ""
    for h in (headers_data if isinstance(headers_data, list) else []):
        sev = h.get("severity","LOW")
        sev_class = sev.lower() if sev.lower() in ("high","medium") else "medium"
        header_rows += (f"<tr><td><span class='sev-{sev_class}'>{sev}</span></td>"
                        f"<td>{h.get('host','')[:40]}</td>"
                        f"<td>{h.get('header','')}</td>"
                        f"<td>{h.get('issue','')[:60]}</td></tr>\n")
    
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def _table(headers, rows, empty_msg):
        if not rows:
            return f"<p class='empty'>{empty_msg}</p>"
        th = "".join(f"<th>{h}</th>" for h in headers)
        return f"<table><tr>{th}</tr>{rows}</table>"
    
    vuln_table = _table(["Severity","Type","URL","Param/Header","Evidence"], vuln_rows, "No vulnerabilities found.")
    secret_table = _table(["Type","Value","Source"], secret_rows, "No secrets found.")
    cve_table = _table(["CVSS","CVE","Technology","Version","Description"], cve_rows, "No CVEs mapped.")
    nuclei_table = _table(["Severity","Name","Matched At","CVE"], nuclei_rows, "No Nuclei findings.")
    header_table = _table(["Severity","Host","Header","Issue"], header_rows, "No header issues.")
    
    total_findings = len(active if isinstance(active,list) else []) + len(misc if isinstance(misc,list) else []) + len(cloud if isinstance(cloud,list) else [])
    
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
       padding-bottom:0.4rem; font-size:1.3rem; cursor:pointer; }}
  h2:hover {{ color:#79c0ff; }}
  .meta {{ color:#8b949e; margin-bottom:2rem; }}
  .stats {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr));
            gap:1rem; margin-bottom:2rem; }}
  .stat {{ background:var(--card); border:1px solid var(--border); border-radius:8px;
           padding:1rem; text-align:center; transition:transform 0.2s; }}
  .stat:hover {{ transform:translateY(-2px); border-color:var(--accent); }}
  .stat .num {{ font-size:2rem; font-weight:700; color:var(--accent); }}
  .stat .lbl {{ font-size:0.85rem; color:#8b949e; }}
  .stat.danger .num {{ color:var(--crit); }}
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
  .sev-medium {{ background:var(--med); color:#000; padding:2px 8px;
                border-radius:4px; font-weight:700; font-size:0.8rem; }}
  .empty {{ color:#484f58; text-align:center; padding:2rem; }}
  .section {{ margin-bottom:2rem; }}
  .badge {{ display:inline-block; padding:2px 10px; border-radius:12px; font-size:0.75rem;
            font-weight:600; margin:0 4px; }}
  .badge-crit {{ background:#f8514933; color:var(--crit); border:1px solid var(--crit); }}
  .badge-high {{ background:#d2992233; color:var(--high); border:1px solid var(--high); }}
  .filter-bar {{ margin:1rem 0; display:flex; gap:0.5rem; flex-wrap:wrap; }}
  .filter-btn {{ background:var(--card); border:1px solid var(--border); color:var(--text);
                 padding:4px 12px; border-radius:6px; cursor:pointer; font-size:0.85rem; }}
  .filter-btn:hover {{ border-color:var(--accent); }}
  .filter-btn.active {{ background:var(--accent); color:#000; border-color:var(--accent); }}
</style>
<script>
function toggleSection(id) {{
  var el = document.getElementById(id);
  el.style.display = el.style.display === 'none' ? 'block' : 'none';
}}
function filterTable(tableId, severity) {{
  var table = document.getElementById(tableId);
  if (!table) return;
  var rows = table.querySelectorAll('tr');
  for (var i = 1; i < rows.length; i++) {{
    var sev = rows[i].querySelector('td span');
    if (!severity || (sev && sev.textContent.toUpperCase().includes(severity.toUpperCase()))) {{
      rows[i].style.display = '';
    }} else {{
      rows[i].style.display = 'none';
    }}
  }}
}}
</script>
</head><body>
<h1>&#128269; BB-RECON v8.0 Report</h1>
<p class="meta">Target: <strong>{domain}</strong> &nbsp;|&nbsp; {ts} &nbsp;|&nbsp; 
<span class="badge badge-crit">{total_findings} Total Findings</span></p>
<div class="stats">
  <div class="stat"><div class="num">{summary_data.get('subdomains',0)}</div><div class="lbl">Subdomains</div></div>
  <div class="stat"><div class="num">{summary_data.get('live_hosts',0)}</div><div class="lbl">Live Hosts</div></div>
  <div class="stat"><div class="num">{summary_data.get('total_urls',0)}</div><div class="lbl">URLs</div></div>
  <div class="stat{'  danger' if len(active if isinstance(active,list) else []) else ''}"><div class="num">{len(active if isinstance(active,list) else [])}</div><div class="lbl">Active Vulns</div></div>
  <div class="stat{'  danger' if len(cloud if isinstance(cloud,list) else []) else ''}"><div class="num">{len(cloud if isinstance(cloud,list) else [])}</div><div class="lbl">Cloud Issues</div></div>
  <div class="stat"><div class="num">{len(secrets if isinstance(secrets,list) else [])}</div><div class="lbl">JS Secrets</div></div>
  <div class="stat"><div class="num">{len(cves)}</div><div class="lbl">CVEs</div></div>
  <div class="stat"><div class="num">{len(nuclei if isinstance(nuclei,list) else [])}</div><div class="lbl">Nuclei</div></div>
</div>

<div class="section">
<h2 onclick="toggleSection('vulns')">&#9888;&#65039; Vulnerabilities ({len(active if isinstance(active,list) else []) + len(misc if isinstance(misc,list) else []) + len(cloud if isinstance(cloud,list) else [])})</h2>
<div id="vulns">{vuln_table}</div>
</div>

<div class="section">
<h2 onclick="toggleSection('secrets-sec')">&#128273; JS Secrets ({len(secrets if isinstance(secrets,list) else [])})</h2>
<div id="secrets-sec">{secret_table}</div>
</div>

<div class="section">
<h2 onclick="toggleSection('cves-sec')">&#128736; CVE Mapping ({len(cves)})</h2>
<div id="cves-sec">{cve_table}</div>
</div>

<div class="section">
<h2 onclick="toggleSection('nuclei-sec')">&#9889; Nuclei Findings ({len(nuclei if isinstance(nuclei,list) else [])})</h2>
<div id="nuclei-sec">{nuclei_table}</div>
</div>

<div class="section">
<h2 onclick="toggleSection('headers-sec')">&#128737; Security Headers ({len(headers_data if isinstance(headers_data, list) else [])})</h2>
<div id="headers-sec">{header_table}</div>
</div>

<p class="meta" style="margin-top:3rem">Generated by BB-RECON v8.0 &mdash; Bug Bounty Reconnaissance Framework</p>
</body></html>"""
    report_path = f"{out}/report.html"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html)
    ok(f"HTML report: {report_path}")
    return report_path
