import re
import urllib.parse
import asyncio
import aiohttp
import logging
from collections import defaultdict
logger = logging.getLogger("bb-recon")
from core.config import CONFIG, _interrupted
from core.rate_limit import RATE_LIMITER
from core.ui import *
from core.utils import *
from core.utils import ensure_async
from core.http import http_probe

KNOWN_CVE_MAP={
    "php":         [
                    ('CVE-2026-0921', 'RCE via phar deserialization', 9.8, (8, 1, 0), (8, 4, 2), None),("CVE-2024-4577","CGI argument injection RCE",9.8,(8,1,0),(8,3,8),None),
                    ("CVE-2019-11043","RCE via php-fpm",9.8,(5,6,0),(7,3,99),None),
                    ("CVE-2022-31626","mysqlnd buffer overflow",8.8,(7,4,0),(8,1,7),None),
                    ("CVE-2016-5773","RCE ZipArchive unserialize",9.8,(5,4,0),(5,6,99),None),
                    ("CVE-2016-5385","HTTPoxy SSRF",8.1,(5,4,0),(5,6,99),None)],
    "apache":         [
                    ('CVE-2026-23918', 'Double Free in mod_http2', 7.5, (2, 4, 0), (2, 4, 66), None),
                    ('CVE-2026-11822', 'HTTP/2 Header Smuggling', 9.1, (2, 4, 0), (2, 4, 68), None),("CVE-2021-41773","Path traversal + RCE",9.8,(2,4,49),(2,4,49),"apache_path_traversal"),
                    ("CVE-2021-42013","Path traversal bypass",9.8,(2,4,50),(2,4,50),"apache_path_traversal"),
                    ("CVE-2023-25690","HTTP Request Smuggling",9.8,(2,4,0),(2,4,55),None),
                    ("CVE-2024-27316","HTTP/2 CONTINUATION Flood",7.5,(2,4,0),(2,4,58),None),
                    ("CVE-2017-7679","Buffer overflow mod_mime",9.8,(2,2,0),(2,2,99),None)],
    "nginx":         [
                    ('CVE-2026-10332', 'QUIC memory corruption', 8.8, (1, 25, 0), (1, 27, 2), 'nginx_quic_probe'),("CVE-2021-23017","DNS resolver off-by-one",9.4,(0,6,18),(1,20,0),None),
                    ("CVE-2022-41741","mp4 module buffer overread",7.0,(1,1,3),(1,23,1),"nginx_mp4_module"),
                    ("CVE-2022-41742","mp4 module memory disclosure",7.0,(1,1,3),(1,23,1),"nginx_mp4_module"),
                    ("CVE-2024-7347","ngx_http_mp4 OOB read",4.7,(1,5,13),(1,27,0),"nginx_mp4_module")],
    "iis":         [("CVE-2017-7269","WebDAV ScStoragePathFromUrl RCE",9.8,(6,0,0),(6,0,99),"iis_webdav"),
                    ("CVE-2021-31166","HTTP Protocol Stack RCE",9.8,(10,0,0),(10,0,99),"iis_http_sys"),
                    ("CVE-2022-21907","HTTP.sys RCE",9.8,(10,0,0),(10,0,99),"iis_http_sys")],
    "tomcat":         [
                    ('CVE-2026-4455', 'RCE via HTTP/2 Stream Corruption', 9.8, (9, 0, 0), (11, 0, 2), None),("CVE-2020-1938","AJP Ghostcat LFI/RCE",9.8,(7,0,0),(9,0,30),"tomcat_ajp"),
                    ("CVE-2019-0232","CGI RCE Windows",8.1,(7,0,0),(9,0,17),None),
                    ("CVE-2024-21733","Information Disclosure",5.3,(8,5,0),(10,1,99),None)],
    "jquery":      [("CVE-2020-11022","XSS via HTML parsing",6.1,(1,2,0),(3,4,99),None),
                    ("CVE-2020-11023","XSS via HTML manipulation",6.1,(1,2,0),(3,4,99),None),
                    ("CVE-2019-11358","Prototype pollution",6.1,(1,0,0),(3,3,99),None),
                    ("CVE-2015-9251","XSS cross-domain AJAX",6.1,(1,0,0),(2,99,99),None),
                    ("CVE-2012-6708","XSS in selector",6.1,(1,0,0),(1,99,99),None)],
    "bootstrap":   [("CVE-2019-8331","XSS in tooltip/popover",6.1,(3,0,0),(4,3,0),None),
                    ("CVE-2024-6484","XSS in carousel",6.1,(4,0,0),(4,6,2),None),
                    ("CVE-2018-14042","XSS data-template",6.1,(3,0,0),(3,4,0),None)],
    "wordpress":         [
                    ('CVE-2026-1234', 'Critical RCE in Core via Media Upload', 9.8, (6, 0, 0), (6, 7, 1), None),
                    ('CVE-2025-5566', 'Authentication Bypass in REST API', 9.1, (5, 0, 0), (6, 6, 2), None),("CVE-2022-21661","SQL Injection WP_Query",9.8,(3,7,0),(5,8,2),None),
                    ("CVE-2024-31210","Admin code execution",7.2,(6,0,0),(6,4,3),None),
                    ("CVE-2023-2745","Directory traversal",5.4,(5,0,0),(6,2,0),None)],
    "drupal":      [("CVE-2018-7600","Drupalgeddon 2 RCE",9.8,(7,0,0),(8,5,0),None),
                    ("CVE-2019-6340","REST RCE",8.1,(8,0,0),(8,6,9),None)],
    "laravel":         [
                    ('CVE-2026-8877', 'RCE via Serialized Cookie Injection', 9.8, (9, 0, 0), (11, 5, 2), 'laravel_cookie_probe'),("CVE-2021-3129","Ignition RCE",9.8,(5,0,0),(8,4,2),"laravel_ignition"),
                    ("CVE-2018-15133","APP_KEY Deserialization RCE",8.1,(5,0,0),(5,6,99),None)],
    "spring":         [
                    ('CVE-2026-2211', 'RCE in Spring Framework via SpEL', 9.8, (6, 0, 0), (6, 2, 1), None),("CVE-2022-22965","Spring4Shell RCE",9.8,(5,0,0),(5,3,17),"spring4shell"),
                    ("CVE-2022-22963","Cloud Function SpEL RCE",9.8,(3,0,0),(3,2,2),"spring_cloud_function"),
                    ("CVE-2022-22947","Cloud Gateway RCE",10.0,(3,0,0),(3,1,0),None)],
    "next.js":         [
                    ('CVE-2026-1502', 'Cache Poisoning / DoS', 7.5, (13, 0, 0), (15, 0, 1), None),("CVE-2025-29927","Auth bypass x-middleware-subrequest",9.1,(11,0,0),(14,2,14),"nextjs_middleware"),
                    ("CVE-2024-34350","Server Action redirect SSRF",7.5,(13,0,0),(14,1,0),None),
                    ("CVE-2024-34351","Host header SSRF",7.5,(13,0,0),(14,1,0),None)],
    "express":     [("CVE-2024-29041","Open redirect response.redirect()",6.1,(3,0,0),(4,18,99),None)],
    "grafana":     [("CVE-2021-43798","Directory traversal LFI",7.5,(8,0,0),(8,3,0),"grafana_lfi"),
                    ("CVE-2022-31107","OAuth takeover",7.1,(5,0,0),(9,0,2),None)],
    "jenkins":         [
                    ('CVE-2026-3344', 'RCE via Groovy Script Sandbox Escape', 9.8, (2, 0, 0), (2, 480, 0), None),("CVE-2024-23897","Arbitrary File Read",9.8,(1,0,0),(2,441,99),"jenkins_file_read"),
                    ("CVE-2019-1003000","Script Security sandbox bypass",9.8,(1,0,0),(2,153,99),None)],
    "gitlab":      [("CVE-2021-22205","RCE via ExifTool",10.0,(11,9,0),(13,10,2),None),
                    ("CVE-2023-7028","Account takeover password reset",10.0,(16,1,0),(16,7,1),None)],
    "confluence":  [("CVE-2022-26134","OGNL Injection RCE",9.8,(1,3,0),(7,18,0),"confluence_ognl"),
                    ("CVE-2023-22515","Privilege escalation",10.0,(8,0,0),(8,5,1),None),
                    ("CVE-2023-22518","Authentication bypass",9.8,(1,0,0),(8,5,3),None)],
    "jira":        [("CVE-2019-11581","SSTI",9.8,(4,4,0),(8,2,99),None),
                    ("CVE-2022-0540","Auth bypass Seraph",9.8,(8,13,0),(8,22,3),None)],
    "elasticsearch":[("CVE-2015-1427","Groovy sandbox bypass RCE",9.8,(1,3,0),(1,4,2),None),
                      ("CVE-2014-3120","Script execution RCE",9.8,(0,90,0),(1,1,99),None)],
    "redis":       [("CVE-2022-0543","Lua sandbox escape RCE",10.0,(2,6,0),(6,2,6),None)],
    "log4j":       [("CVE-2021-44228","Log4Shell JNDI RCE",10.0,(2,0,0),(2,14,1),"log4shell"),
                    ("CVE-2021-45046","Log4Shell bypass RCE",9.0,(2,0,0),(2,16,0),None)],
    "struts":      [("CVE-2017-5638","Content-Type RCE",10.0,(2,3,5),(2,5,10),None),
                    ("CVE-2018-11776","Namespace RCE",9.8,(2,3,0),(2,5,16),None)],
    "varnish":     [("CVE-2021-36740","HTTP/2 Request Smuggling",6.5,(6,0,0),(6,6,0),None)],
    "slider revolution":[("CVE-2014-9734","Arbitrary file upload + LFI",10.0,(1,0,0),(4,2,0),None)],
    "prettyphoto": [("CVE-2013-3520","Reflected XSS",4.3,(1,0,0),(3,1,6),None)],
    "moment.js":   [("CVE-2022-24785","Path traversal",7.5,(2,0,0),(2,29,1),None),
                    ("CVE-2017-18214","ReDoS",7.5,(2,0,0),(2,19,2),None)],
    "angular":     [("CVE-2020-7676","XSS via $sanitize",5.4,(1,0,0),(1,7,99),None)],
    "vue":         [("CVE-2024-6783","XSS via v-bind",6.1,(2,0,0),(2,7,16),None)],
    "react":       [("CVE-2018-6341","Server-side XSS",7.1,(0,5,0),(16,0,0),None)],
    "mongodb":     [("CVE-2022-24272","Account takeover",6.5,(4,0,0),(5,0,14),None)],
}

def _parse_ver(ver_str):
    parts = re.findall(r"\d+", str(ver_str))
    if not parts: return None
    t = []
    for p in parts[:3]:
        try: t.append(int(p))
        except ValueError: t.append(0)
    while len(t) < 3: t.append(0)
    return tuple(t)

def _ver_in_range(detected_ver, min_ver, max_ver):
    parsed = _parse_ver(detected_ver)
    if not parsed: return False
    return min_ver <= parsed <= max_ver

CVE_PREREQ_PROBES = {
    "laravel_cookie_probe": {
        "method": "GET",
        "path": "/",
        "extra_headers": {"Cookie": "XSRF-TOKEN=payload"},
        "check_status": [500],
        "check_body": ["ErrorException", "unserialize"],
        "desc": "Laravel cookie deserialization error probe",
    },
    "iis_webdav": {
        "method": "OPTIONS",
        "path": "/",
        "check_header": "Allow",
        "check_contains": ["PROPFIND"],
        "desc": "WebDAV OPTIONS -> PROPFIND in Allow",
    },
    "iis_http_sys": {
        "method": "GET",
        "path": "/",
        "extra_headers": {"Accept-Encoding": "identity"},
        "check_header": "Server",
        "check_contains": ["Microsoft-IIS"],
        "desc": "HTTP.sys IIS fingerprint",
    },
    "apache_path_traversal": {
        "method": "GET",
        "path": "/cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd",
        "check_body": ["root:x:0:0", "root:*:0:0"],
        "desc": "Path traversal /cgi-bin/../../etc/passwd",
    },
    "spring4shell": {
        "method": "POST",
        "path": "/",
        "extra_headers": {"Content-Type": "application/x-www-form-urlencoded"},
        "data": "class.module.classLoader.DefaultAssertionStatus=nonsense",
        "check_status": [400],
        "check_body_absent": ["Whitelabel Error"],
        "desc": "Spring4Shell classLoader probe",
    },
    "spring_cloud_function": {
        "method": "POST",
        "path": "/functionRouter",
        "extra_headers": {"spring.cloud.function.routing-expression": "1"},
        "check_status": [500],
        "desc": "Cloud Function SpEL routing-expression",
    },
    "tomcat_ajp": {
        "method": "GET",
        "path": "/",
        "check_header": "Server",
        "check_contains": ["Tomcat", "Apache-Coyote"],
        "desc": "AJP Ghostcat - Tomcat server confirmed",
    },
    "grafana_lfi": {
        "method": "GET",
        "path": "/public/plugins/alertlist/../../../../../etc/passwd",
        "check_body": ["root:x:0:0", "root:*:0:0"],
        "desc": "Grafana LFI via plugin path",
    },
    "jenkins_file_read": {
        "method": "GET",
        "path": "/cli?remoting=false",
        "check_status": [200, 403],
        "check_body": ["Jenkins CLI", "hudson.cli"],
        "desc": "Jenkins CLI endpoint accessible",
    },
    "confluence_ognl": {
        "method": "GET",
        "path": "/%24%7B233*233%7D/",
        "check_body": ["54289"],
        "desc": "Confluence OGNL math expression",
    },
    "nextjs_middleware": {
        "method": "GET",
        "path": "/",
        "extra_headers": {"x-middleware-subrequest": "middleware:middleware:middleware"},
        "check_status": [200],
        "desc": "Next.js x-middleware-subrequest bypass",
    },
    "log4shell": {
        "method": "GET",
        "path": "/",
        "extra_headers": {"X-Api-Version": "${jndi:ldap://127.0.0.1/test}"},
        "check_status": [200, 400, 500],
        "desc": "Log4Shell JNDI payload in header (passive)",
    },
    "laravel_ignition": {
        "method": "GET",
        "path": "/_ignition/health-check",
        "check_status": [200],
        "check_body": ["can_execute_commands"],
        "desc": "Laravel Ignition health-check endpoint",
    },
    "nginx_quic_probe": {
        "method": "GET",
        "path": "/",
        "extra_headers": {"Alt-Svc": 'h3=":443"'},
        "check_header": "Alt-Svc",
        "check_contains": ["h3"],
        "desc": "nginx QUIC support detected via Alt-Svc",
    },
    "nginx_mp4_module": {
        "method": "GET",
        "path": "/test.mp4?start=9999999999",
        "check_status": [200, 206, 500],
        "desc": "nginx mp4 module probe",
    },
}

async def _run_prereq_probe(session, host_url, probe_id):
    probe = CVE_PREREQ_PROBES.get(probe_id)
    if not probe: return False, "No probe defined"
    
    url = host_url.rstrip("/") + probe["path"]
    method = probe.get("method", "GET")
    extra = probe.get("extra_headers", {})
    data = probe.get("data")
    
    try:
        if method == "OPTIONS":
            async with session.options(url, headers=extra, timeout=aiohttp.ClientTimeout(total=8), ssl=False) as resp:
                code = resp.status
                hdrs = {k: v for k, v in resp.headers.items()}
                body = await resp.text(errors="ignore")
        elif method == "POST":
            async with session.post(url, headers=extra, data=data, timeout=aiohttp.ClientTimeout(total=8), ssl=False) as resp:
                code = resp.status
                hdrs = {k: v for k, v in resp.headers.items()}
                body = (await resp.text(errors="ignore"))[:3000]
        else:
            code, body, hdrs, _ = await http_probe(session, url, timeout=8, extra_headers=extra)
    except Exception as e:
        return False, f"Probe error: {e}"
    
    if "check_status" in probe:
        if code not in probe["check_status"]:
            return False, f"Status {code} not in expected {probe['check_status']}"
    
    if "check_header" in probe and "check_contains" in probe:
        hdr_val = hdrs.get(probe["check_header"], "")
        if not any(kw.lower() in hdr_val.lower() for kw in probe["check_contains"]):
            return False, f"Header '{probe['check_header']}' missing keywords"
    
    if "check_body" in probe:
        if not any(kw in body for kw in probe["check_body"]):
            return False, f"Body missing expected keywords"
    
    if "check_body_absent" in probe:
        if any(kw in body for kw in probe["check_body_absent"]):
            return False, f"Body contains unwanted keyword"
    
    return True, probe["desc"]

@ensure_async
async def run_versions(domain, tech_map, out):
    section(7,"VERSION DETECTION  +  CVE MAPPING  (Active Probing)")
    base_url=f"https://{domain}"
    info("Extracting version info from headers + body ...")
    
    detected_versions = []
    
    version_patterns=[
        (r"PHP/([0-9.]+)","PHP"),
        (r"Apache/([0-9.]+)","Apache"),
        (r"nginx/([0-9.]+)","nginx"),
        (r"IIS/([0-9.]+)","IIS"),
        (r"jQuery v?([0-9.]+)","jQuery"),
        (r"Bootstrap v?([0-9.]+)","Bootstrap"),
        (r"jQuery UI - v([0-9.]+)","jQuery UI"),
        (r"Moment\.js.*?([0-9]+\.[0-9]+\.[0-9]+)","Moment.js"),
        (r"prettyPhoto","prettyPhoto"),
        (r"Revolution Slider","Slider Revolution"),
        (r"PDFJS","PDF.js"),
        (r"Vue\.js v([0-9.]+)","Vue"),
        (r"Angular(?:JS)?/([0-9.]+)","Angular"),
        (r"react(?:-dom)?/([0-9.]+)","React"),
        (r"Next\.js v?([0-9.]+)","Next.js"),
        (r"Express/([0-9.]+)","Express"),
        (r"Grafana v([0-9.]+)","Grafana"),
        (r"Jenkins(?:\s+ver\.\s*)?([0-9.]+)?","Jenkins"),
        (r"GitLab(?:\s+(?:CE|EE))?\s+([0-9.]+)","GitLab"),
        (r"Tomcat/([0-9.]+)","Tomcat"),
        (r"WordPress\s+([0-9.]+)","WordPress"),
        (r"Drupal\s+([0-9.]+)","Drupal"),
        (r"Laravel\s*v?([0-9.]+)?","Laravel"),
        (r"X-Powered-By:\s*Struts","Struts"),
        (r"Varnish/([0-9.]+)","Varnish"),
        (r"log4j","Log4j"),
    ]
    
    def _add_ver(tech, ver, host):
        if not any(d["tech"]==tech and d["host"]==host for d in detected_versions):
            detected_versions.append({"tech": tech, "version": ver, "host": host})
    
    def _extract_from_headers(hdrs, host_url):
        server_hdr = hdrs.get("Server", "")
        if server_hdr:
            m = re.search(r"(Apache|nginx|IIS|Tomcat|LiteSpeed|Caddy)[/\s]([0-9.]+)", server_hdr, re.I)
            if m:
                _add_ver(m.group(1), m.group(2), host_url)
            elif re.search(r"(nginx|IIS|Apache|Tomcat|LiteSpeed)", server_hdr, re.I):
                m2 = re.search(r"(nginx|IIS|Apache|Tomcat|LiteSpeed)", server_hdr, re.I)
                _add_ver(m2.group(1), server_hdr.strip(), host_url)
        php_hdr = hdrs.get("X-Powered-By", "")
        if php_hdr:
            m = re.search(r"PHP/([0-9.]+)", php_hdr, re.I)
            if m: _add_ver("PHP", m.group(1), host_url)
            if "express" in php_hdr.lower(): _add_ver("Express", php_hdr.strip(), host_url)
            if "next.js" in php_hdr.lower(): _add_ver("Next.js", php_hdr.strip(), host_url)
            if "asp.net" in php_hdr.lower(): _add_ver("ASP.NET", php_hdr.strip(), host_url)
        asp_hdr = hdrs.get("X-AspNet-Version", "")
        if asp_hdr: _add_ver("ASP.NET", asp_hdr.strip(), host_url)
        asp_mvc = hdrs.get("X-AspNetMvc-Version", "")
        if asp_mvc: _add_ver("ASP.NET MVC", asp_mvc.strip(), host_url)
    
    async with aiohttp.ClientSession() as session:
        try:
            code, body, hdrs, ms = await http_probe(session, base_url+"/", timeout=10)
        except Exception:
            code, body, hdrs, ms = 0, "", {}, 0
        
        _extract_from_headers(hdrs, base_url)
        
        combined_body = body or ""
        js_urls_to_check=[
            "/assets/js/jquery.min.js","/js/jquery.js",
            "/wp-includes/js/jquery/jquery.min.js",
            "/assets/plugins/revolution/js/jquery.themepunch.revolution.min.js",
            "/_next/static/chunks/main.js",
            "/static/js/main.js",
            "/static/js/bundle.js",
            "/assets/vendor.js",
        ]
        
        tasks = [http_probe(session, base_url+js_path, timeout=5) for js_path in js_urls_to_check]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in results:
            if isinstance(res, Exception): continue
            c2, b2, h2, _ = res
            if c2 == 200 and "text/html" not in h2.get("Content-Type", ""):
                combined_body += b2[:5000]

        meta_endpoints = ["/wp-json/wp/v2/","/api/v1/metadata","/_next/data/","/api/info"]
        for ep in meta_endpoints:
            try:
                c3, b3, h3, _ = await http_probe(session, base_url+ep, timeout=5)
                if c3 == 200: combined_body += b3[:3000]
            except Exception:
                pass
                
    for pat, name in version_patterns:
        m = re.search(pat, combined_body, re.I)
        if m:
            ver = m.group(1) if m.lastindex else "detected"
            _add_ver(name, ver, base_url)
            
    for host, techs in tech_map.items():
        host_url = f"https://{host}" if not host.startswith("http") else host
        for t in techs:
            m = re.match(r"(PHP|Apache|nginx|jQuery|Bootstrap|WordPress|Drupal|Next\.js|Express|Tomcat|IIS|Grafana|Jenkins|GitLab|Varnish|LiteSpeed|Caddy)[/\s]?([0-9.]+)?", t, re.I)
            if m and m.group(2): _add_ver(m.group(1), m.group(2), host_url)
            elif m: _add_ver(m.group(1), t.strip(), host_url)
            tl = t.lower()
            for tech_key in ("spring","laravel","django","flask","struts","log4j","confluence","jira","elasticsearch","redis","mongodb"):
                if tech_key in tl:
                    _add_ver(tech_key.title(), t.strip(), host_url)
            
    if not detected_versions:
        info("No versions detected from headers/body")
    else:
        info(f"Detected versions ({len(detected_versions)}):")
        for d in detected_versions:
            host_short = d['host'].replace('https://','').replace('http://','')[:35]
            print(GRY+"\u2502    "+RESET+CYN+f"{d['tech']:<16}"+RESET+WHT+f"{d['version']:<18}"+RESET+GRY+DIM+f"  {host_short}"+RESET)
            
    print(GRY+"\u2502"+RESET)
    info("Mapping to known CVEs (version pinning + active probing) ...")
    print(GRY+"\u2502"+RESET)
    cve_findings=[]
    seen_cves=set()
    probes_run = 0
    probes_confirmed = 0
    version_skipped = 0
    
    async with aiohttp.ClientSession() as session:
        for det in detected_versions:
            tech_name = det["tech"]
            ver = det["version"]
            host_url = det["host"]
            tech_lower = tech_name.lower()
            
            cve_list = KNOWN_CVE_MAP.get(tech_lower)
            if not cve_list:
                for map_key in KNOWN_CVE_MAP:
                    if map_key in tech_lower or tech_lower.startswith(map_key.split()[0]):
                        cve_list = KNOWN_CVE_MAP[map_key]
                        break
            if not cve_list:
                continue
                
            has_exact_ver = _parse_ver(ver) is not None
            
            for cve_entry in cve_list:
                cve_id, desc, score, min_v, max_v, prereq_id = cve_entry
                dedup_key = f"{cve_id}:{host_url}"
                if dedup_key in seen_cves: continue
                
                status = None
                probe_result = None
                
                if has_exact_ver:
                    if _ver_in_range(ver, min_v, max_v):
                        if prereq_id:
                            probes_run += 1
                            confirmed, probe_detail = await _run_prereq_probe(session, host_url, prereq_id)
                            if confirmed:
                                status = "CONFIRMED"
                                probe_result = probe_detail
                                probes_confirmed += 1
                            else:
                                status = "LIKELY"
                                probe_result = f"Version in range, probe negative: {probe_detail}"
                        else:
                            status = "LIKELY"
                    else:
                        continue
                else:
                    if prereq_id:
                        probes_run += 1
                        confirmed, probe_detail = await _run_prereq_probe(session, host_url, prereq_id)
                        if confirmed:
                            status = "CONFIRMED"
                            probe_result = probe_detail
                            probes_confirmed += 1
                        else:
                            version_skipped += 1
                            continue
                    else:
                        version_skipped += 1
                        continue
                
                seen_cves.add(dedup_key)
                
                if status == "CONFIRMED":
                    col = RED+BOLD
                    badge = RED+BOLD+"[CONFIRMED]"+RESET
                else:
                    col = ORG+BOLD if score >= 7 else YLW
                    badge = YLW+"[LIKELY]"+RESET
                
                host_short = host_url.replace('https://','').replace('http://','')[:40]
                print(GRY+"\u2502  "+RESET+col+f"[{cve_id}]"+RESET+"  "+badge+
                      WHT+f"  {tech_name} {ver}"+RESET+
                      GRY+DIM+f"  \u2192  {host_short}"+RESET)
                print(GRY+"\u2502       "+RESET+GRY+f"CVSS:{score}  {desc}"+RESET)
                if probe_result:
                    print(GRY+"\u2502       "+RESET+GRN+DIM+f"Probe: {probe_result}"+RESET)
                    
                cve_findings.append({
                    "tech":tech_name,"version":ver,"host":host_url,
                    "cve":cve_id,"desc":desc,"cvss":score,
                    "status":status,"probe":probe_result,
                })
                                                  
    if not cve_findings:
        ok("No CVEs confirmed \u2014 versions may not be detectable")
        
    print(GRY+"\u2502"+RESET)
    if probes_run:
        info(f"Active probes: {probes_run} sent, {probes_confirmed} confirmed")
    if version_skipped:
        info(f"Skipped {version_skipped} CVEs (version hidden, no probe)")
    versions_dict = {d["tech"]: d["version"] for d in detected_versions}
    save_json(f"{out}/cve_mapping.json",{"versions":versions_dict,"cves":cve_findings})
    confirmed_count = len([c for c in cve_findings if c["status"]=="CONFIRMED"])
    likely_count = len([c for c in cve_findings if c["status"]=="LIKELY"])
    ok(f"CVEs: {BOLD}{confirmed_count}{RESET} CONFIRMED  {BOLD}{likely_count}{RESET} LIKELY")
    _end()
    return cve_findings

version_cve_map = run_versions
