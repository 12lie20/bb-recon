import re
import asyncio
import aiohttp
import logging
import json
logger = logging.getLogger("bb-recon")

from core.ui import *
from core.utils import *
from core.http import http_probe

CLOUD_BUCKET_PATTERNS = [
    (re.compile(r"([a-z0-9][a-z0-9\-_.]{1,61}[a-z0-9])\.s3[.\-][a-z0-9\-]+\.amazonaws\.com"), "AWS S3"),
    (re.compile(r"s3[.\-][a-z0-9\-]+\.amazonaws\.com/([a-z0-9][a-z0-9\-_.]{1,61}[a-z0-9])"), "AWS S3"),
    (re.compile(r"([a-z0-9][a-z0-9\-_.]{1,61}[a-z0-9])\.s3\.amazonaws\.com"), "AWS S3"),
    (re.compile(r"storage\.googleapis\.com/([a-z0-9][a-z0-9\-_.]{1,61}[a-z0-9])"), "GCS"),
    (re.compile(r"([a-z0-9][a-z0-9\-_.]{1,61}[a-z0-9])\.storage\.googleapis\.com"), "GCS"),
    (re.compile(r"([a-z0-9]+)\.blob\.core\.windows\.net"), "Azure Blob"),
    (re.compile(r"([a-z0-9][a-z0-9\-_.]{1,61}[a-z0-9])\.[a-z0-9\-]+\.digitaloceanspaces\.com"), "DigitalOcean Spaces"),
    (re.compile(r"([a-z0-9][a-z0-9\-_.]{1,61}[a-z0-9])\.r2\.cloudflarestorage\.com"), "Cloudflare R2"),
    (re.compile(r"([a-z0-9][a-z0-9\-_.]{1,61}[a-z0-9])\.oss[.\-][a-z0-9\-]+\.aliyuncs\.com"), "Alibaba OSS"),
    (re.compile(r"([a-z0-9][a-z0-9\-_.]{1,61}[a-z0-9])\.storage\.yandexcloud\.net"), "Yandex Cloud"),
    (re.compile(r"([a-z0-9][a-z0-9\-_.]{1,61}[a-z0-9])\.backblazeb2\.com"), "Backblaze B2"),
    (re.compile(r"([a-z0-9][a-z0-9\-_.]{1,61}[a-z0-9])\.wasabisys\.com"), "Wasabi"),
]

S3_CNAME_SUFFIXES = [
    ".s3.amazonaws.com",
    ".s3-us-east-1.amazonaws.com",
    ".s3-us-west-1.amazonaws.com",
    ".s3-us-west-2.amazonaws.com",
    ".s3-eu-west-1.amazonaws.com",
    ".s3-ap-southeast-1.amazonaws.com",
    ".s3.us-east-1.amazonaws.com",
    ".s3.us-west-2.amazonaws.com",
    ".s3.eu-west-1.amazonaws.com",
    ".s3.eu-central-1.amazonaws.com",
    ".s3.ap-northeast-1.amazonaws.com",
    ".storage.googleapis.com",
    ".blob.core.windows.net",
]

FIREBASE_RULES_TESTS = [
    "/.json",
    "/users.json",
    "/data.json",
    "/admin.json",
    "/config.json",
]

async def _extract_buckets_from_source(session, live_lines, urls):
    extracted = {}
    
    combined_text = " ".join(urls[:500])
    
    live_hosts = set()
    for line in live_lines[:20]:
        m = re.match(r"(https?://[^\s\[/]+)", line)
        if m: live_hosts.add(m.group(1))
    
    sem = asyncio.Semaphore(10)
    async def fetch_source(base_url):
        async with sem:
            try:
                code, body, _, _ = await http_probe(session, base_url + "/", timeout=8)
                if code and body: return body[:50000]
            except Exception:
                pass
            return ""
    
    fetch_tasks = [fetch_source(h) for h in sorted(live_hosts)[:15]]
    fetch_results = await asyncio.gather(*fetch_tasks, return_exceptions=True)
    for res in fetch_results:
        if isinstance(res, str):
            combined_text += " " + res
    
    for pat, provider in CLOUD_BUCKET_PATTERNS:
        for m in pat.finditer(combined_text):
            bucket_name = m.group(1) if m.groups() else m.group(0)
            full_url = m.group(0)
            if bucket_name not in extracted:
                extracted[bucket_name] = {
                    "provider": provider,
                    "full_ref": full_url,
                    "source": "html/js",
                }
    
    return extracted

async def _extract_buckets_from_dns(live_lines):
    extracted = {}
    
    try:
        import dns.resolver
        has_dns = True
    except ImportError:
        has_dns = False
    
    subdomains = set()
    for line in live_lines:
        m = re.match(r"(?:https?://)?([^\s\[/:]+)", line)
        if m:
            subdomains.add(m.group(1).lower())
    
    if not has_dns:
        for sub in sorted(subdomains)[:50]:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "nslookup", "-type=CNAME", sub,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
                output = stdout.decode("utf-8", errors="ignore").lower()
                for suffix in S3_CNAME_SUFFIXES:
                    if suffix in output:
                        cname_match = re.search(r"canonical name\s*[=:]\s*(\S+)", output)
                        if cname_match:
                            cname_target = cname_match.group(1).rstrip(".")
                            bucket_name = cname_target.split(".s3")[0].split(".storage")[0].split(".blob")[0]
                            if bucket_name and len(bucket_name) >= 3:
                                provider = "AWS S3"
                                if ".storage.googleapis" in cname_target: provider = "GCS"
                                elif ".blob.core.windows" in cname_target: provider = "Azure Blob"
                                extracted[bucket_name] = {
                                    "provider": provider,
                                    "full_ref": cname_target,
                                    "source": f"CNAME:{sub}",
                                    "subdomain": sub,
                                }
            except Exception:
                pass
        return extracted
    
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 5
    
    for sub in sorted(subdomains)[:50]:
        try:
            answers = resolver.resolve(sub, "CNAME")
            for rdata in answers:
                cname_target = str(rdata.target).rstrip(".").lower()
                for suffix in S3_CNAME_SUFFIXES:
                    if cname_target.endswith(suffix) or suffix.lstrip(".") in cname_target:
                        bucket_name = cname_target.split(".s3")[0].split(".storage")[0].split(".blob")[0]
                        if bucket_name and len(bucket_name) >= 3:
                            provider = "AWS S3"
                            if ".storage.googleapis" in cname_target: provider = "GCS"
                            elif ".blob.core.windows" in cname_target: provider = "Azure Blob"
                            extracted[bucket_name] = {
                                "provider": provider,
                                "full_ref": cname_target,
                                "source": f"CNAME:{sub}",
                                "subdomain": sub,
                            }
                            break
        except Exception:
            pass
    
    return extracted

async def _verify_bucket(session, bucket_name, info_dict, findings):
    provider = info_dict["provider"]
    source = info_dict["source"]
    full_ref = info_dict["full_ref"]
    
    test_urls = []
    if provider == "AWS S3":
        test_urls = [
            f"https://{bucket_name}.s3.amazonaws.com/",
            f"https://s3.amazonaws.com/{bucket_name}/",
        ]
    elif provider == "GCS":
        test_urls = [f"https://storage.googleapis.com/{bucket_name}/"]
    elif provider == "Azure Blob":
        test_urls = [f"https://{bucket_name}.blob.core.windows.net/?comp=list&restype=container"]
    elif provider == "DigitalOcean Spaces":
        test_urls = [f"https://{bucket_name}.nyc3.digitaloceanspaces.com/"]
    elif provider == "Cloudflare R2":
        test_urls = [f"https://{bucket_name}.r2.cloudflarestorage.com/"]
    elif provider == "Wasabi":
        test_urls = [f"https://{bucket_name}.s3.wasabisys.com/"]
    
    for test_url in test_urls:
        try:
            code, body, hdrs, _ = await http_probe(session, test_url, timeout=8)
        except Exception:
            continue
        
        if code == 200:
            if "<ListBucketResult" in body or "<Contents>" in body:
                entries = len(re.findall(r"<Key>", body))
                vuln(f"OPEN {provider} BUCKET (LIST): {bucket_name}")
                print(GRY+"\u2502    "+RESET+RED+f"Listing {entries} objects publicly"+RESET)
                print(GRY+"\u2502    "+RESET+GRY+DIM+f"Evidence: {source} \u2192 {full_ref}"+RESET)
                findings.append({
                    "type": f"OpenBucket-{provider}", "bucket": bucket_name,
                    "url": test_url, "severity": "CRITICAL",
                    "objects_listed": entries, "evidence": source,
                })
                return
            elif "<EnumerationResults" in body:
                vuln(f"OPEN {provider} CONTAINER (LIST): {bucket_name}")
                print(GRY+"\u2502    "+RESET+GRY+DIM+f"Evidence: {source} \u2192 {full_ref}"+RESET)
                findings.append({
                    "type": f"OpenBucket-{provider}", "bucket": bucket_name,
                    "url": test_url, "severity": "CRITICAL", "evidence": source,
                })
                return
            elif len(body) > 100:
                found(f"{provider} bucket accessible (200): {bucket_name}")
                print(GRY+"\u2502    "+RESET+GRY+DIM+f"Evidence: {source} \u2192 {full_ref}"+RESET)
                findings.append({
                    "type": f"AccessibleBucket-{provider}", "bucket": bucket_name,
                    "url": test_url, "severity": "HIGH", "evidence": source,
                })
                return
        
        elif code == 404 or (body and "NoSuchBucket" in body):
            subdomain = info_dict.get("subdomain", "")
            if "CNAME" in source:
                vuln(f"CONFIRMED TAKEOVER \u2014 {provider}: {bucket_name}")
                print(GRY+"\u2502    "+RESET+RED+BOLD+f"Subdomain {subdomain} \u2192 CNAME {full_ref} \u2192 NoSuchBucket"+RESET)
                print(GRY+"\u2502    "+RESET+RED+f"This bucket can be claimed for subdomain takeover!"+RESET)
                findings.append({
                    "type": f"BucketTakeover-{provider}", "bucket": bucket_name,
                    "url": test_url, "severity": "CRITICAL",
                    "status": "CONFIRMED",
                    "evidence": source,
                    "subdomain": subdomain,
                    "note": f"CNAME points to non-existent bucket - claimable",
                })
            else:
                found(f"Dangling reference \u2014 {provider}: {bucket_name}")
                print(GRY+"\u2502    "+RESET+ORG+f"Source code references non-existent bucket"+RESET)
                print(GRY+"\u2502    "+RESET+GRY+DIM+f"Ref: {full_ref}"+RESET)
                findings.append({
                    "type": f"DanglingBucketRef-{provider}", "bucket": bucket_name,
                    "url": test_url, "severity": "HIGH",
                    "status": "LIKELY",
                    "evidence": source,
                    "note": f"Referenced in {source} but bucket does not exist",
                })
            return
        
        elif code == 403:
            pass

async def run_cloud_scan(domain, urls, live_lines, out):
    section(11, "CLOUD MISCONFIGURATION SCAN (Evidence-Based)")
    findings = []
    
    async with aiohttp.ClientSession() as session:
        info("Phase 1: Extracting bucket references from HTML/JS source ...")
        source_buckets = await _extract_buckets_from_source(session, live_lines, urls)
        if source_buckets:
            for name, info_d in source_buckets.items():
                print(GRY+"\u2502    "+RESET+CYN+f"{info_d['provider']:<12}"+RESET+WHT+f"{name:<30}"+RESET+GRY+DIM+f"  [{info_d['source']}]"+RESET)
        ok(f"Bucket references from source: {BOLD}{len(source_buckets)}{RESET}")
        
        print(GRY+"\u2502"+RESET)
        info("Phase 2: Scanning DNS CNAME records for cloud storage pointers ...")
        dns_buckets = await _extract_buckets_from_dns(live_lines)
        if dns_buckets:
            for name, info_d in dns_buckets.items():
                print(GRY+"\u2502    "+RESET+CYN+f"{info_d['provider']:<12}"+RESET+WHT+f"{name:<30}"+RESET+GRY+DIM+f"  [{info_d['source']}]"+RESET)
        ok(f"Bucket references from DNS CNAME: {BOLD}{len(dns_buckets)}{RESET}")
        
        all_buckets = {}
        all_buckets.update(source_buckets)
        for k, v in dns_buckets.items():
            if k not in all_buckets:
                all_buckets[k] = v
            elif "CNAME" in v["source"]:
                all_buckets[k] = v
        
        if not all_buckets:
            print(GRY+"\u2502"+RESET)
            ok("No bucket references found \u2014 skipping bucket verification (zero guessing)")
        else:
            print(GRY+"\u2502"+RESET)
            info(f"Phase 3: Verifying {len(all_buckets)} evidence-backed buckets ...")
            sem = asyncio.Semaphore(5)
            
            async def safe_verify(name, info_d):
                async with sem:
                    try:
                        await _verify_bucket(session, name, info_d, findings)
                    except Exception as e:
                        logger.debug(f"Bucket verify failed for {name}: {e}")
            
            verify_tasks = [safe_verify(name, info_d) for name, info_d in all_buckets.items()]
            await asyncio.gather(*verify_tasks, return_exceptions=True)
        
        print(GRY+"\u2502"+RESET)
        info("Firebase RTDB open access check ...")
        
        firebase_urls = set()
        for u in urls:
            m = re.search(r"(https://[a-z0-9\-]+\.firebaseio\.com)", u, re.I)
            if m: firebase_urls.add(m.group(1))
        
        for line in live_lines:
            m = re.search(r"(https://[a-z0-9\-]+\.firebaseio\.com)", line, re.I)
            if m: firebase_urls.add(m.group(1))
        
        for fb_url in firebase_urls:
            for test_path in FIREBASE_RULES_TESTS:
                try:
                    code, body, _, _ = await http_probe(session, fb_url + test_path, timeout=6)
                    if code == 200 and body and body.strip() not in ("null", "{}", "[]", ""):
                        data = json.loads(body)
                        if data and data != {} and data != []:
                            vuln(f"FIREBASE OPEN READ: {fb_url}{test_path}")
                            key_count = len(data) if isinstance(data, (dict, list)) else 0
                            print(GRY+"\u2502    "+RESET+RED+f"Readable data: {key_count} top-level keys/items"+RESET)
                            findings.append({"type": "FirebaseOpenRead", "url": fb_url + test_path,
                                           "severity": "CRITICAL", "keys": key_count})
                            break
                except Exception:
                    pass
        
        if not firebase_urls:
            ok("No Firebase references found in source")
        
        print(GRY+"\u2502"+RESET)
        info("GraphQL introspection check ...")
        
        graphql_endpoints = [
            "/graphql", "/graphql/", "/api/graphql", "/graphiql",
            "/v1/graphql", "/v2/graphql", "/query", "/gql",
            "/api/v1/graphql", "/api/v2/graphql",
        ]
        
        introspection_query = '{"query":"query{__schema{types{name fields{name type{name}}}}}"}'
        
        for host_line in live_lines[:10]:
            m = re.match(r"(https?://[^\s\[/]+)", host_line)
            if not m: continue
            base = m.group(1)
            
            for ep in graphql_endpoints:
                try:
                    code, body, hdrs, _ = await http_probe(
                        session, base + ep, timeout=6, method="POST",
                        data=introspection_query,
                        extra_headers={"Content-Type": "application/json"}
                    )
                    if code == 200 and "__schema" in body:
                        vuln(f"GRAPHQL INTROSPECTION ENABLED: {base}{ep}")
                        try:
                            gql_data = json.loads(body)
                            types_count = len(gql_data.get("data", {}).get("__schema", {}).get("types", []))
                            print(GRY+"\u2502    "+RESET+RED+f"Schema exposed: {types_count} types"+RESET)
                            
                            mutation_types = [t for t in gql_data.get("data", {}).get("__schema", {}).get("types", [])
                                            if t.get("name", "").startswith("Mutation") or 
                                               any(f.get("name","") in ("createUser","deleteUser","updatePassword","login","register","resetPassword","addAdmin")
                                                   for f in (t.get("fields") or []))]
                            if mutation_types:
                                vuln(f"SENSITIVE MUTATIONS DETECTED")
                                for mt in mutation_types:
                                    for f in (mt.get("fields") or []):
                                        print(GRY+"\u2502      "+RESET+RED+f"\u2192 {f.get('name','')}" +RESET)
                        except Exception:
                            pass
                        findings.append({"type": "GraphQLIntrospection", "url": base + ep,
                                       "severity": "HIGH"})
                        break
                    
                    code2, body2, _, _ = await http_probe(session, base + ep, timeout=6)
                    if code2 == 200 and ("graphiql" in body2.lower() or "graphql" in body2.lower() or "playground" in body2.lower()):
                        found(f"GraphQL IDE/Playground: {base}{ep}")
                        findings.append({"type": "GraphQLIDE", "url": base + ep, "severity": "MEDIUM"})
                        break
                except Exception:
                    pass

        print(GRY+"\u2502"+RESET)
        info("Exposed metadata endpoint check ...")
        
        metadata_endpoints = [
            ("/.well-known/openid-configuration", "OpenID Config", "OIDC configuration exposed"),
            ("/server-info", "Server Info", "Server info page"),
            ("/actuator", "Spring Actuator", "Spring Boot Actuator"),
            ("/actuator/env", "Spring Actuator Env", "Environment variables exposed"),
            ("/actuator/heapdump", "Spring Heapdump", "JVM heap dump accessible"),
            ("/actuator/health", "Spring Health", "Health endpoint"),
            ("/actuator/configprops", "Spring Config Props", "Configuration properties"),
            ("/actuator/mappings", "Spring Mappings", "URL mappings"),
            ("/manage/health", "Spring Manage Health", "Management health endpoint"),
            ("/__debug__/", "Debug Page", "Debug mode active"),
            ("/_debug/", "Debug Page", "Debug mode active"),
            ("/debug/vars", "Go Debug Vars", "Go runtime variables"),
            ("/debug/pprof/", "Go PProf", "Go profiling endpoint"),
            ("/elmah.axd", "ELMAH", "ASP.NET error log"),
            ("/trace.axd", "ASP.NET Trace", "Request trace viewer"),
            ("/info", "Info Endpoint", "Application info"),
            ("/metrics", "Metrics", "Application metrics"),
            ("/stats", "Stats Page", "Statistics endpoint"),
            ("/console", "Web Console", "Administrative console"),
            ("/jolokia/", "Jolokia JMX", "Java JMX exposed via HTTP"),
            ("/jmx-console/", "JMX Console", "JBoss JMX console"),
            ("/web-console/", "Web Console", "JBoss web console"),
            ("/_cat/indices", "Elasticsearch", "Elasticsearch indices listing"),
            ("/_cluster/health", "Elasticsearch", "Elasticsearch cluster health"),
        ]
        
        base_url = f"https://{domain}"
        
        async def check_meta(ep_path, ep_name, ep_desc):
            try:
                code, body, hdrs, _ = await http_probe(session, base_url + ep_path, timeout=6)
                if code == 200 and len(body) > 50:
                    ct = hdrs.get("Content-Type", "").lower()
                    if "json" in ct or "xml" in ct or body.strip()[:1] in ("{","[","<"):
                        found(f"{ep_name}: {base_url}{ep_path}")
                        print(GRY+"\u2502    "+RESET+GRY+DIM+f"{ep_desc}"+RESET)
                        sev = "CRITICAL" if any(x in ep_path for x in ("heapdump","env","configprops","jolokia","jmx")) else "HIGH"
                        findings.append({"type": f"ExposedEndpoint-{ep_name}", "url": base_url + ep_path,
                                       "severity": sev, "description": ep_desc})
            except Exception:
                pass
        
        meta_tasks = [check_meta(ep_path, ep_name, ep_desc) for ep_path, ep_name, ep_desc in metadata_endpoints]
        await asyncio.gather(*meta_tasks, return_exceptions=True)
    
    print(GRY+"\u2502"+RESET)
    save_json(f"{out}/cloud_findings.json", findings)
    confirmed = len([f for f in findings if f.get("status") == "CONFIRMED"])
    critical = len([f for f in findings if f.get("severity") in ("CRITICAL", "HIGH")])
    ok(f"Cloud findings: {BOLD}{len(findings)}{RESET}  ({BOLD}{confirmed}{RESET} confirmed, {BOLD}{critical}{RESET} critical/high)")
    _end()
    return findings
