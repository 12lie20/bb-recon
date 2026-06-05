import re
import json
import asyncio
import aiohttp
import logging
import urllib.parse
from core.ui import section, ok, vuln, found, info, warn, GRY, WHT, RESET, CYN, RED, YLW, BOLD
from core.http import http_probe
from core.utils import save_json
logger = logging.getLogger("bb-recon")

SWAGGER_PATHS = [
    "/swagger.json", "/v1/swagger.json", "/v2/swagger.json", "/v3/swagger.json",
    "/api-docs", "/api/swagger.json", "/swagger/v1/swagger.json",
    "/openapi.json", "/api/openapi.json", "/openapi/v3/api-docs",
    "/.well-known/openapi.json", "/docs/swagger.json",
    "/swagger-ui/swagger.json", "/api-docs.json",
    "/api/doc", "/api/docs", "/api/v1/docs", "/api/v2/docs",
    "/redoc", "/api/schema", "/graphql/schema",
]

BOLA_ID_PATTERNS = re.compile(r'/(\d{1,10})(?:/|$|\?)')
AUTH_HEADERS_NEEDED = ["authorization", "x-api-key", "cookie", "x-auth-token"]

async def run_api_security(target, urls, classified, out):
    section_title = "API SECURITY TESTING  (OpenAPI · BOLA · Mass Assignment · Rate Limit)"
    print()
    print(GRY+"┌─ "+RESET+WHT+BOLD+"STEP 5e"+RESET+GRY+" ─── "+RESET+CYN+BOLD+section_title+RESET)
    print(GRY+"│"+RESET)

    findings = []
    parsed = urllib.parse.urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"

    info("Searching for API documentation endpoints ...")
    specs_found = []

    async with aiohttp.ClientSession() as session:
        sem = asyncio.Semaphore(10)

        async def probe_spec(path):
            async with sem:
                test_url = base + path
                code, body, hdrs, _ = await http_probe(session, test_url, timeout=6)
                if code == 200 and body and len(body) > 50:
                    ct = hdrs.get("Content-Type", "").lower()
                    if "json" in ct or body.strip().startswith("{") or "swagger" in body.lower() or "openapi" in body.lower():
                        return (path, body)
                return None

        tasks = [probe_spec(p) for p in SWAGGER_PATHS]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if r and isinstance(r, tuple):
                specs_found.append(r)

        if specs_found:
            vuln(f"API Documentation EXPOSED: {len(specs_found)} spec(s) found")
            for path, body in specs_found:
                print(GRY+"│    "+RESET+CYN+f"{base}{path}"+RESET)
                findings.append({
                    "type": "API-SpecExposed", "url": f"{base}{path}",
                    "severity": "MEDIUM", "confidence": "CONFIRMED",
                })

                try:
                    spec = json.loads(body)
                    api_paths = spec.get("paths", {})
                    info(f"Parsing OpenAPI spec: {len(api_paths)} endpoints ...")

                    for endpoint, methods in api_paths.items():
                        for method, details in methods.items():
                            if method.lower() in ("put", "delete", "patch", "post"):
                                security = details.get("security", spec.get("security", []))
                                if not security:
                                    vuln(f"Unauthenticated {method.upper()} {endpoint}")
                                    findings.append({
                                        "type": "API-NoAuth", "url": f"{base}{endpoint}",
                                        "method": method.upper(),
                                        "severity": "HIGH", "confidence": "LIKELY",
                                        "note": "State-changing endpoint without authentication requirement",
                                    })

                            params = details.get("parameters", [])
                            for param in params:
                                if param.get("in") == "path" and "id" in param.get("name", "").lower():
                                    findings.append({
                                        "type": "API-BOLA-Candidate",
                                        "url": f"{base}{endpoint}",
                                        "param": param.get("name"),
                                        "severity": "INFO",
                                        "note": "ID-based path parameter — potential BOLA/IDOR target",
                                    })

                except json.JSONDecodeError:
                    pass
        else:
            info("No OpenAPI/Swagger specs found")

        api_urls = [u for u in urls if "/api" in u.lower() or "/v1/" in u or "/v2/" in u or "/v3/" in u]

        info(f"Testing {len(api_urls[:15])} API endpoints for authorization issues ...")
        for api_url in api_urls[:15]:
            try:
                code_auth, body_auth, _, _ = await http_probe(session, api_url, timeout=8)
                code_noauth, body_noauth, _, _ = await http_probe(
                    session, api_url, timeout=8,
                    extra_headers={"Authorization": "", "Cookie": ""}
                )

                if code_auth == 200 and code_noauth == 200:
                    if len(body_auth) > 100 and abs(len(body_auth) - len(body_noauth)) < 100:
                        found(f"API accessible without auth: {api_url}")
                        findings.append({
                            "type": "API-AuthBypass", "url": api_url,
                            "severity": "HIGH", "confidence": "LIKELY",
                        })

                id_match = BOLA_ID_PATTERNS.search(api_url)
                if id_match and code_auth == 200:
                    orig_id = int(id_match.group(1))
                    for test_id in [orig_id + 1, orig_id - 1, 1]:
                        if test_id == orig_id or test_id < 0:
                            continue
                        bola_url = api_url.replace(str(orig_id), str(test_id), 1)
                        code_b, body_b, _, _ = await http_probe(session, bola_url, timeout=8)
                        if code_b == 200 and len(body_b) > 50:
                            found(f"BOLA/IDOR: {bola_url}")
                            findings.append({
                                "type": "API-BOLA", "url": bola_url,
                                "original_url": api_url, "severity": "HIGH",
                                "confidence": "LIKELY",
                                "evidence": f"Changed ID {orig_id} → {test_id}, got 200 with data",
                            })
                            break

            except Exception as e:
                logger.debug(f"API test failed on {api_url}: {e}")

        mass_endpoints = [u for u in api_urls if any(kw in u.lower() for kw in ["user", "profile", "account", "register", "signup"])][:5]
        for ep in mass_endpoints:
            try:
                ma_payloads = [
                    {"role": "admin", "is_admin": True},
                    {"isAdmin": True, "admin": 1},
                    {"role": "superadmin", "privilege": "elevated"},
                ]
                for ma_payload in ma_payloads:
                    code_ma, body_ma, _, _ = await http_probe(
                        session, ep, timeout=8, method="POST",
                        data=json.dumps(ma_payload),
                        extra_headers={"Content-Type": "application/json"}
                    )
                    if code_ma in (200, 201) and body_ma:
                        try:
                            resp_json = json.loads(body_ma)
                            resp_str = json.dumps(resp_json).lower()
                            if "admin" in resp_str or "role" in resp_str:
                                found(f"Mass Assignment possible: {ep}")
                                findings.append({
                                    "type": "API-MassAssignment", "url": ep,
                                    "severity": "HIGH", "confidence": "POSSIBLE",
                                    "payload": json.dumps(ma_payload),
                                })
                                break
                        except json.JSONDecodeError:
                            pass
            except Exception:
                pass

        rate_limit_urls = api_urls[:3]
        for rl_url in rate_limit_urls:
            try:
                blocked = False
                for i in range(30):
                    code_rl, _, _, _ = await http_probe(session, rl_url, timeout=5)
                    if code_rl in (429, 503):
                        blocked = True
                        break
                if not blocked:
                    found(f"No rate limiting after 30 requests: {rl_url}")
                    findings.append({
                        "type": "API-NoRateLimit", "url": rl_url,
                        "severity": "LOW", "confidence": "CONFIRMED",
                    })
            except Exception:
                pass

    print(GRY+"│"+RESET)
    save_json(f"{out}/api_security_findings.json", findings)
    vuln_count = len([f for f in findings if f.get("severity") in ("HIGH", "CRITICAL")])
    if vuln_count:
        vuln(f"API Security: {vuln_count} issue(s) found!")
    else:
        ok("API Security: no critical issues")
    print(GRY+"└"+"─"*70+RESET)
    return findings
