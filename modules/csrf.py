import re
import asyncio
import aiohttp
import logging
from core.ui import section, ok, vuln, found, info, warn, GRY, WHT, RESET, CYN, RED, BOLD
from core.http import http_probe
from core.utils import save_json
logger = logging.getLogger("bb-recon")

FORM_RE = re.compile(r'<form\b[^>]*>(.*?)</form>', re.I | re.S)
INPUT_RE = re.compile(r'<input\b([^>]*)/?>', re.I)
ACTION_RE = re.compile(r'action\s*=\s*["\']([^"\']+)["\']', re.I)
METHOD_RE = re.compile(r'method\s*=\s*["\']([^"\']+)["\']', re.I)
NAME_RE = re.compile(r'name\s*=\s*["\']([^"\']+)["\']', re.I)
TYPE_RE = re.compile(r'type\s*=\s*["\']([^"\']+)["\']', re.I)
VALUE_RE = re.compile(r'value\s*=\s*["\']([^"\']*)["\']', re.I)

CSRF_TOKEN_NAMES = re.compile(
    r"(csrf|xsrf|_token|authenticity_token|__RequestVerificationToken"
    r"|csrfmiddlewaretoken|_csrf_token|anti.?forgery"
    r"|YII_CSRF_TOKEN|__VIEWSTATEGENERATOR"
    r"|nonce|security_token|form_key)", re.I
)

SAFE_STATE_CHANGE_METHODS = {"post", "put", "delete", "patch"}

async def run_csrf_detection(urls, out):
    section_title = "CSRF TOKEN ANALYSIS"
    print()
    print(GRY+"┌─ "+RESET+WHT+BOLD+"STEP 5d"+RESET+GRY+" ─── "+RESET+CYN+BOLD+section_title+RESET)
    print(GRY+"│"+RESET)

    findings = []

    form_urls = []
    for url in urls:
        lower = url.lower()
        if any(kw in lower for kw in [
            "login", "register", "signup", "password", "profile", "settings",
            "account", "edit", "update", "create", "delete", "submit", "form",
            "contact", "comment", "checkout", "payment", "transfer", "send",
        ]):
            form_urls.append(url)
    form_urls = form_urls[:30]

    if not form_urls:
        form_urls = urls[:20]

    info(f"Checking {len(form_urls)} URLs for forms without CSRF protection ...")

    sem = asyncio.Semaphore(5)
    async def check_url(session, url):
        async with sem:
            try:
                code, body, hdrs, _ = await http_probe(session, url, timeout=8)
                if code != 200 or not body:
                    return []

                url_findings = []
                forms = FORM_RE.findall(body)
                if not forms:
                    return []

                for i, form_html in enumerate(forms):
                    method_m = METHOD_RE.search(form_html)
                    method = method_m.group(1).lower() if method_m else "get"

                    if method not in SAFE_STATE_CHANGE_METHODS:
                        continue

                    action_m = ACTION_RE.search(form_html)
                    action = action_m.group(1) if action_m else url

                    inputs = INPUT_RE.findall(form_html)
                    has_csrf_token = False
                    form_fields = []

                    for inp_attrs in inputs:
                        name_m = NAME_RE.search(inp_attrs)
                        type_m = TYPE_RE.search(inp_attrs)
                        value_m = VALUE_RE.search(inp_attrs)
                        fname = name_m.group(1) if name_m else ""
                        ftype = type_m.group(1).lower() if type_m else "text"
                        fval = value_m.group(1) if value_m else ""

                        if fname and CSRF_TOKEN_NAMES.search(fname):
                            has_csrf_token = True
                            if len(fval) < 10:
                                vuln(f"CSRF TOKEN EMPTY/SHORT: {url}")
                                url_findings.append({
                                    "type": "CSRF-WeakToken", "url": url,
                                    "action": action, "method": method,
                                    "token_name": fname, "token_value": fval,
                                    "severity": "HIGH",
                                })
                        if ftype == "hidden":
                            form_fields.append(fname)

                    if not has_csrf_token:
                        samesite = "none"
                        sc = hdrs.get("Set-Cookie", "")
                        if "SameSite=Strict" in sc:
                            samesite = "strict"
                        elif "SameSite=Lax" in sc:
                            samesite = "lax"

                        if samesite == "strict":
                            severity = "LOW"
                        elif samesite == "lax" and method == "post":
                            severity = "MEDIUM"
                        else:
                            severity = "HIGH"

                        verb = method.upper()
                        vuln(f"NO CSRF TOKEN in {verb} form: {url}")
                        print(GRY+"│    "+RESET+CYN+f"action: {action}"+RESET)
                        url_findings.append({
                            "type": "CSRF-Missing", "url": url,
                            "action": action, "method": method,
                            "severity": severity, "samesite": samesite,
                            "hidden_fields": form_fields,
                        })

                return url_findings

            except Exception as e:
                logger.debug(f"CSRF check failed on {url}: {e}")
                return []

    async with aiohttp.ClientSession() as session:
        tasks = [check_url(session, url) for url in form_urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    for res in results:
        if isinstance(res, list):
            findings.extend(res)

    print(GRY+"│"+RESET)
    save_json(f"{out}/csrf_findings.json", findings)
    vuln_count = len([f for f in findings if f.get("severity") in ("HIGH", "CRITICAL")])
    if vuln_count:
        vuln(f"CSRF: {vuln_count} forms missing protection!")
    else:
        ok("CSRF: all state-changing forms appear protected")
    print(GRY+"└"+"─"*70+RESET)
    return findings
