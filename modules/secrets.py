import re
import math
import urllib.parse
import aiohttp
import asyncio
import logging
logger = logging.getLogger("bb-recon")

from core.ui import *
from core.utils import *
from core.utils import ensure_async
from core.http import http_probe

def _shannon_entropy(s):
    if not s: return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())

_AWS_FP_PATTERNS = re.compile(
    r"(?i)"
    r"(?:assets/|static/|images/|img/|fonts/|css/|dist/|build/|node_modules/|vendor/|public/|src/)"
    r"|(?:\.(?:png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|css|js|map|json|xml|html|htm|pdf|zip|tar|gz))"
    r"|(?:ABCDEFGHIJKLMNOP|abcdefghijklmnop|0123456789|1234567890)"
    r"|(?:AAAAAAA|BBBBBBB|CCCCCCC|XXXXXXX|xxxxxxx|0000000)"
    r"|(?:example|sample|dummy|test|mock|fake|placeholder|template|default)"
)

def _validate_aws_key(name, matched_value):
    val = matched_value.strip().strip("'\"").strip()
    if _AWS_FP_PATTERNS.search(val):
        return False
    if name == "AWS Access Key":
        if not re.fullmatch(r"(?:AKIA|ASIA)[0-9A-Z]{16}", val):
            return False
        if len(val) != 20:
            return False
        suffix = val[4:]
        if _shannon_entropy(suffix) < 3.5:
            return False
    elif name == "AWS Secret Key":
        clean = val.strip()
        if len(clean) != 40:
            return False
        if not re.fullmatch(r"[A-Za-z0-9/+=]{40}", clean):
            return False
        if _shannon_entropy(clean) < 4.0:
            return False
        if clean == clean[0] * 40:
            return False
    return True

JS_PATS={
    "AWS Access Key":   re.compile(r"(?<![A-Za-z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Za-z0-9])"),
    "AWS Secret Key":   re.compile(r"(?i)(?:aws)?_?(?:secret)?_?(?:access)?_?(?:key)?\s*['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])['\"]?"),
    "AWS Session Token":re.compile(r"(?i)(?:aws)?_?(?:session)?_?(?:token)?\s*['\"]?\s*[:=]\s*['\"]([\w/+=]{100,})['\"]?"),
    "AWS MWS Key":      re.compile(r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),

    "Google API Key":   re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "Google OAuth":     re.compile(r"ya29\.[0-9A-Za-z\-_]+"),
    "Google Cloud Auth":re.compile(r"\"type\": \"service_account\",\s*\"project_id\":"),
    "Firebase URL":     re.compile(r"https://[a-z0-9-]+\.firebaseio\.com"),
    "Firebase Key":     re.compile(r"(?i)firebase[_-]?(?:api[_-]?)?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{30,})['\"]?"),
    "GCP OAuth Client": re.compile(r"[0-9]+-[a-z0-9_]+\.apps\.googleusercontent\.com"),

    "Azure Storage Key":re.compile(r"(?i)(?:azure|storage)[_-]?(?:account)?[_-]?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9+/=]{44,})['\"]?"),
    "Azure SAS Token":  re.compile(r"(?:sv|sig|se|sp|srt|ss)=[^&\s]{5,}&(?:sv|sig|se|sp|srt|ss)="),
    "Azure Conn String":re.compile(r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{40,}"),
    "Azure AD Client":  re.compile(r"(?i)(?:azure|aad)[_-]?client[_-]?secret['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9~_.\-]{30,})['\"]?"),

    "DigitalOcean Token":re.compile(r"(?i)do(?:_|ct_)[a-zA-Z0-9]{64}"),
    "DigitalOcean Space":re.compile(r"(?i)(?:do|digitalocean)[_-]?(?:spaces)?[_-]?(?:access)?[_-]?key['\"]?\s*[:=]\s*['\"]?([A-Z0-9]{20})['\"]?"),

    "Cloudflare API Key":re.compile(r"(?i)(?:cloudflare|cf)[_-]?(?:api)?[_-]?key['\"]?\s*[:=]\s*['\"]?([a-f0-9]{37})['\"]?"),
    "Cloudflare Token": re.compile(r"(?i)cf[_-]?(?:api)?[_-]?token['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{40})['\"]?"),

    "GitHub Token":     re.compile(r"(?i)gh[pousr]_[A-Za-z0-9_]{36,255}"),
    "GitHub OAuth":     re.compile(r"(?i)gho_[A-Za-z0-9_]{36}"),
    "GitHub Fine-Grain":re.compile(r"github_pat_[A-Za-z0-9_]{22,255}"),
    "GitLab Token":     re.compile(r"glpat-[A-Za-z0-9\-_]{20,}"),
    "GitLab Runner":    re.compile(r"GR1348941[A-Za-z0-9\-_]{20,}"),
    "Bitbucket Token":  re.compile(r"(?i)bitbucket[_-]?(?:api)?[_-]?(?:token|key|secret)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9]{10,})['\"]?"),

    "Slack Token":      re.compile(r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,}"),
    "Slack Webhook":    re.compile(r"https://hooks\.slack\.com/services/[T|B][A-Z0-9]{8,}/[B][A-Z0-9]{8,}/[A-Za-z0-9]{24,}"),
    "Discord Webhook":  re.compile(r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+"),
    "Discord Bot Token":re.compile(r"(?:N|M|O)[A-Za-z0-9]{23,}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,}"),
    "Telegram Bot":     re.compile(r"\d{8,10}:[A-Za-z0-9_\-]{35}"),

    "Stripe Standard":  re.compile(r"(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{20,}"),
    "Stripe Restricted":re.compile(r"rk_(?:live|test)_[A-Za-z0-9]{24,}"),
    "PayPal Braintree":re.compile(r"access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}"),
    "Square Token":    re.compile(r"sq0[a-z]{3}-[A-Za-z0-9_\-]{22,}"),

    "Twilio API Key":   re.compile(r"SK[a-z0-9]{32}"),
    "Twilio Account":   re.compile(r"AC[a-z0-9]{32}"),
    "Heroku API Key":   re.compile(r"(?i)heroku[_-]?(?:api[_-]?)?key['\"]?\s*[:=]\s*['\"]([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})['\"]?"),
    "Mailgun Key":      re.compile(r"key-[0-9a-zA-Z]{32}"),
    "Mailchimp Key":    re.compile(r"[0-9a-f]{32}-us\d{1,2}"),
    "SendGrid API Key": re.compile(r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}"),
    "Postmark Token":   re.compile(r"(?i)postmark[_-]?(?:api)?[_-]?(?:token|key)['\"]?\s*[:=]\s*['\"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['\"]?"),

    "OpenAI Key":       re.compile(r"sk-[a-zA-Z0-9_-]{20,}T3BlbkFJ[a-zA-Z0-9_-]{20,}"),
    "OpenAI Project":   re.compile(r"sk-proj-[a-zA-Z0-9_-]{48,}"),
    "Anthropic Key":    re.compile(r"sk-ant-[a-zA-Z0-9_-]{80,}"),
    "HuggingFace Token":re.compile(r"hf_[a-zA-Z0-9]{34}"),
    "Replicate Token":  re.compile(r"r8_[a-zA-Z0-9]{37}"),
    "Cohere API Key":   re.compile(r"(?i)cohere[_-]?(?:api)?[_-]?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9]{40})['\"]?"),

    "Supabase Key":     re.compile(r"sbp_[a-zA-Z0-9]{40}"),
    "Algolia Key":      re.compile(r"(?i)algolia[_-]?(?:api)?[_-]?key['\"]?\s*[:=]\s*['\"]?([a-f0-9]{32})['\"]?"),
    "Mapbox Token":     re.compile(r"(?:pk|sk)\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
    "Sentry DSN":       re.compile(r"https://[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io/\d+"),

    "NPM Token":        re.compile(r"npm_[a-zA-Z0-9]{36}"),
    "PyPI Token":       re.compile(r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}"),
    "Docker Hub Token": re.compile(r"dckr_pat_[A-Za-z0-9_\-]{27}"),

    "Shopify Key":      re.compile(r"shpat_[a-fA-F0-9]{32}"),
    "Shopify Shared":   re.compile(r"shpss_[a-fA-F0-9]{32}"),
    "Shopify Access":   re.compile(r"shpca_[a-fA-F0-9]{32}"),

    "JWT Token":        re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    "Private Key":      re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY"),
    "Basic Auth URL":   re.compile(r"https?://[^:@\s\"']{3,}:[^:@\s\"']{3,}@[a-z0-9\-\.]+"),
    "Hardcoded Passwd": re.compile(r"(?i)(?:password|passwd|pwd|secret)\s*['\"]?\s*[:=]\s*['\"]([^'\"]{8,64})['\"]"),
    "API Key Assign":   re.compile(r"(?i)(?:api[_-]?key|apikey|x-api-key|auth_token|access_token|client_secret|app_secret|app_key|secret_key|private_key|consumer_key|consumer_secret)\s*['\"]?\s*[:=]\s*['\"]([A-Za-z0-9\-_]{16,})['\"]"),
    "Bearer Token":     re.compile(r"(?i)bearer\s+([a-zA-Z0-9_\-\.]{20,})"),
    "OAuth Secret":     re.compile(r"(?i)(?:oauth|client)[_-]?secret['\"]?\s*[:=]\s*['\"]([A-Za-z0-9\-_]{20,})['\"]"),

    "Internal IP/URL":  re.compile(r"https?://(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)[^\s'\"]{5,}"),
    "Database URI":     re.compile(r"(?i)(?:postgres|mysql|mongodb|redis|amqp|rediss|mssql|sqlite)://[^:\s]+:[^@\s]+@[^\s/<\"']+"),
    "SMTP URI":         re.compile(r"(?i)smtp://[^:\s]+:[^@\s]+@[^\s/<\"']+"),
    "S3 Bucket URL":    re.compile(r"(?:https?://)?[a-z0-9\-]+\.s3[.\-][a-z0-9\-]+\.amazonaws\.com"),
    "GCS Bucket URL":   re.compile(r"(?:https?://)?storage\.googleapis\.com/[a-z0-9\-_.]+"),
    "Azure Blob URL":   re.compile(r"(?:https?://)?[a-z0-9]+\.blob\.core\.windows\.net/[a-z0-9\-]+"),
}
PLACEHOLDERS={"undefined","null","placeholder","example","changeme",
               "password","secret","your_key","xxx","test","sample","dummy",
               "api_key","apikey","insert_your","token_here","key_here","xxxx",
               "12345678","abcdefgh","1234567890","YOUR_API_KEY","YOUR_SECRET",
               "REPLACE_ME","TODO","FIXME","your_token","your-api-key",
               "your_secret_key","insert_key_here","sk-xxxx","pk_test","sk_test",
               "example.com","localhost","127.0.0.1","0.0.0.0"}

_RECAPTCHA_PREFIX = re.compile(r"^6L[a-zA-Z0-9_-]{38}$")

_PASSWORD_UI_CONTEXT = re.compile(
    r"(?i)(?:"
    r"enter\s+(?:your\s+)?password|show\s+password|hide\s+password|forgot\s+password|"
    r"confirm\s+password|reset\s+password|change\s+password|new\s+password|"
    r"current\s+password|old\s+password|re-?enter\s+password|"
    r"placeholder|aria-label|aria-placeholder|data-i18n|translate|"
    r"<label|<input|<span|<p>|<div|type=.password|"
    r"i18n|l10n|locale|lang[_-]|messages?[._]|translations?[._]"
    r")"
)

MIN_TOKEN_ENTROPY = 3.0
               
@ensure_async
async def run_secrets(domain, live_lines, urls, out):
    section(8,"JS SECRETS SCANNER  (70+ patterns)")
    js_urls = {u for u in urls if ".js" in u.split("?")[0][-4:]}
    info(f"JS from step-4 crawl: {len(js_urls)}")
    live_host_urls = set()
    for _line in live_lines:
        _m = re.match(r"(https?://[^\s\[/]+)", _line)
        if _m: live_host_urls.add(_m.group(1))
    live_host_urls.add(f"https://{domain}")
    
    async with aiohttp.ClientSession() as session:
        async def _extract_js(base_url):
            _found = set()
            _, _body, _, _ = await http_probe(session, base_url+"/", timeout=8)
            if not _body: return _found
            for _src in re.findall(r"""src=["']([^"']{3,200})["']""", _body):
                _src = _src.strip()
                if ".js" not in _src: continue
                if _src.startswith("http"):  _found.add(_src)
                elif _src.startswith("//"): _found.add("https:"+_src)
                elif _src.startswith("/"):  _found.add(base_url.rstrip("/")+_src)
                else:                        _found.add(base_url.rstrip("/")+"/"+_src)
            for _src in re.findall(r"""(?:src|href|data-src)=["']([^"']{3,200}\.js(?:\?[^"']*)?)["']""", _body):
                _src = _src.strip()
                if _src.startswith("http"):  _found.add(_src)
                elif _src.startswith("//"): _found.add("https:"+_src)
                elif _src.startswith("/"):  _found.add(base_url.rstrip("/")+_src)
            for _src in re.findall(r"""import\s+.*?from\s+["']([^"']+\.js)["']""", _body):
                if _src.startswith("http"): _found.add(_src)
                elif _src.startswith("/"): _found.add(base_url.rstrip("/")+_src)
            return _found
            
        extract_tasks = [_extract_js(h) for h in sorted(live_host_urls)]
        extract_results = await asyncio.gather(*extract_tasks, return_exceptions=True)
        for res in extract_results:
            if not isinstance(res, Exception):
                js_urls.update(res)
                
        info(f"Total JS files queued: {len(js_urls)}")
        secrets=[]
        
        sem = asyncio.Semaphore(20)
        
        async def scan_one(js_url):
            async with sem:
                code,body,hdrs,_ = await http_probe(session, js_url,timeout=10)
                ct=hdrs.get("Content-Type","").lower()
                if code==0 or not body or len(body)<100 or "text/html" in ct: return []
                hits=[]; seen=set()
                for name,pat in JS_PATS.items():
                    for m in pat.finditer(body):
                        val=m.group(0)[:120]
                        inner=(m.group(1) if m.lastindex else val).strip()
                        if inner.lower() in PLACEHOLDERS or len(inner)<10: continue
                        if val in seen: continue
                        if _RECAPTCHA_PREFIX.match(inner):
                            continue
                        if name in ("AWS Access Key", "AWS Secret Key"):
                            if not _validate_aws_key(name, inner):
                                continue
                        if name == "Hardcoded Passwd":
                            start_pos = max(0, m.start() - 80)
                            end_pos = min(len(body), m.end() + 80)
                            context = body[start_pos:end_pos]
                            if _PASSWORD_UI_CONTEXT.search(context):
                                continue
                        ent = _shannon_entropy(inner)
                        if ent < MIN_TOKEN_ENTROPY:
                            continue
                        seen.add(val)
                        confidence = "HIGH"
                        if ent < 3.5:
                            confidence = "LOW"
                        elif ent < 4.0:
                            confidence = "MEDIUM"
                        hits.append({"type":name,"value":val,"url":js_url,"confidence":confidence,"entropy":round(ent,2)})
                return hits
                
        scan_tasks = [scan_one(u) for u in js_urls]
        scan_results = await asyncio.gather(*scan_tasks, return_exceptions=True)
        
        for res in scan_results:
            if isinstance(res, Exception):
                logger.debug(f"JS scan failed: {res}")
                continue
            for h in res:
                found(h["type"])
                print(GRY+"│     val: "+RESET+RED+BOLD+h["value"][:90]+RESET)
                print(GRY+"│     src: "+RESET+GRY+DIM+h["url"][:80]+RESET)
                secrets.append(h)
                
    if not secrets: ok("No secrets found")
    save_json(f"{out}/js_secrets.json",secrets)
    ok(f"JS secrets: {BOLD}{len(secrets)}{RESET}  ({BOLD}{len(JS_PATS)}{RESET} patterns)")
    _end()
    return secrets

scan_js = run_secrets
