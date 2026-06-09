import time, ssl, asyncio, logging, random
import difflib
try:
    import aiohttp
except ImportError:
    pass

logger = logging.getLogger("bb-recon")
from core.config import CONFIG
from core.ui import *
from core.utils import UA, random_ua
from core.rate_limit import RATE_LIMITER

def _ctx():
    if CONFIG.verify_ssl:
        return ssl.create_default_context()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_ciphers('DEFAULT:@SECLEVEL=1')
    return ctx

def _build_auth_headers():
    h = {}
    if CONFIG.auth_header:
        parts = CONFIG.auth_header.split(":", 1)
        if len(parts) == 2:
            h[parts[0].strip()] = parts[1].strip()
    if CONFIG.custom_headers:
        h.update(CONFIG.custom_headers)
    return h

def _build_auth_cookie():
    if CONFIG.auth_cookie:
        return CONFIG.auth_cookie
    return None

BINARY_TYPES = {
    'image/', 'video/', 'audio/', 'application/pdf', 'application/zip',
    'application/x-rar', 'application/octet-stream', 'application/x-executable',
    'application/x-sharedlib', 'font/', 'application/msword', 'application/vnd.ms-'
}

def is_soft_404(body, baseline_body, threshold=0.85):
    if not body or not baseline_body:
        return False
    # Quick length check
    len_diff = abs(len(body) - len(baseline_body))
    if len_diff < 20:
        return True
    # Similarity check for small bodies
    if len(body) < 10000 and len(baseline_body) < 10000:
        ratio = difflib.SequenceMatcher(None, body[:2000], baseline_body[:2000]).ratio()
        return ratio > threshold
    return False

async def http_probe(session, url, timeout=8, method="GET", data=None, extra_headers=None, follow_redirects=True, retries=3, rotate_ua=False, max_body_size=1024*1024):
    headers = {
        "User-Agent": random_ua() if rotate_ua else UA, 
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
    }
    auth_h = _build_auth_headers()
    if auth_h: headers.update(auth_h)
    if extra_headers: headers.update(extra_headers)

    cookie_str = _build_auth_cookie()
    if cookie_str and "Cookie" not in headers:
        headers["Cookie"] = cookie_str

    client_timeout = aiohttp.ClientTimeout(total=timeout, connect=max(3, timeout-2))
    ssl_context = _ctx()

    host = ""
    try:
        from urllib.parse import urlparse
        host = urlparse(url).netloc
    except: pass

    for attempt in range(retries):
        if host: await RATE_LIMITER.wait(host)
        t0 = time.time()
        try:
            async with session.request(
                method, url, headers=headers, data=data,
                timeout=client_timeout, ssl=ssl_context,
                allow_redirects=follow_redirects
            ) as r:
                ms = int((time.time() - t0) * 1000)
                
                # Backoff for rate limits
                if r.status in (429, 503):
                    if host: await RATE_LIMITER.report_blocked(host)
                    wait_time = (2 ** attempt) + random.uniform(0.1, 1.0)
                    await asyncio.sleep(wait_time)
                    continue

                if host: await RATE_LIMITER.report_success(host)

                # Binary & Size Check
                ct = r.headers.get("Content-Type", "").lower()
                cl = int(r.headers.get("Content-Length", 0))
                if any(bt in ct for bt in BINARY_TYPES) or cl > max_body_size:
                    return r.status, "[binary/large skipped]", dict(r.headers), ms

                body_bytes = await r.read()
                body = body_bytes.decode("utf-8", errors="ignore")
                return r.status, body, dict(r.headers), ms
        except (asyncio.TimeoutError, aiohttp.ClientError) as e:
            if attempt < retries - 1:
                wait_time = (2 ** attempt) + random.uniform(0.5, 1.5)
                await asyncio.sleep(wait_time)
                continue
            return 0, "", {}, 0
        except Exception as e:
            return 0, "", {}, 0
            
    return 0, "", {}, 0
