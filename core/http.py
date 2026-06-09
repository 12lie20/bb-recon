import time, ssl, asyncio, logging, random
try:
    import aiohttp
except ImportError:
    pass

logger = logging.getLogger("bb-recon")
from core.config import CONFIG
from core.ui import *
from core.utils import UA, random_ua
from core.rate_limit import RATE_LIMITER

# Binary content types to avoid full body read
BINARY_TYPES = {
    'application/octet-stream', 'application/pdf', 'application/zip', 
    'image/', 'video/', 'audio/', 'application/x-executable',
    'application/x-sharedlib', 'font/'
}

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
    return CONFIG.auth_cookie if CONFIG.auth_cookie else None

async def http_probe(session, url, timeout=8, method="GET", data=None, extra_headers=None, 
                     follow_redirects=True, retries=3, rotate_ua=False, max_body_size=1_000_000):
    
    await RATE_LIMITER.wait(url)
    
    headers = {
        "User-Agent": random_ua() if rotate_ua else UA, 
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
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

    for attempt in range(retries):
        t0 = time.time()
        try:
            async with session.request(
                method, url, headers=headers, data=data,
                timeout=client_timeout, ssl=ssl_context,
                allow_redirects=follow_redirects
            ) as r:
                ct = r.headers.get("Content-Type", "").lower()
                cl = int(r.headers.get("Content-Length", 0))
                
                # Check for binary types or excessive size before reading
                if any(bt in ct for bt in BINARY_TYPES) or cl > max_body_size:
                    # We might still want the head/metadata
                    ms = int((time.time() - t0) * 1000)
                    return r.status, f"[Binary Content or Large File: {ct}]", dict(r.headers), ms

                body_bytes = await r.read()
                body = body_bytes.decode("utf-8", errors="ignore")
                ms = int((time.time() - t0) * 1000)
                
                if r.status in (429, 502, 503, 504):
                    await RATE_LIMITER.report_blocked(url)
                    if attempt < retries - 1:
                        continue
                else:
                    await RATE_LIMITER.report_success(url)
                    
                return r.status, body, dict(r.headers), ms
                
        except (asyncio.TimeoutError, aiohttp.ClientError):
            if attempt < retries - 1:
                await asyncio.sleep(1 * (attempt + 1))
                continue
            return 0, "", {}, 0
        except Exception as e:
            logger.debug(f"Request error for {url}: {e}")
            return 0, "", {}, 0
            
    return 0, "", {}, 0
