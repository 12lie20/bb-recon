import time, ssl, asyncio, logging, random
try:
    import aiohttp
except ImportError:
    pass

logger = logging.getLogger("bb-recon")
from core.config import CONFIG
from core.ui import *
from core.utils import UA, random_ua

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

async def http_probe(session, url, timeout=8, method="GET", data=None, extra_headers=None, follow_redirects=True, retries=3, rotate_ua=False):
    headers = {
        "User-Agent": random_ua() if rotate_ua else UA, 
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "DNT": "1",
    }
    auth_h = _build_auth_headers()
    if auth_h:
        headers.update(auth_h)
    if extra_headers:
        headers.update(extra_headers)

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
                body_bytes = await r.read()
                body = body_bytes.decode("utf-8", errors="ignore")
                ms = int((time.time() - t0) * 1000)
                
                if r.status in (429, 502, 503, 504) and attempt < retries - 1:
                    wait_time = (2 ** attempt) + random.uniform(0.1, 1.0)
                    await asyncio.sleep(wait_time)
                    continue
                    
                return r.status, body, dict(r.headers), ms
        except asyncio.TimeoutError:
            if attempt < retries - 1:
                wait_time = (2 ** attempt) + random.uniform(0.5, 1.5)
                await asyncio.sleep(wait_time)
                continue
            return 0, "", {}, 0
        except aiohttp.ClientError:
            if attempt < retries - 1:
                wait_time = (2 ** attempt) + random.uniform(0.1, 1.0)
                await asyncio.sleep(wait_time)
                continue
            return 0, "", {}, 0
        except Exception as e:
            if attempt < retries - 1:
                await asyncio.sleep(0.5)
                continue
            return 0, "", {}, 0
            
    return 0, "", {}, 0
