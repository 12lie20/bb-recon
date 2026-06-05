import aiohttp
import asyncio
import ssl
import hashlib
import time
import logging
from core.config import CONFIG
from core.utils import UA, random_ua

logger = logging.getLogger("bb-recon")

class SessionManager:
    def __init__(self, max_connections=100, max_per_host=10):
        self._session = None
        self._max_conn = max_connections
        self._max_per_host = max_per_host
        self._cache = {}
        self._cache_ttl = 30
        self._lock = asyncio.Lock()

    def _ssl_ctx(self):
        if CONFIG.verify_ssl:
            return ssl.create_default_context()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers('DEFAULT:@SECLEVEL=1')
        return ctx

    async def get_session(self):
        if self._session is None or self._session.closed:
            async with self._lock:
                if self._session is None or self._session.closed:
                    connector = aiohttp.TCPConnector(
                        limit=self._max_conn,
                        limit_per_host=self._max_per_host,
                        ssl=self._ssl_ctx(),
                        enable_cleanup_closed=True,
                        ttl_dns_cache=300,
                        force_close=False,
                    )
                    timeout = aiohttp.ClientTimeout(total=30, connect=10)
                    self._session = aiohttp.ClientSession(
                        connector=connector,
                        timeout=timeout,
                        headers={"User-Agent": UA},
                    )
        return self._session

    def _cache_key(self, method, url, headers_hash=""):
        raw = f"{method}:{url}:{headers_hash}"
        return hashlib.md5(raw.encode()).hexdigest()

    def get_cached(self, method, url, headers_hash=""):
        key = self._cache_key(method, url, headers_hash)
        entry = self._cache.get(key)
        if entry and (time.time() - entry["ts"]) < self._cache_ttl:
            return entry["data"]
        return None

    def set_cached(self, method, url, data, headers_hash=""):
        key = self._cache_key(method, url, headers_hash)
        self._cache[key] = {"data": data, "ts": time.time()}
        if len(self._cache) > 5000:
            cutoff = time.time() - self._cache_ttl
            self._cache = {k: v for k, v in self._cache.items() if v["ts"] > cutoff}

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None
        self._cache.clear()

SESSION_POOL = SessionManager()
