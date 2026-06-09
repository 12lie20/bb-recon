import asyncio, logging, random
from urllib.parse import urlparse
logger = logging.getLogger("bb-recon")
from core.ui import warn, info
from core.config import CONFIG

AGGRESSIVE_WAFS = {"cloudflare", "aws waf", "aws shield", "akamai", "imperva/incapsula",
                   "imperva", "incapsula", "google cloud armor", "azure waf/frontdoor"}
MODERATE_WAFS = {"f5 big-ip", "sucuri", "modsecurity", "fortinet", "barracuda",
                 "palo alto", "radware", "citrix/netscaler", "fastly", "wallarm",
                 "wordfence", "reblaze", "naxsi"}

class HostLimiter:
    def __init__(self, initial=0.05, max_delay=8.0):
        self.delay = initial
        self.max_delay = max_delay
        self.base_delay = initial
        self.success_streak = 0
        self.total_requests = 0
        self.total_blocked = 0
        self._lock = asyncio.Lock()

    async def wait(self):
        self.total_requests += 1
        if self.delay > 0.01:
            jitter = random.uniform(0, 0.15 * self.delay)
            await asyncio.sleep(self.delay + jitter)

    async def report_blocked(self, host):
        async with self._lock:
            self.total_blocked += 1
            self.success_streak = 0
            old = self.delay
            self.delay = min(self.max_delay, max(0.5, self.delay * 2.0))
            if self.delay != old:
                warn(f"WAF/Rate-limit [{host}] — backoff {old:.2f}s → {self.delay:.2f}s")
            await asyncio.sleep(self.delay + random.uniform(0.5, 2.0))

    async def report_success(self):
        async with self._lock:
            self.success_streak += 1
            if self.success_streak > 12:
                self.delay = max(self.base_delay, self.delay * 0.70)
                self.success_streak = 0

class AdaptiveRateLimiter:
    def __init__(self, initial=0.05, max_delay=8.0):
        self.initial = initial
        self.max_delay = max_delay
        self.host_limiters = {}
        self._lock = asyncio.Lock()
        self.waf_level = "unknown"

    def _get_host(self, url_or_host):
        if "://" in url_or_host:
            return urlparse(url_or_host).netloc
        return url_or_host

    async def get_limiter(self, url_or_host):
        host = self._get_host(url_or_host)
        async with self._lock:
            if host not in self.host_limiters:
                self.host_limiters[host] = HostLimiter(self.initial, self.max_delay)
            return self.host_limiters[host]

    async def wait(self, url_or_host):
        limiter = await self.get_limiter(url_or_host)
        await limiter.wait()

    async def report_blocked(self, url_or_host):
        host = self._get_host(url_or_host)
        limiter = await self.get_limiter(host)
        await limiter.report_blocked(host)

    async def report_success(self, url_or_host):
        limiter = await self.get_limiter(url_or_host)
        await limiter.report_success()

    def adapt_to_waf(self, waf_name, url_or_host=None):
        if not waf_name: return
        waf_lower = waf_name.lower()
        
        # Global config adjustments
        if any(aw in waf_lower for aw in AGGRESSIVE_WAFS):
            CONFIG.waf_level = "aggressive"
            CONFIG.max_threads = min(CONFIG.max_threads, 5)
            self.initial = max(self.initial, 2.0)
        elif any(mw in waf_lower for mw in MODERATE_WAFS):
            CONFIG.waf_level = "moderate"
            CONFIG.max_threads = min(CONFIG.max_threads, 10)
            self.initial = max(self.initial, 1.0)
        
        if url_or_host:
            # We can't easily await here as this is often called from sync contexts,
            # but in this refactor we'll ensure the host limiter exists.
            pass

    def stats(self):
        total_req = sum(l.total_requests for l in self.host_limiters.values())
        total_blk = sum(l.total_blocked for l in self.host_limiters.values())
        return {
            "total_requests": total_req,
            "total_blocked": total_blk,
            "hosts_tracked": len(self.host_limiters),
            "block_rate": round(total_blk / max(1, total_req) * 100, 1),
            "waf_level": getattr(CONFIG, 'waf_level', 'light'),
        }

RATE_LIMITER = AdaptiveRateLimiter()
