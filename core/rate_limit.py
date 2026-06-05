import asyncio, logging, random
logger = logging.getLogger("bb-recon")
from core.ui import warn, info
from core.config import CONFIG

AGGRESSIVE_WAFS = {"cloudflare", "aws waf", "aws shield", "akamai", "imperva/incapsula",
                   "imperva", "incapsula", "google cloud armor", "azure waf/frontdoor"}
MODERATE_WAFS = {"f5 big-ip", "sucuri", "modsecurity", "fortinet", "barracuda",
                 "palo alto", "radware", "citrix/netscaler", "fastly", "wallarm",
                 "wordfence", "reblaze", "naxsi"}

class AdaptiveRateLimiter:
    def __init__(self, initial=0.05, max_delay=8.0):
        self.delay = initial
        self.max_delay = max_delay
        self.blocked_count = 0
        self.success_streak = 0
        self.base_delay = initial
        self._lock = asyncio.Lock()
        self.total_requests = 0
        self.total_blocked = 0

    async def wait(self):
        self.total_requests += 1
        if self.delay > 0.01:
            jitter = random.uniform(0, 0.15 * self.delay)
            await asyncio.sleep(self.delay + jitter)

    async def report_blocked(self):
        async with self._lock:
            self.blocked_count += 1
            self.total_blocked += 1
            self.success_streak = 0
            old = self.delay
            self.delay = min(self.max_delay, max(0.5, self.delay * 2.0))
            if self.delay != old:
                warn(f"WAF/Rate-limited — backoff {old:.2f}s → {self.delay:.2f}s (total blocks: {self.total_blocked})")
            await asyncio.sleep(self.delay + random.uniform(0.5, 2.0))

    async def report_success(self):
        async with self._lock:
            self.success_streak += 1
            if self.success_streak > 12:
                self.delay = max(self.base_delay, self.delay * 0.70)
                self.success_streak = 0

    def adapt_to_waf(self, waf_name):
        if not waf_name:
            return
        waf_lower = waf_name.lower()
        
        if any(aw in waf_lower for aw in AGGRESSIVE_WAFS):
            CONFIG.waf_level = "aggressive"
            CONFIG.max_threads = min(CONFIG.max_threads, 5)
            CONFIG.scan_timeout = 20
            self.delay = max(self.delay, 2.0)
            self.base_delay = max(self.base_delay, 2.0)
            self.max_delay = 15.0
            warn(f"Aggressive WAF ({waf_name}) → threads={CONFIG.max_threads}, delay={self.delay}s, timeout={CONFIG.scan_timeout}s")
        elif any(mw in waf_lower for mw in MODERATE_WAFS):
            CONFIG.waf_level = "moderate"
            CONFIG.max_threads = min(CONFIG.max_threads, 10)
            CONFIG.scan_timeout = 15
            self.delay = max(self.delay, 1.0)
            self.base_delay = max(self.base_delay, 1.0)
            self.max_delay = 12.0
            warn(f"Moderate WAF ({waf_name}) → threads={CONFIG.max_threads}, delay={self.delay}s, timeout={CONFIG.scan_timeout}s")
        else:
            CONFIG.waf_level = "light"
            CONFIG.max_threads = min(CONFIG.max_threads, 15)
            CONFIG.scan_timeout = 12
            self.delay = max(self.delay, 0.5)
            self.base_delay = max(self.base_delay, 0.5)
            info(f"Light WAF ({waf_name}) → threads={CONFIG.max_threads}, delay={self.delay}s")

    def stats(self):
        return {
            "total_requests": self.total_requests,
            "total_blocked": self.total_blocked,
            "final_delay": round(self.delay, 3),
            "block_rate": round(self.total_blocked / max(1, self.total_requests) * 100, 1),
            "waf_level": CONFIG.waf_level,
        }

RATE_LIMITER = AdaptiveRateLimiter()
