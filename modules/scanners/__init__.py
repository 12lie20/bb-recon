import urllib.parse
from core.http import http_probe
from core.rate_limit import RATE_LIMITER

class BaseScanner:
    """Base OOP class for asynchronous vulnerability scanners."""
    
    def __init__(self, session, waf_detected: bool, waf_delay: float):
        self.session = session
        self.waf_detected = waf_detected
        self.waf_delay = waf_delay

    async def _waf_sleep(self):
        if self.waf_delay > 0:
            RATE_LIMITER.delay = max(RATE_LIMITER.delay, self.waf_delay)
        await RATE_LIMITER.wait()

    def _get_params(self, url):
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        return parsed, params

    def _build_url(self, parsed, params):
        new_query = urllib.parse.urlencode(params, doseq=True)
        return parsed._replace(query=new_query).geturl()

    async def scan(self, url: str) -> list:
        """
        Main method to be overridden.
        Should return a list of findings (dicts).
        """
        raise NotImplementedError("Scanners must implement the scan() method.")
