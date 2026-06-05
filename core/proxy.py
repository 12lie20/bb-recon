import random
import itertools
import logging
logger = logging.getLogger("bb-recon")

class ProxyManager:
    def __init__(self, proxy_list=None, proxy_file=None, use_tor=False):
        self.proxies = []
        self._cycle = None
        self.use_tor = use_tor

        if use_tor:
            self.proxies = ["socks5://127.0.0.1:9050"]
        elif proxy_file:
            try:
                with open(proxy_file, "r") as f:
                    self.proxies = [l.strip() for l in f if l.strip() and not l.startswith("#")]
                logger.info(f"Loaded {len(self.proxies)} proxies from {proxy_file}")
            except Exception as e:
                logger.warning(f"Could not load proxy file {proxy_file}: {e}")
        elif proxy_list:
            self.proxies = proxy_list

        if self.proxies:
            self._cycle = itertools.cycle(self.proxies)

    @property
    def active(self):
        return len(self.proxies) > 0

    def get_proxy(self):
        if not self.proxies:
            return None
        return next(self._cycle)

    def get_random_proxy(self):
        if not self.proxies:
            return None
        return random.choice(self.proxies)

    def remove_proxy(self, proxy):
        if proxy in self.proxies:
            self.proxies.remove(proxy)
            if self.proxies:
                self._cycle = itertools.cycle(self.proxies)
            else:
                self._cycle = None
            logger.info(f"Removed bad proxy: {proxy} ({len(self.proxies)} remaining)")

PROXY_MANAGER = ProxyManager()

def configure_proxy(proxy_list=None, proxy_file=None, use_tor=False):
    global PROXY_MANAGER
    PROXY_MANAGER = ProxyManager(proxy_list=proxy_list, proxy_file=proxy_file, use_tor=use_tor)
