import logging
from dataclasses import dataclass, field
logger = logging.getLogger("bb-recon")
@dataclass
class ScanConfig:
    max_threads: int = 30
    verify_ssl: bool = False
    dry_run: bool = False
    auth_cookie: str = ""
    auth_header: str = ""
    oob_server: str = ""
    deep_scan: bool = False
    custom_headers: dict[str, str] = field(default_factory=dict)
    waf_level: str = "none"
    original_threads: int = 30
    scan_timeout: int = 10
CONFIG = ScanConfig()
_interrupted = False
