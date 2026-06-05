from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import json

@dataclass
class Finding:
    id: str = ""
    type: str = ""
    severity: str = "INFO"
    confidence: str = "POSSIBLE"
    url: str = ""
    param: str = ""
    payload: str = ""
    evidence: str = ""
    cvss_score: float = 0.0
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    timestamp: str = ""
    module: str = ""
    technique: str = ""
    host: str = ""
    extra: dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if not self.id:
            raw = f"{self.type}:{self.url}:{self.param}:{self.payload}"
            self.id = hashlib.md5(raw.encode()).hexdigest()[:12]

    def to_dict(self):
        d = {}
        for k, v in self.__dict__.items():
            if v or v == 0:
                d[k] = v
        return d

    @staticmethod
    def from_dict(d):
        return Finding(**{k: v for k, v in d.items() if k in Finding.__dataclass_fields__})

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
CONFIDENCE_ORDER = {"CONFIRMED": 0, "LIKELY": 1, "POSSIBLE": 2}

REMEDIATION_MAP = {
    "SQLi":                "Use parameterized queries/prepared statements. Never concatenate user input into SQL.",
    "XSS":                 "Sanitize output with context-aware encoding. Implement strict CSP.",
    "LFI":                 "Validate and whitelist file paths. Disable allow_url_include in PHP.",
    "SSRF":                "Whitelist allowed URLs/IPs. Block internal/metadata IPs. Use network segmentation.",
    "SSTI":                "Never pass user input directly into template engines. Use sandboxed rendering.",
    "CRLF":                "Strip CR/LF characters from user input before using in HTTP headers.",
    "OpenRedirect":        "Whitelist redirect destinations. Validate redirect URLs against allowed domains.",
    "OS-CMD":              "Avoid system calls with user input. Use language-native APIs instead of shell commands.",
    "XXE":                 "Disable external entity processing. Use JSON instead of XML where possible.",
    "CSRF":                "Implement anti-CSRF tokens. Use SameSite=Strict cookies.",
    "IDOR":                "Implement proper authorization checks. Use UUIDs instead of sequential IDs.",
    "PrototypePollution":  "Freeze Object.prototype. Validate JSON keys. Use Map instead of plain objects.",
    "SubdomainTakeover":   "Remove dangling DNS records. Monitor CNAME targets.",
    "CORS-CRITICAL":       "Restrict ACAO to specific trusted origins. Never reflect arbitrary origins with credentials.",
    "HostHeaderInjection": "Whitelist allowed Host header values. Use server-side base URL configuration.",
    "JWT":                 "Use strong algorithms (RS256/ES256). Validate all claims. Rotate signing keys.",
    "HTTPSmuggling":       "Normalize HTTP parsing. Disable HTTP/1.1 keep-alive if not needed. Use HTTP/2 end-to-end.",
    "CachePoisoning":      "Normalize cache keys. Restrict unkeyed headers. Use Vary header correctly.",
    "Deserialization":     "Never deserialize untrusted data. Use safe serialization formats (JSON).",
    "FirebaseOpenRead":    "Configure Firebase Security Rules to require authentication.",
    "OpenBucket":          "Set bucket policy to private. Enable access logging.",
    "GraphQLIntrospection":"Disable introspection in production. Implement field-level authorization.",
}

def auto_remediation(finding_type):
    for key, rem in REMEDIATION_MAP.items():
        if key.lower() in finding_type.lower():
            return rem
    return "Review and fix according to security best practices."

def sort_findings(findings):
    return sorted(findings, key=lambda f: (
        SEVERITY_ORDER.get(f.get("severity", "INFO"), 4),
        CONFIDENCE_ORDER.get(f.get("confidence", "POSSIBLE"), 2)
    ))
