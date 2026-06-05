import random
import asyncio
import logging
logger = logging.getLogger("bb-recon")

BROWSER_UA_PROFILES = [
    {
        "name": "Chrome-Win",
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "accept_language": "en-US,en;q=0.9",
        "accept_encoding": "gzip, deflate, br, zstd",
        "sec_ch_ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
        "sec_ch_ua_mobile": "?0",
        "sec_ch_ua_platform": '"Windows"',
    },
    {
        "name": "Chrome-Mac",
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "accept_language": "en-US,en;q=0.9",
        "accept_encoding": "gzip, deflate, br, zstd",
        "sec_ch_ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
        "sec_ch_ua_mobile": "?0",
        "sec_ch_ua_platform": '"macOS"',
    },
    {
        "name": "Firefox-Win",
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "accept_language": "en-US,en;q=0.5",
        "accept_encoding": "gzip, deflate, br, zstd",
    },
    {
        "name": "Firefox-Mac",
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0) Gecko/20100101 Firefox/125.0",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "accept_language": "en-US,en;q=0.5",
        "accept_encoding": "gzip, deflate, br",
    },
    {
        "name": "Edge-Win",
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "accept_language": "en-US,en;q=0.9",
        "accept_encoding": "gzip, deflate, br, zstd",
        "sec_ch_ua": '"Chromium";v="124", "Microsoft Edge";v="124", "Not-A.Brand";v="99"',
    },
    {
        "name": "Safari-Mac",
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "accept_language": "en-US,en;q=0.9",
        "accept_encoding": "gzip, deflate, br",
    },
]

def get_stealth_headers():
    profile = random.choice(BROWSER_UA_PROFILES)
    headers = {
        "User-Agent": profile["ua"],
        "Accept": profile["accept"],
        "Accept-Language": profile["accept_language"],
        "Accept-Encoding": profile["accept_encoding"],
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "DNT": "1",
        "Cache-Control": "max-age=0",
    }
    if "sec_ch_ua" in profile:
        headers["Sec-CH-UA"] = profile["sec_ch_ua"]
    if "sec_ch_ua_mobile" in profile:
        headers["Sec-CH-UA-Mobile"] = profile["sec_ch_ua_mobile"]
    if "sec_ch_ua_platform" in profile:
        headers["Sec-CH-UA-Platform"] = profile["sec_ch_ua_platform"]
    return headers

HEADER_ORDER_CHROME = [
    "Host", "Connection", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
    "Upgrade-Insecure-Requests", "User-Agent", "Accept", "Sec-Fetch-Site",
    "Sec-Fetch-Mode", "Sec-Fetch-User", "Sec-Fetch-Dest", "Accept-Encoding",
    "Accept-Language", "Cookie",
]

HEADER_ORDER_FIREFOX = [
    "Host", "User-Agent", "Accept", "Accept-Language", "Accept-Encoding",
    "Connection", "Upgrade-Insecure-Requests", "Sec-Fetch-Dest", "Sec-Fetch-Mode",
    "Sec-Fetch-Site", "Sec-Fetch-User", "Cookie",
]

async def stealth_delay(min_ms=50, max_ms=500):
    delay = random.gauss((min_ms + max_ms) / 2, (max_ms - min_ms) / 6)
    delay = max(min_ms, min(max_ms, delay))
    await asyncio.sleep(delay / 1000.0)

PAYLOAD_ENCODERS = {
    "url_double": lambda p: "".join(f"%25{ord(c):02x}" if not c.isalnum() else c for c in p),
    "unicode": lambda p: "".join(f"\\u{ord(c):04x}" if not c.isalnum() else c for c in p),
    "html_entity": lambda p: "".join(f"&#{ord(c)};" if not c.isalnum() else c for c in p),
    "mixed_case": lambda p: "".join(c.upper() if random.random() > 0.5 else c.lower() for c in p),
    "comment_insert": lambda p: "".join(c + ("/**/" if random.random() > 0.7 and c == " " else "") for c in p),
    "null_byte": lambda p: p.replace(" ", "%00"),
    "tab_insert": lambda p: p.replace(" ", "%09"),
    "newline_break": lambda p: p.replace(" ", "%0a"),
}

def encode_payload(payload, technique="url_double"):
    encoder = PAYLOAD_ENCODERS.get(technique)
    if encoder:
        return encoder(payload)
    return payload

def get_all_encoded_variants(payload):
    variants = [payload]
    for name, encoder in PAYLOAD_ENCODERS.items():
        try:
            encoded = encoder(payload)
            if encoded != payload and encoded not in variants:
                variants.append(encoded)
        except Exception:
            pass
    return variants
