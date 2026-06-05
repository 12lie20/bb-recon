# BB-RECON

Automated bug bounty reconnaissance framework. Point it at a domain and it runs a full security audit — subdomain enumeration, vulnerability scanning, secret detection, CVE mapping, and an HTML report.

## What it does

18 stages, sequentially:

1. **Subdomain enumeration** — crt.sh + 10 passive APIs + subfinder + dnsx + httpx
2. **WAF detection & baseline** — 30+ WAF providers, per-host response fingerprints
3. **Port scanning** — naabu top-1000 + service banner grabbing + HTTP probing
4. **URL collection** — waybackurls + gau + katana + uro dedup
5. **URL classification** — 15 categories (admin panels, APIs, file uploads, SQLi/LFI candidates, etc.)
6. **Active vulnerability scans** — SQLi (error/boolean/time-based) + XSS (context-aware) + LFI + SSRF + OS command injection + SSTI + CRLF injection + Open Redirect + XXE + HTTP Smuggling + Cache Poisoning + Deserialization
7. **CORS + Host Header injection + Subdomain takeover**
8. **CSRF detection** — form parsing, method checks, token presence validation
9. **JWT attacks** — alg:none bypass + common secret brute-force + privilege escalation
10. **API security** — OpenAPI/Swagger discovery + BOLA/IDOR + Mass Assignment + Rate Limit testing
11. **Cookie analysis** — weak tokens (MD5), Base64 decoding, JWT detection, session fixation
12. **Version detection & CVE mapping** — active probing across 40+ CVEs with prerequisite checks
13. **JS secrets scanning** — 70+ patterns (AWS, GCP, Azure, GitHub, Slack, Stripe, etc.)
14. **Security headers audit** — CSP, HSTS, X-Frame-Options, COOP, COEP, CORP, Permissions-Policy
15. **Nuclei integration** — tagged by detected tech stack
16. **Cloud misconfigurations** — S3, GCS, Azure Blob, Firebase, GraphQL introspection, metadata endpoints
17. **Source map analysis** — extract hidden endpoints from .map files
18. **HTML report** — severity cards, evidence, CVE tables, secret listings

## Requirements

- Python 3.9+
- Go (optional but recommended — subfinder, httpx, dnsx, naabu, nuclei, katana, waybackurls, gau, uro)

The framework auto-installs missing Go tools if Go is installed. It degrades gracefully otherwise.

## Install

```bash
git clone https://github.com/<your-account>/bb-recon
cd bb-recon
pip install -r requirements.txt
```

## Usage

```bash
# Basic scan
python main.py -d example.com

# Deep scan with higher concurrency
python main.py -d example.com --deep --threads 100

# Authenticated scanning
python main.py -d example.com --auth-cookie "session=abc123"

# Slack & Discord notifications for HIGH+ findings
python main.py -d example.com --notify-slack "https://hooks.slack.com/..." --notify-discord "https://discord.com/api/webhooks/..."

# Skip stages you don't need
python main.py -d example.com --no-ports --no-jwt --no-nuclei

# Resume from a checkpoint
python main.py -d example.com --resume recon_example.com_20260605_120000
```

## Output

Everything lands in `recon_<domain>_<timestamp>/`:

| File | Contents |
|------|----------|
| `subdomains.txt` | All discovered subdomains |
| `live_hosts.txt` | Live hosts with status codes & tech stack |
| `urls.txt` | Deduplicated URLs |
| `classified_urls.json` | Categorized URLs with HTTP probe results |
| `active_param_findings.json` | Confirmed vulnerabilities (SQLi, XSS, LFI, SSRF, etc.) |
| `misc_findings.json` | CORS, takeover, host header injection |
| `js_secrets.json` | Secrets extracted from JavaScript files |
| `cve_mapping.json` | Detected versions and mapped CVEs |
| `security_headers.json` | Missing & weak security headers |
| `nuclei.json` | Nuclei findings |
| `cookie_analysis.json` | Cookie/session vulnerabilities |
| `cloud_findings.json` | Cloud misconfigurations & takeover risk |
| `summary.json` | Full scan summary |
| `report.html` | Final HTML report |

## Structure

```
bb-recon/
├── main.py              # Entry point
├── core/                # Shared infrastructure (config, HTTP, rate limiting, UI)
├── modules/             # Scan modules
│   └── scanners/        # Vulnerability scanners (SQLi, XSS, SSRF, XXE, etc.)
├── legacy/              # Old monolithic builds (reference only)
└── requirements.txt
```

## Disclaimer

This tool is meant for ethical security testing and authorized bug bounty programs. Only scan domains you own or have explicit permission to test.
