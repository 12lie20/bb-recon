# bb-recon

Hi — this is bb-recon. I built it to make the tedious early stages of bug-bounty recon faster and less repetitive.

What it is

bb-recon ties together a bunch of well-known tools and small scripts to automatically collect the attack surface of a target domain: subdomains, live hosts, URLs, basic fingerprints, and quick active checks. Think of it as a fast, opinionated starting point — not a replacement for careful manual testing.

Why use it

- Save time on the repetitive parts of recon.
- Get structured output you can feed into your manual workflow.
- Bring together passive and active techniques without wiring everything yourself.

Highlights

- Subdomain and URL collection
- Port/service probing and simple fingerprinting
- Integrations: waybackurls, gau, subfinder, httpx/dnsx, naabu, nuclei (if installed)
- JSON and HTML output for easy review and reporting

Quick start

Requirements

- Python 3.10+
- pip
- (Optional) Go toolchain if you want bb-recon to install and use Go-based tools (recommended)

Install

```bash
git clone https://github.com/12lie20/bb-recon.git
cd bb-recon
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Run a basic scan

```bash
# example
python main.py --domain example.com --output results/example.com
```

Common options

- --domain / -d : target domain
- --output : output directory
- --deep : enable deeper (slower) checks
- --no-nuclei / --no-ports : skip stages you don't want

What the output looks like

The run creates a folder like `recon_<domain>_<timestamp>/` with files such as:

- subdomains.txt — discovered subdomains
- live_hosts.txt — live hosts and status codes
- urls.txt — collected URLs
- findings/ — structured JSON/HTML report with notable results

Contributing

If you want to improve parsing, add a new module, or tidy outputs: open a PR. Keep changes modular and add tests where it makes sense.

License

If you want me to add a specific license (MIT/Apache-2.0, etc.), tell me which one and I'll add it.

Responsible use

Only run bb-recon against domains you own or have explicit permission to test. This tool can trigger active scans; misuse is your responsibility.

Need customization?

If you want extra integrations, output formats, or a CI workflow, tell me which repo to target and I’ll add it.