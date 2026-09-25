# GhostCrawl v3.3 — Recon & Exploit Detection Tool

```
 ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗ ██████╗██████╗  █████╗ ██╗    ██╗██╗
██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝██╔════╝██╔══██╗██╔══██╗██║    ██║██║
██║  ███╗███████║██║   ██║███████╗   ██║   ██║     ██████╔╝███████║██║ █╗ ██║██║
██║   ██║██╔══██║██║   ██║╚════██║   ██║   ██║     ██╔══██╗██╔══██║██║███╗██║██║
╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ╚██████╗██║  ██║██║  ██║╚███╔███╔╝███████╗
```

**Developer:** ANZZ  
**Version:** 3.3 "Report Intelligence"  
**Module:** OSINT / Recon / Web Exploit Detection

---

## Features

| Module | Description |
|--------|-------------|
| **Recon Core** | Async crawler, fingerprint, path probe, JS secret extraction |
| **Auth-Aware** | Cookie / Bearer / API Key / Form Login session support |
| **Fingerprint** | CMS/framework detection (12 stacks), WAF/CDN detection (8 providers) |
| **Risk Engine** | Severity scoring, CRITICAL/HIGH/MEDIUM/LOW/INFO tagging, auto-summary |
| **SQLi Probe** | Error-based + boolean-based detection (non-destructive) |
| **IDOR Enum** | Sequential ID ownership-check probing |
| **Export** | JSON + Markdown + CSV auto-export |

---

## Requirements

- Python 3.10+
- Dependencies auto-installed via `install.py`

---

## Quick Start

```bash
git clone https://github.com/nebulaaics01-oss/ghostcrawl.git
cd ghostcrawl
python install.py
```

Or install manually:

```bash
pip install -r requirements.txt
python -m ghostcrawl
```

---

## Usage

```bash
# Auto-install + launch
python install.py

# Direct launch (after deps installed)
python -m ghostcrawl
```

### Menu Options

```
1  Full Recon Scan
2  Quick Fingerprint Only
3  Common Path Probe Only
4  SQLi Probe
5  IDOR Enumeration
6  Full Recon + Exploit Probe
0  Exit
```

---

## Output

All exports saved to `./output/`:

```
output/
  target_YYYYMMDD_HHMMSS.json     ← full raw findings
  target_YYYYMMDD_HHMMSS.md       ← readable report
  target_YYYYMMDD_HHMMSS_endpoints.csv
  ghostcrawl.log                  ← request trail
```

---

## Project Structure

```
ghostcrawl/
├── install.py          ← auto-installer + launcher
├── __main__.py         ← python -m entrypoint
├── requirements.txt
├── README.md
└── modules/
    ├── __init__.py
    ├── config.py       ← dataclasses, enums, logging setup
    ├── auth.py         ← auth handler (cookie/bearer/api key/form login)
    ├── fingerprint.py  ← CMS + WAF detection engine
    ├── risk.py         ← risk scoring + auto-summary
    ├── exploit.py      ← SQLi probe + IDOR enumerator
    ├── report.py       ← Rich rendering + JSON/MD/CSV export
    └── core.py         ← scraper class + interactive menu
```

---

## Legal Notice

This tool performs real HTTP requests.
**Use only against targets you own or are authorized to test.**
Unauthorized use is illegal and unethical.
