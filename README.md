<div align="center">

```
███████╗██╗   ██╗██████╗ ███████╗████████╗ █████╗ ████████╗██╗   ██╗███████╗
██╔════╝██║   ██║██╔══██╗██╔════╝╚══██╔══╝██╔══██╗╚══██╔══╝██║   ██║██╔════╝
███████╗██║   ██║██████╔╝███████╗   ██║   ███████║   ██║   ██║   ██║███████╗
╚════██║██║   ██║██╔══██╗╚════██║   ██║   ██╔══██║   ██║   ██║   ██║╚════██║
███████║╚██████╔╝██████╔╝███████║   ██║   ██║  ██║   ██║   ╚██████╔╝███████║
╚══════╝ ╚═════╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚══════╝
```

**Fast async subdomain HTTP status checker for security reconnaissance**

[![Python](https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square&logo=python)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow?style=flat-square)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.0-brightgreen?style=flat-square)]()
[![Async](https://img.shields.io/badge/async-aiohttp-orange?style=flat-square)]()

</div>

---

## What is SubStatus?

**SubStatus** is a fast, fully async Python CLI tool designed to check the HTTP/HTTPS status of large subdomain lists during security reconnaissance. Feed it the output of any subdomain enumeration tool, and it tells you which hosts are live, their response codes, IPs, page titles, server technologies, and response times — all in seconds.

```
URL                                           STATUS   TIME       IP                 TITLE                                    TECH
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
https://shop.example.com                      200      0.187s     93.184.216.34      Example Shop — Home                      Nginx, Cloudflare
https://staging.example.com                   403      0.334s     93.184.216.34      403 Forbidden                            Nginx
https://dev.example.com                       DOWN     -          N/A                N/A                                      N/A
```

---

## Features

| Feature | Description |
|---|---|
| ⚡ **Full Async Engine** | Built on `aiohttp` — fires all requests concurrently with zero thread overhead |
| 🌐 **Dual Protocol** | Auto-probes HTTPS first, falls back to HTTP per target |
| 🔐 **SSL Tolerance** | Bypasses broken, self-signed, or expired certificates gracefully |
| 🎨 **Colored Output** | Status codes, IPs, response times all color-coded in the terminal |
| 📄 **HTML Title Scraping** | Extracts `<title>` tag from every live response body |
| 🔍 **Tech Fingerprinting** | Detects server stack from response headers (Nginx, Cloudflare, PHP, Vercel, etc.) |
| 🌍 **DNS / IP Resolution** | Resolves A record and CNAME per target via `dnspython` |
| 📊 **JSON + CSV Export** | Auto-exports results on every run; override output path with flags |
| 📈 **Scan Summary** | Live/down counts, status code breakdown, and total scan time |
| 🔇 **Live-only Filter** | `--live-only` flag to suppress DOWN hosts from terminal output |
| ♾️ **No Target Limit** | Handles 1000+ subdomains; no artificial cap |

---

## Installation

**1. Clone the repository**
```bash
git clone https://github.com/yahyaibr/Subdomain-status-checker.git
cd Subdomain-status-checker
```

**2. Install dependencies**
```bash
pip3 install -r requirements.txt
```

### Requirements

```
aiohttp
dnspython
beautifulsoup4
colorama
```

> Python 3.8 or higher is required for `asyncio.run()`.

---

## Usage

### Scan from a file
```bash
python3 substatus.py -f subs.txt
```

### Scan inline subdomains
```bash
python3 substatus.py -s example.com api.example.com admin.example.com
```

### Show only live hosts
```bash
python3 substatus.py -f subs.txt --live-only
```

### Export to specific paths
```bash
python3 substatus.py -f subs.txt -oj results.json -oc results.csv
```

### High-speed scan with more threads
```bash
python3 substatus.py -f subs.txt -t 100
```

---

## Flags

| Flag | Long Form | Description |
|------|-----------|-------------|
| `-f` | `--file` | Path to a line-separated subdomain file |
| `-s` | `--subdomains` | Space-separated subdomains from the CLI |
| `-t` | `--threads` | Max concurrent connections (default: `50`) |
| `-oj` | `--output-json` | Export results to JSON (e.g. `results.json`) |
| `-oc` | `--output-csv` | Export results to CSV (e.g. `results.csv`) |
| `-l` | `--live-only` | Only print live (non-DOWN) hosts to terminal |

> If no `-oj` or `-oc` flags are provided, SubStatus auto-exports both formats with a timestamp filename.

---

## Output Fields

Every result row — both in the terminal and in exported files — contains:

| Field | Description |
|-------|-------------|
| `url` | Final URL after redirects |
| `status` | HTTP response code or `DOWN` |
| `time` | Response latency in seconds |
| `ip` | Resolved A record (IPv4) |
| `cname` | Resolved CNAME record (if present) |
| `title` | HTML `<title>` tag content |
| `tech` | Detected server technologies |

### JSON export sample

```json
[
  {
    "url": "https://shop.example.com",
    "status": 200,
    "time": "0.187s",
    "title": "Example Shop — Home",
    "tech": "Cloudflare, Nginx",
    "ip": "93.184.216.34",
    "cname": "N/A"
  }
]
```

---

## Color Guide

**Status codes**

| Color | Meaning |
|-------|---------|
| 🟢 Bright green | 2xx — Success |
| 🔵 Cyan | 3xx — Redirect |
| 🟡 Yellow | 401 / 403 — Auth / Forbidden |
| 🟡 Dim yellow | Other 4xx — Client error |
| 🔴 Red | 5xx — Server error |
| 🔴 Bright red | DOWN — Unreachable |

**Response time**

| Color | Range |
|-------|-------|
| 🟢 Green | < 0.3s |
| 🟡 Yellow | 0.3s – 0.8s |
| 🔴 Red | > 0.8s |

---

## Reconnaissance Workflow

SubStatus is designed to plug directly into the output of any subdomain enumeration tool:

```bash
# Step 1 — enumerate subdomains
subfinder -d example.com -o subs.txt

# Step 2 — check live status, export results
python3 substatus.py -f subs.txt --live-only -oj live.json -oc live.csv

# Step 3 — triage: look for 200s, 403s (login panels), 500s (broken internals)
```

---

## Detected Technologies

SubStatus fingerprints the following from response headers:

`Nginx` · `Apache` · `IIS` · `Cloudflare` · `OpenResty` · `LiteSpeed` · `Caddy` · `Gunicorn` · `uWSGI` · `Express.js` · `PHP` · `WordPress` · `Drupal` · `Joomla` · `Akamai` · `Fastly` · `AWS` · `Vercel` · `Netlify` · `Shopify`

Detection uses `Server`, `X-Powered-By`, `Via`, `X-CDN`, and `CF-Ray` headers.

---

## Comparison with httpstatus.io

| | SubStatus | httpstatus.io |
|---|---|---|
| Subdomain limit | **Unlimited** | 100 max |
| Execution | Local CLI | Web browser |
| Speed | Async, configurable concurrency | Sequential |
| DNS resolution | ✅ A + CNAME | ❌ |
| Tech detection | ✅ Header fingerprinting | ❌ |
| Title scraping | ✅ | ❌ |
| JSON / CSV export | ✅ Auto | ❌ Manual copy |
| Pipeline-friendly | ✅ Fully scriptable | ❌ |
| SSL tolerance | ✅ | Limited |
| Cost | Free / Open Source | Free (limited) |

---

## Project Structure

```
SubStatus/
├── substatus.py        # Main tool
├── requirements.txt    # Python dependencies
├── subs.txt            # Example subdomain input file
└── README.md
```

---

## Disclaimer

This tool is intended for **educational purposes and authorized security testing only**. Do not scan or perform reconnaissance on systems without explicit written permission from the asset owner. The author holds no liability for misuse or damage caused by this tool.

---

## Author

**Yahya Ibrahim** — [@yahyaibr](https://github.com/yahyaibr)

## License

Released under the [MIT License](LICENSE).
