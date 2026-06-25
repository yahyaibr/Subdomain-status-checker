
# SubStatus 🔎
[![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)


A fast and lightweight Python command-line utility designed to check the HTTP/HTTPS status of multiple subdomains concurrently. 

`SubStatus` takes a list of subdomains and checks their live availability by sending optimized network requests, returning real-time response metrics. This tool is built specifically to streamline asset verification during security reconnaissance workflows following subdomain enumeration.

---

## Features 🚀

* ⚡ **Fast Concurrent Scanning:** Utilizes multi-threading (`ThreadPoolExecutor`) to scan hundreds of targets simultaneously.
* 🌐 **Dual Protocol Support:** Automatically probes both `HTTPS` and `HTTP` environments.
* 🔄 **Smart Redirects:** Follows HTTP redirection schemes automatically to find the final landing destination.
* 🔐 **SSL Tolerance:** Bypasses intrusive warning alerts to accurately report targets with broken, self-signed, or expired SSL certificates.
* 📄 **File Input Streaming:** Effortlessly parses line-by-line flat text lists of domains.
* ⌨️ **Direct CLI Input:** Allows quick checking via space-separated inline arguments.
* ⏱️ **Performance Metrics:** Measures and tracks precise HTTP response latency.
* 📊 **Live Progress Visualizer:** Integrates a real-time progress bar powered by `tqdm`.

---

## Project Structure

```text
SubStatus/
├── substatus.py
├── requirements.txt
├── subs.txt
└── README.md

```

---

## Installation

1. **Clone the repository:**
```bash
git clone [https://github.com/yahyaibr/SubStatus.git](https://github.com/yahyaibr/SubStatus.git)

```


2. **Enter the directory:**
```bash
cd SubStatus

```


3. **Install dependencies:**
```bash
pip3 install -r requirements.txt

```



### Requirements

* Python 3.x
* `requests`
* `tqdm`

---

## Usage

### Options & Flags

| Option | Long Flag | Description |
| --- | --- | --- |
| `-f` | `--file` | Path to a line-separated text file containing subdomains |
| `-s` | `--subdomains` | Direct space-separated list of subdomains from the CLI |
| `-t` | `--threads` | Number of concurrent worker threads (Default: `20`) |

---

### Examples

#### 1. Scan subdomains from a file

Create a target file (e.g., `subs.txt`):

```text
example.com
api.example.com
admin.example.com
dev.example.com

```

Run the script pointing to your file:

```bash
python3 substatus.py -f subs.txt

```

**Example Output:**

```text
[*] Scanning 4 targets using 20 threads...

URL                                           STATUS     RESPONSE TIME
----------------------------------------------------------------------

======================================================================
[https://example.com](https://example.com)                           200        0.321s
[https://api.example.com](https://api.example.com)                       403        0.210s
[https://admin.example.com](https://admin.example.com)                     404        0.189s
dev.example.com                               DOWN       -
======================================================================

```

#### 2. Scan directly from the command line

```bash
python3 substatus.py -s example.com api.example.com dev.example.com

```

#### 3. Run high-speed scans using custom threads

```bash
python3 substatus.py -f subs.txt -t 50

```

---

## Reconnaissance Workflow Example

Easily integrate `SubStatus` into your wider automation or manual discovery pipelines:

```bash
# Step 1: Review your gathered subdomains
cat subdomains.txt

# Step 2: Feed the discovered targets directly into SubStatus
python3 substatus.py -f subdomains.txt

# Step 3: Quickly isolate live web servers, open panels, and forbidden paths!

```

---

## Roadmap 🛠️

Future structural and feature milestones planned for development:

* [ ] Export findings natively to structured `JSON` formatted sheets
* [ ] Export results to comma-separated value tables (`CSV`)
* [ ] Automated HTML Title tag parsing and scraping
* [ ] Server technology identification headers signature matching (Wappalyzer-lite style)
* [ ] Inline DNS/IP mapping resolution metrics
* [ ] Colored terminal outputs for cleaner scanning visibility
* [ ] Fully asynchronous structural core conversion using `aiohttp`

---

## Disclaimer ⚠️

This tool is created for educational purposes and authorized security testing workflows only. Do not scan or perform reconnaissance on systems without explicit prior permission from the asset owners. The author holds no liability for misuse or damage caused by this utility.

---

## Author

**Yahya Ibrahim** * GitHub: [@yahyaibr](https://github.com/yahyaibr)

## License

This project is open-source and released under the [MIT License](https://www.google.com/search?q=LICENSE).

```

```
