#!/usr/bin/env python3
"""
SubStatus  — Fast async subdomain HTTP status checker for reconnaissance.
Features: async scanning, colored output, JSON/CSV export, HTML title parsing,
          server tech detection, DNS/IP resolution.
Author: Yahya Ibrahim | github.com/yahyaibr
"""

import argparse
import asyncio
import csv
import json
import socket
import ssl
import sys
import time
from datetime import datetime
from urllib.parse import urlparse

import aiohttp
import dns.resolver
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

init(autoreset=True)



def color_status(code):
    if code == "DOWN":
        return f"{Fore.RED}{Style.BRIGHT}DOWN{Style.RESET_ALL}"
    try:
        c = int(code)
        if 200 <= c < 300:
            return f"{Fore.GREEN}{Style.BRIGHT}{code}{Style.RESET_ALL}"
        elif 300 <= c < 400:
            return f"{Fore.CYAN}{code}{Style.RESET_ALL}"
        elif c == 403 or c == 401:
            return f"{Fore.YELLOW}{code}{Style.RESET_ALL}"
        elif 400 <= c < 500:
            return f"{Fore.YELLOW}{Style.DIM}{code}{Style.RESET_ALL}"
        elif 500 <= c < 600:
            return f"{Fore.RED}{code}{Style.RESET_ALL}"
    except ValueError:
        pass
    return str(code)

def color_url(url):
    return f"{Fore.BLUE}{Style.BRIGHT}{url}{Style.RESET_ALL}"

def color_time(t):
    if t == "-":
        return f"{Fore.RED}-{Style.RESET_ALL}"
    try:
        val = float(t.replace("s", ""))
        if val < 0.3:
            return f"{Fore.GREEN}{t}{Style.RESET_ALL}"
        elif val < 0.8:
            return f"{Fore.YELLOW}{t}{Style.RESET_ALL}"
        else:
            return f"{Fore.RED}{t}{Style.RESET_ALL}"
    except ValueError:
        return t

def banner():
    print(f"""
{Fore.BLUE}{Style.BRIGHT}
  ███████╗██╗   ██╗██████╗ ███████╗████████╗ █████╗ ████████╗██╗   ██╗███████╗
  ██╔════╝██║   ██║██╔══██╗██╔════╝╚══██╔══╝██╔══██╗╚══██╔══╝██║   ██║██╔════╝
  ███████╗██║   ██║██████╔╝███████╗   ██║   ███████║   ██║   ██║   ██║███████╗
  ╚════██║██║   ██║██╔══██╗╚════██║   ██║   ██╔══██║   ██║   ██║   ██║╚════██║
  ███████║╚██████╔╝██████╔╝███████║   ██║   ██║  ██║   ██║   ╚██████╔╝███████║
  ╚══════╝ ╚═════╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚══════╝
{Style.RESET_ALL}
  {Fore.WHITE} |  Fast Async Subdomain Recon  |  {Fore.BLUE}github.com/yahyaibr{Style.RESET_ALL}
  {Style.DIM}──────────────────────────────────────────────────────────────────────{Style.RESET_ALL}
""")


def resolve_dns(subdomain):
    """Return (ip, cname_or_None) for the given hostname."""
    hostname = subdomain.strip()
  
    for prefix in ("https://", "http://"):
        if hostname.startswith(prefix):
            hostname = hostname[len(prefix):]
    hostname = hostname.split("/")[0]

    ip_addr = None
    cname   = None

    try:
        answers = dns.resolver.resolve(hostname, "A")
        ip_addr = answers[0].to_text()
    except Exception:
        pass

    try:
        cname_ans = dns.resolver.resolve(hostname, "CNAME")
        cname = cname_ans[0].target.to_text().rstrip(".")
    except Exception:
        pass

    return ip_addr, cname



SERVER_SIGNATURES = {
    "nginx":           "Nginx",
    "apache":          "Apache",
    "microsoft-iis":   "IIS",
    "cloudflare":      "Cloudflare",
    "openresty":       "OpenResty",
    "litespeed":       "LiteSpeed",
    "caddy":           "Caddy",
    "gunicorn":        "Gunicorn",
    "uwsgi":           "uWSGI",
    "express":         "Express.js",
    "php":             "PHP",
    "wordpress":       "WordPress",
    "drupal":          "Drupal",
    "joomla":          "Joomla",
    "akamai":          "Akamai",
    "fastly":          "Fastly",
    "aws":             "AWS",
    "vercel":          "Vercel",
    "netlify":         "Netlify",
    "shopify":         "Shopify",
    "x-powered-by":    None,  
}

def detect_tech(headers: dict) -> str:
    """Parse response headers and return detected technology stack."""
    tech = set()

    server = headers.get("Server", "").lower()
    powered = headers.get("X-Powered-By", "")
    via     = headers.get("Via", "").lower()
    cdn     = headers.get("X-CDN", "").lower()

    for sig, label in SERVER_SIGNATURES.items():
        if sig in server:
            tech.add(label or sig)
        if sig in via:
            tech.add(label or sig)
        if sig in cdn:
            tech.add(label or sig)

    if powered:
        tech.add(powered.split("/")[0].strip())


    if "cf-ray" in [h.lower() for h in headers]:
        tech.add("Cloudflare")

    return ", ".join(sorted(tech)) if tech else "Unknown"



async def check_subdomain(session: aiohttp.ClientSession, subdomain: str) -> dict:
    subdomain = subdomain.strip()
    if not subdomain:
        return None

    hostname = subdomain
    for prefix in ("https://", "http://"):
        if subdomain.startswith(prefix):
            hostname = subdomain[len(prefix):]
            break


    loop = asyncio.get_event_loop()
    ip_addr, cname = await loop.run_in_executor(None, resolve_dns, hostname)

    protocols = ["https", "http"]
    for proto in protocols:
        url = f"{proto}://{hostname}"
        try:
            start = time.perf_counter()
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=7),
                allow_redirects=True,
                ssl=False,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            ) as resp:
                elapsed = time.perf_counter() - start
                body    = await resp.text(errors="ignore")

              
                title = "N/A"
                try:
                    soup  = BeautifulSoup(body, "html.parser")
                    tag   = soup.find("title")
                    if tag and tag.string:
                        title = tag.string.strip()[:80]
                except Exception:
                    pass

                
                tech = detect_tech(dict(resp.headers))

                return {
                    "url":      str(resp.url),
                    "status":   resp.status,
                    "time":     f"{elapsed:.3f}s",
                    "title":    title,
                    "tech":     tech,
                    "ip":       ip_addr or "N/A",
                    "cname":    cname or "N/A",
                }

        except (aiohttp.ClientError, asyncio.TimeoutError, ssl.SSLError, OSError):
            continue

    return {
        "url":    hostname,
        "status": "DOWN",
        "time":   "-",
        "title":  "N/A",
        "tech":   "N/A",
        "ip":     ip_addr or "N/A",
        "cname":  cname or "N/A",
    }



COL_URL    = 45
COL_STATUS = 8
COL_TIME   = 10
COL_IP     = 18
COL_TITLE  = 40
COL_TECH   = 20

def print_header():
    sep = f"{Style.DIM}{'─'*140}{Style.RESET_ALL}"
    header = (
        f"{Fore.WHITE}{Style.BRIGHT}"
        f"{'URL':<{COL_URL}} "
        f"{'STATUS':<{COL_STATUS}} "
        f"{'TIME':<{COL_TIME}} "
        f"{'IP':<{COL_IP}} "
        f"{'TITLE':<{COL_TITLE}} "
        f"{'TECH':<{COL_TECH}}"
        f"{Style.RESET_ALL}"
    )
    print(sep)
    print(header)
    print(sep)

def print_result(r: dict):
    status_str = color_status(str(r["status"]))
    url_str    = color_url(r["url"][:COL_URL])
    time_str   = color_time(r["time"])
    ip_str     = f"{Fore.CYAN}{r['ip'][:COL_IP]}{Style.RESET_ALL}"
    title_str  = f"{Style.DIM}{r['title'][:COL_TITLE]}{Style.RESET_ALL}"
    tech_str   = f"{Fore.MAGENTA}{r['tech'][:COL_TECH]}{Style.RESET_ALL}"


    def pad(s, raw, width):
        ansi_overhead = len(s) - len(raw)
        return s.ljust(width + ansi_overhead)

    line = (
        pad(url_str,    r["url"][:COL_URL],           COL_URL)    + " " +
        pad(status_str, str(r["status"])[:COL_STATUS], COL_STATUS) + " " +
        pad(time_str,   r["time"][:COL_TIME],          COL_TIME)   + " " +
        pad(ip_str,     r["ip"][:COL_IP],              COL_IP)     + " " +
        pad(title_str,  r["title"][:COL_TITLE],        COL_TITLE)  + " " +
        tech_str
    )
    print(line)

def export_json(results: list, path: str):
    with open(path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"{Fore.GREEN}[+] JSON saved → {path}{Style.RESET_ALL}")

def export_csv(results: list, path: str):
    if not results:
        return
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
    print(f"{Fore.GREEN}[+] CSV  saved → {path}{Style.RESET_ALL}")



def print_summary(results: list, elapsed: float):
    total  = len(results)
    live   = [r for r in results if r["status"] != "DOWN"]
    down   = total - len(live)
    codes  = {}
    for r in live:
        codes[str(r["status"])] = codes.get(str(r["status"]), 0) + 1

    sep = f"{Style.DIM}{'═'*140}{Style.RESET_ALL}"
    print(f"\n{sep}")
    print(f"{Fore.WHITE}{Style.BRIGHT}  SCAN SUMMARY{Style.RESET_ALL}")
    print(sep)
    print(f"  Total targets : {Fore.WHITE}{Style.BRIGHT}{total}{Style.RESET_ALL}")
    print(f"  Live hosts    : {Fore.GREEN}{Style.BRIGHT}{len(live)}{Style.RESET_ALL}  "
          f"{Style.DIM}({len(live)/total*100:.1f}%){Style.RESET_ALL}")
    print(f"  Down          : {Fore.RED}{down}{Style.RESET_ALL}  "
          f"{Style.DIM}({down/total*100:.1f}%){Style.RESET_ALL}")
    print(f"  Scan time     : {Fore.CYAN}{elapsed:.2f}s{Style.RESET_ALL}")
    if codes:
        print(f"  Status codes  : ", end="")
        parts = []
        for code, count in sorted(codes.items()):
            parts.append(f"{color_status(code)} ×{count}")
        print("  ".join(parts))
    print(sep + "\n")



async def run(subdomains: list, threads: int, output_json: str, output_csv: str, live_only: bool):
    connector = aiohttp.TCPConnector(limit=threads, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:

        print_header()
        results   = []
        semaphore = asyncio.Semaphore(threads)

        async def bounded(sub):
            async with semaphore:
                return await check_subdomain(session, sub)

        tasks   = [bounded(s) for s in subdomains]
        start_t = time.perf_counter()

        for coro in asyncio.as_completed(tasks):
            r = await coro
            if r:
                results.append(r)
                if live_only and r["status"] == "DOWN":
                    continue
                print_result(r)

        elapsed = time.perf_counter() - start_t

    print_summary(results, elapsed)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    if output_json:
        export_json(results, output_json)
    if output_csv:
        export_csv(results, output_csv)


    if not output_json and not output_csv:
        default_json = f"substatus_{ts}.json"
        default_csv  = f"substatus_{ts}.csv"
        export_json(results, default_json)
        export_csv(results,  default_csv)



def main():
    banner()

    parser = argparse.ArgumentParser(
        description="SubStatus — Fast async subdomain HTTP status checker",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-f",  "--file",        help="Path to text file containing subdomains (one per line)")
    parser.add_argument("-s",  "--subdomains",  nargs="+", help="Space-separated list of subdomains")
    parser.add_argument("-t",  "--threads",     type=int, default=50, help="Max concurrent connections (default: 50)")
    parser.add_argument("-oj", "--output-json", help="Export results to JSON (e.g. results.json)")
    parser.add_argument("-oc", "--output-csv",  help="Export results to CSV  (e.g. results.csv)")
    parser.add_argument("-l",  "--live-only",   action="store_true", help="Only display live (non-DOWN) hosts")
    args = parser.parse_args()

    if args.file:
        try:
            with open(args.file, "r") as f:
                subdomains = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            parser.error(f"File not found: {args.file}")
    elif args.subdomains:
        subdomains = args.subdomains
    else:
        parser.error("Provide -f <file> or -s <subdomain1> <subdomain2> ...")

    print(f"  {Fore.WHITE}[*] Scanning {Fore.CYAN}{Style.BRIGHT}{len(subdomains)}{Style.RESET_ALL} "
          f"{Fore.WHITE}targets  |  threads: {Fore.CYAN}{args.threads}{Style.RESET_ALL}\n")

    try:
        asyncio.run(run(
            subdomains   = subdomains,
            threads      = args.threads,
            output_json  = args.output_json,
            output_csv   = args.output_csv,
            live_only    = args.live_only,
        ))
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[-] Scan aborted by user.{Style.RESET_ALL}")
        sys.exit(0)

if __name__ == "__main__":
    main()
