#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════
#  pathscan.py — نقطة الدخول
#  شغّل: python pathscan.py -u "http://target.com/"
# ═══════════════════════════════════════════════════════

import sys
import json
import time
import argparse
from pathlib import Path

import yaml
from colorama import init as color_init, Fore

from core.session  import build_session
from core.payloads import generate_payloads
from core.waf      import WAFGuard
from core.crawler  import Crawler
from core.scanner  import Scanner
from core.reporter import generate_html_report

color_init(autoreset=True)


# ─── Logger ───
class Logger:
    def __init__(self, verbose=False):
        self.verbose = verbose

    def info(self, msg):
        print(f"{Fore.CYAN}[*]{Fore.RESET} {msg}")

    def debug(self, msg):
        if self.verbose:
            print(f"{Fore.MAGENTA}[~]{Fore.RESET} {msg}")

    def finding(self, f):
        m = f.get("method", "GET")
        print(f"\n{Fore.GREEN}[+] Confirmed Finding! ({m}){Fore.RESET}")
        print(f"    URL        : {f['url']}")
        print(f"    Parameter  : {f['param']}")
        print(f"    Payload    : {f['payload']}")
        print(f"    Status     : {f['status_code']}  |  Diff: {f['length_diff']}B")
        for name, sev, desc in f.get("signatures", []):
            color = Fore.RED if sev == "critical" else (Fore.YELLOW if sev == "high" else Fore.BLUE)
            print(f"    Signature  : {color}{name}{Fore.RESET} [{sev}] — {desc}")

    def progress(self, stage, cur, total, extra=""):
        pct = int(cur * 100 / max(total, 1))
        bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
        text = f"\r\033[K  [{stage}] {bar} {cur}/{total} {extra[:45]}"
        print(text, end="", flush=True)


# ─── Configuration Loader ───
def load_config(path):
    p = Path(path)
    if not p.is_file():
        print(f"{Fore.RED}[!] Configuration file not found: {path}{Fore.RESET}")
        sys.exit(1)
    with open(p, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
        return cfg or {}


# ─── Save Results ───
def save_results(config, findings, tested_count=0, custom_html=None):
    out = Path(config.get("output", {}).get("directory", "output"))
    out.mkdir(exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")

    # JSON export
    if config.get("output", {}).get("json", True):
        p = out / f"findings_{ts}.json"
        with open(p, "w", encoding="utf-8") as f:
            json.dump(findings, f, indent=2, ensure_ascii=False)
        print(f"\n{Fore.CYAN}[*]{Fore.RESET} JSON   : {p}")

    # Plain text export
    if config.get("output", {}).get("text", True):
        p = out / f"findings_{ts}.txt"
        with open(p, "w", encoding="utf-8") as f:
            f.write("# METHOD\tURL\tPARAM\tPAYLOAD\tSTATUS\tDIFF\tSIGNATURES\n")
            for x in findings:
                sigs = ",".join(s[0] for s in x.get("signatures", []))
                f.write(f"{x['method']}\t{x['url']}\t{x['param']}\t"
                        f"{x['payload']}\t{x['status_code']}\t{x['length_diff']}\t{sigs}\n")
        print(f"{Fore.CYAN}[*]{Fore.RESET} TXT    : {p}")

    # HTML Interactive Dashboard export
    html_report_path = Path(custom_html) if custom_html else (out / f"report_{ts}.html")
    html_content = generate_html_report(config, findings, tested_count)
    with open(html_report_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"{Fore.CYAN}[*]{Fore.RESET} HTML   : {html_report_path}")


# ─── Main Entry Point ───
def main():
    ap = argparse.ArgumentParser(description="PathScan v3.0 — Path Traversal & Sensitive File Disclosure Scanner")
    ap.add_argument("-c", "--config", default="config.yaml", help="Path to YAML configuration file")
    ap.add_argument("-u", "--url", help="Target URL (overrides seed_url in config)")
    ap.add_argument("-t", "--threads", type=int, help="Number of concurrent worker threads (default: 5)")
    ap.add_argument("-p", "--proxy", help="HTTP proxy, e.g. 'http://127.0.0.1:8080'")
    ap.add_argument("--cookie", help="Cookie string, e.g. 'PHPSESSID=abc123'")
    ap.add_argument("-o", "--output", help="Output directory for reports")
    ap.add_argument("--html", help="Custom output filepath for HTML dashboard report")
    ap.add_argument("-v", "--verbose", action="store_true", help="Enable verbose debug logging")
    ap.add_argument("--no-crawl", action="store_true", help="Scan target directly without crawling")
    ap.add_argument("--urls-file", help="File with list of URLs (one per line) for batch scanning")
    ap.add_argument("--payloads-file", help="Custom text file with test cases/payloads (one per line)")
    args = ap.parse_args()

    cfg = load_config(args.config)

    # Command line overrides
    if args.url:
        from urllib.parse import urlparse
        raw_url = args.url.strip()
        if not raw_url.startswith(("http://", "https://")):
            raw_url = f"http://{raw_url}"
        cfg.setdefault("target", {})["seed_url"] = raw_url

        # Extract hostname and update scope
        p_url = urlparse(raw_url)
        host = p_url.netloc
        domain = p_url.hostname or host
        cfg["target"]["scope"] = list(set([host, domain])) if host else []

    if args.proxy:
        cfg.setdefault("session", {})["proxy"] = args.proxy

    if args.output:
        cfg.setdefault("output", {})["directory"] = args.output

    if args.verbose:
        cfg.setdefault("logging", {})["level"] = "DEBUG"

    if args.threads:
        cfg.setdefault("scanner", {})["threads"] = args.threads

    if args.cookie:
        cookies = cfg.get("session", {}).get("cookies") or {}
        for part in args.cookie.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                cookies[k.strip()] = v.strip()
        cfg.setdefault("session", {})["cookies"] = cookies

    log = Logger(verbose=cfg.get("logging", {}).get("level") == "DEBUG")
    target_seed = cfg.get("target", {}).get("seed_url", "N/A")
    threads_count = cfg.get("scanner", {}).get("threads", 5)

    print(f"{Fore.CYAN}{'═'*60}")
    print(f"  PathScan v3.0 — Advanced Path Traversal Scanner")
    print(f"  Target: {target_seed}")
    print(f"  Threads: {threads_count}")
    print(f"{'═'*60}{Fore.RESET}\n")

    # 1) Session & WAF Guard
    sess = build_session(cfg)
    waf = WAFGuard(cfg)

    # 2) Load or Generate Payloads
    if args.payloads_file:
        p_path = Path(args.payloads_file)
        if not p_path.is_file():
            print(f"{Fore.RED}[!] Payloads file not found: {args.payloads_file}{Fore.RESET}")
            sys.exit(1)
        with open(p_path, "r", encoding="utf-8") as f:
            payloads = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
        log.info(f"Loaded {len(payloads)} custom test payloads from {args.payloads_file}")
    else:
        payloads = generate_payloads()
        limit = cfg.get("scanner", {}).get("payload_limit", 150)
        log.info(f"Generated payloads: {len(payloads)} (test limit: {limit})")

    # 3) Crawling / Load URLs
    if args.urls_file:
        p_file = Path(args.urls_file)
        if not p_file.is_file():
            print(f"{Fore.RED}[!] URLs file not found: {args.urls_file}{Fore.RESET}")
            return
        with open(p_file, "r", encoding="utf-8") as f:
            urls = [l.strip() for l in f if l.strip()]
        log.info(f"Loaded {len(urls)} URLs from file")
        forms = []
    elif args.no_crawl:
        urls = [target_seed]
        forms = []
        log.info("Skipping crawl — testing target URL directly")
    else:
        crawler = Crawler(sess, cfg, waf, log)
        urls = crawler.crawl()
        forms = crawler.forms

    # 4) Filter Scanable URLs
    scanable = [u for u in urls if "?" in u and "=" in u.split("?", 1)[1]]
    log.info(f"Scanable GET URLs found: {len(scanable)}")

    if not scanable and not forms:
        print(f"{Fore.YELLOW}[!] Nothing to scan — ensure target URLs include parameters (e.g., ?param=val) or POST forms exist.{Fore.RESET}")
        return

    # 5) Scanning (Multi-Threaded)
    scanner = Scanner(sess, cfg, waf, payloads, log, threads=threads_count)
    if scanable:
        scanner.scan_all(scanable)
    if cfg.get("scanner", {}).get("test_post", True) and forms:
        scanner.scan_forms(forms)
    findings = scanner.summary()

    # 6) Reporting
    print(f"\n{Fore.CYAN}{'═'*60}")
    print(f"  Final Results: {len(findings)} confirmed finding(s)")
    print(f"{'═'*60}{Fore.RESET}")
    save_results(cfg, findings, tested_count=scanner.tested, custom_html=args.html)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user.{Fore.RESET}")
        sys.exit(0)
