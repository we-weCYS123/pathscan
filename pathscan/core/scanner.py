# ═══════════════════════════════════════════════════════
#  scanner.py — High-Performance Multi-Threaded Scan Engine
#  Compares responses against baseline to eliminate false positives
# ═══════════════════════════════════════════════════════

import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urlunparse

from .signatures import SIGNATURES


class Scanner:
    def __init__(self, session, config, waf_guard, payloads, logger, threads=None):
        self.sess = session
        self.cfg = config
        self.waf = waf_guard
        limit = self.cfg.get("scanner", {}).get("payload_limit", 150)
        self.payloads = payloads[:limit]
        self.log = logger
        self.threads = threads or self.cfg.get("scanner", {}).get("threads", 5)
        self.findings = []
        self.tested = 0
        self._lock = threading.Lock()

    # ─── URL Builder Preserving Raw Payload Encodings ───
    def _build_url(self, url, param, new_value):
        p = urlparse(url)
        parts = []
        for part in p.query.split("&"):
            if "=" in part:
                k, _ = part.split("=", 1)
            else:
                k = part
            if k == param:
                parts.append(f"{k}={new_value}")
            else:
                parts.append(part)
        return urlunparse(p._replace(query="&".join(parts)))

    # ─── Baseline Request ───
    def _get_baseline(self, url, method="GET", data=None):
        try:
            timeout = self.cfg.get("scanner", {}).get("timeout", 15)
            if method == "POST":
                r = self.sess.post(url, data=data,
                                   timeout=timeout,
                                   allow_redirects=False)
            else:
                r = self.sess.get(url,
                                  timeout=timeout,
                                  allow_redirects=False)
            body = r.text or ""
            return len(body), r.status_code, body
        except Exception:
            return 0, 0, ""

    # ─── Signature Matching Against Baseline ───
    def _check_signatures(self, body, base_body=""):
        hits = []
        body_lower = body.lower()
        base_lower = base_body.lower() if base_body else ""

        for name, meta in SIGNATURES.items():
            for pat in meta["patterns"]:
                pat_lower = pat.lower()
                # Signature must exist in the tested response and NOT in the baseline response
                if pat_lower in body_lower:
                    if not base_lower or pat_lower not in base_lower:
                        hits.append((name, meta["severity"], meta["description"]))
                        break
        return hits

    # ─── Record Finding (Thread-safe) ───
    def _record(self, url, method, param, payload, code, diff, sigs):
        with self._lock:
            f = {
                "url": url, "method": method, "param": param,
                "payload": payload, "status_code": code,
                "length_diff": diff, "signatures": sigs,
            }
            self.findings.append(f)
            self.log.finding(f)

    # ─── Single GET Test Worker ───
    def _test_get_payload(self, url, param, payload, base_len, base_body, timeout, stop_event):
        if stop_event.is_set():
            return None
        test_url = self._build_url(url, param, payload)
        try:
            r = self.sess.get(test_url, timeout=timeout, allow_redirects=False)
            with self._lock:
                self.tested += 1

            if self.waf.is_blocked(r):
                self.waf.handle_block()
                return None
            self.waf.reset()

            body = r.text or ""
            sigs = self._check_signatures(body, base_body)
            diff = abs(len(body) - base_len)

            if sigs:
                self._record(test_url, "GET", param, payload, r.status_code, diff, sigs)
                stop_event.set()
                return True
        except Exception as e:
            self.log.debug(f"GET error {test_url}: {e}")
        return False

    # ─── Multi-threaded GET Parameter Scan ───
    def scan_url(self, url):
        p = urlparse(url)
        params = [x.split("=", 1)[0] for x in p.query.split("&") if x]
        if not params:
            return

        base_len, base_code, base_body = self._get_baseline(url)
        delay = self.cfg.get("scanner", {}).get("delay", 0)
        timeout = self.cfg.get("scanner", {}).get("timeout", 15)

        for param in params:
            self.log.info(f"  └─ [GET] Testing parameter: {param} (Concurrency: {self.threads} threads)")
            stop_event = threading.Event()
            total = len(self.payloads)
            completed_count = 0

            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {
                    executor.submit(
                        self._test_get_payload, url, param, payload,
                        base_len, base_body, timeout, stop_event
                    ): payload for payload in self.payloads
                }

                for future in as_completed(futures):
                    completed_count += 1
                    payload = futures[future]
                    if completed_count % 10 == 0 or completed_count == total:
                        with self._lock:
                            self.log.progress("scan", completed_count, total, f"{param}: {payload[:20]}")
                    if stop_event.is_set():
                        # Parameter confirmed vulnerable, cancel remaining tasks
                        for f in futures:
                            f.cancel()
                        break
                    if delay:
                        time.sleep(delay)

            print()  # End progress line

    # ─── Single POST Test Worker ───
    def _test_post_payload(self, action, param, payload, base_data, base_len, base_body, timeout, stop_event):
        if stop_event.is_set():
            return None
        try:
            data = dict(base_data)
            data[param] = payload
            r = self.sess.post(action, data=data, timeout=timeout, allow_redirects=False)
            with self._lock:
                self.tested += 1

            if self.waf.is_blocked(r):
                self.waf.handle_block()
                return None
            self.waf.reset()

            body = r.text or ""
            sigs = self._check_signatures(body, base_body)
            diff = abs(len(body) - base_len)

            if sigs:
                self._record(action, "POST", param, payload, r.status_code, diff, sigs)
                stop_event.set()
                return True
        except Exception as e:
            self.log.debug(f"POST error {action}: {e}")
        return False

    # ─── Multi-threaded POST Form Scan ───
    def scan_post_form(self, form):
        action = form["action"]
        inputs = form["inputs"]
        base_data = {i["name"]: i["value"] for i in inputs}
        base_len, base_code, base_body = self._get_baseline(action, "POST", base_data)
        delay = self.cfg.get("scanner", {}).get("delay", 0)
        timeout = self.cfg.get("scanner", {}).get("timeout", 15)
        post_limit = self.cfg.get("scanner", {}).get("post_limit_per_form", 50)
        target_payloads = self.payloads[:post_limit]

        for inp in inputs:
            if inp.get("type") in ("submit", "button", "reset", "image"):
                continue
            param = inp["name"]
            self.log.info(f"  └─ [POST] Testing parameter: {param} (Concurrency: {self.threads} threads)")
            stop_event = threading.Event()
            total = len(target_payloads)
            completed_count = 0

            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {
                    executor.submit(
                        self._test_post_payload, action, param, payload,
                        base_data, base_len, base_body, timeout, stop_event
                    ): payload for payload in target_payloads
                }

                for future in as_completed(futures):
                    completed_count += 1
                    payload = futures[future]
                    if completed_count % 10 == 0 or completed_count == total:
                        with self._lock:
                            self.log.progress("scan", completed_count, total, f"{param}: {payload[:20]}")
                    if stop_event.is_set():
                        for f in futures:
                            f.cancel()
                        break
                    if delay:
                        time.sleep(delay)

            print()

    # ─── Full Scan Orchestrator ───
    def scan_all(self, urls):
        self.log.info(f"Starting scan on {len(urls)} GET URLs (Concurrency: {self.threads} threads)...")
        for i, u in enumerate(urls, 1):
            self.log.progress("urls", i, len(urls), u[:70])
            print()
            self.scan_url(u)

    def scan_forms(self, forms):
        if not forms:
            return
        self.log.info(f"Starting scan on {len(forms)} POST forms (Concurrency: {self.threads} threads)...")
        for i, f in enumerate(forms, 1):
            self.log.progress("forms", i, len(forms), f["action"][:70])
            print()
            if f.get("method") == "post":
                self.scan_post_form(f)

    def summary(self):
        self.log.info(f"Scan finished: {self.tested} requests sent, {len(self.findings)} confirmed findings")
        return self.findings
