# ═══════════════════════════════════════════════════════
#  test_scanner.py — Automated Unit & Integration Tests
# ═══════════════════════════════════════════════════════

import unittest
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from pathlib import Path

from core.session import build_session
from core.waf import WAFGuard
from core.scanner import Scanner
from core.payloads import generate_payloads
from core.reporter import generate_html_report
from pathscan import Logger


class MockVulnerableHandler(BaseHTTPRequestHandler):
    """Mock HTTP handler for testing detection and false-positive resilience."""
    def do_GET(self):
        p = urlparse(self.path)
        qs = parse_qs(p.query)

        if p.path == "/clean":
            # Clean endpoint: returns 200 for normal, 404 for traversals
            page = qs.get("page", [""])[0]
            if ".." in page or "/" in page:
                self.send_response(404)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html><body><h1>404 Not Found</h1></body></html>")
            else:
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html><body><h1>Clean Page</h1><p>Welcome</p></body></html>")

        elif p.path == "/vuln":
            # Vulnerable endpoint: leaks /etc/passwd on traversal
            file_param = qs.get("file", [""])[0]
            if "etc/passwd" in file_param or "etc%2fpasswd" in file_param:
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
            else:
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html><body><h1>About Page</h1></body></html>")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # Quiet during automated test runs


class TestScannerIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = 19123
        cls.server = HTTPServer(("127.0.0.1", cls.port), MockVulnerableHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.3)

        cls.config = {
            "target": {"seed_url": f"http://127.0.0.1:{cls.port}/", "scope": ["127.0.0.1"]},
            "session": {"headers": {}, "cookies": {}, "proxy": {}},
            "ssl": {"verify": False, "ca_bundle": None},
            "scanner": {"threads": 4, "timeout": 5, "delay": 0, "payload_limit": 50, "post_limit_per_form": 10},
            "waf": {"enabled": False, "block_codes": [403], "signatures": [], "backoff_seconds": 1, "max_retries": 3},
            "output": {"directory": "output", "json": True, "text": True}
        }
        cls.session = build_session(cls.config)
        cls.waf = WAFGuard(cls.config)
        cls.logger = Logger(verbose=False)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_clean_endpoint_no_false_positives(self):
        """Verifies that non-vulnerable endpoints returning 404/500 never trigger false positive findings."""
        payloads = ["../../../etc/passwd", "../../../../etc/passwd", "/etc/passwd", "win.ini"]
        scanner = Scanner(self.session, self.config, self.waf, payloads, self.logger, threads=2)
        clean_url = f"http://127.0.0.1:{self.port}/clean?page=home"
        scanner.scan_url(clean_url)
        self.assertEqual(len(scanner.findings), 0, "Clean endpoint must yield 0 findings.")

    def test_vulnerable_endpoint_detected(self):
        """Verifies that true vulnerabilities are accurately identified and signature matched."""
        payloads = ["../../../etc/passwd", "../../../../etc/passwd"]
        scanner = Scanner(self.session, self.config, self.waf, payloads, self.logger, threads=2)
        vuln_url = f"http://127.0.0.1:{self.port}/vuln?file=about"
        scanner.scan_url(vuln_url)
        self.assertGreaterEqual(len(scanner.findings), 1, "Vulnerable endpoint must be detected.")
        finding = scanner.findings[0]
        self.assertEqual(finding["param"], "file")
        sig_names = [s[0] for s in finding["signatures"]]
        self.assertIn("linux_passwd", sig_names)

    def test_html_report_generation(self):
        """Verifies HTML report compiles valid HTML containing expected badges and metrics."""
        mock_findings = [{
            "url": "http://example.com/view?file=../../../etc/passwd",
            "method": "GET",
            "param": "file",
            "payload": "../../../etc/passwd",
            "status_code": 200,
            "length_diff": 45,
            "signatures": [("linux_passwd", "critical", "Read /etc/passwd — system users disclosure")]
        }]
        html_output = generate_html_report(self.config, mock_findings, tested_count=10)
        self.assertIn("PathScan v3.0 — Audit Report", html_output)
        self.assertIn("CRITICAL", html_output)
        self.assertIn("linux_passwd", html_output)
        self.assertIn("Remediation & Defensive Recommendations", html_output)


if __name__ == "__main__":
    unittest.main()
