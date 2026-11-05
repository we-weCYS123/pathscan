# ═══════════════════════════════════════════════════════
#  waf.py — WAF Detection & Automatic Backoff
# ═══════════════════════════════════════════════════════

import time


class WAFGuard:
    def __init__(self, config):
        self.cfg = config.get("waf", {})
        self.block_codes = set(self.cfg.get("block_codes", [403, 406, 429, 503]))
        self.signatures = [s.lower() for s in self.cfg.get("signatures", [])]
        self.backoff = self.cfg.get("backoff_seconds", 10)
        self.max_retries = self.cfg.get("max_retries", 3)
        self.consecutive_blocks = 0

    def is_blocked(self, response):
        """Returns True if the response indicates a WAF block / rate-limit."""
        if not self.cfg.get("enabled", True) or response is None:
            return False

        # 429 always indicates rate limiting or block
        if response.status_code == 429:
            return True

        # Check WAF signatures in body
        body = (response.text or "").lower()
        if any(sig in body for sig in self.signatures):
            return True

        # Check WAF signatures in server headers
        headers_str = " ".join(f"{k}:{v}" for k, v in response.headers.items()).lower()
        if any(sig in headers_str for sig in ("cloudflare", "incapsula", "imperva", "akamai")):
            if response.status_code in self.block_codes:
                return True

        # Check block status codes
        if response.status_code in self.block_codes:
            return True

        return False

    def handle_block(self):
        """Exponential backoff when repeatedly blocked."""
        self.consecutive_blocks += 1
        if self.consecutive_blocks >= self.max_retries:
            wait = self.backoff * self.consecutive_blocks
            print(f"\n  [!] WAF block detected {self.consecutive_blocks} times — backing off for {wait}s...")
            time.sleep(wait)
            self.consecutive_blocks = 0

    def reset(self):
        self.consecutive_blocks = 0
