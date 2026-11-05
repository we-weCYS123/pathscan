# ═══════════════════════════════════════════════════════
#  crawler.py — Web Crawler (HTML + JS + Forms + robots + sitemap)
# ═══════════════════════════════════════════════════════

import re
import time
from urllib.parse import urljoin, urlparse, urldefrag
from collections import deque

from bs4 import BeautifulSoup


class Crawler:
    def __init__(self, session, config, waf_guard, logger):
        self.sess = session
        self.cfg = config
        self.waf = waf_guard
        self.log = logger
        self.visited = set()
        self.forms = []          # Extracted POST forms
        self._seen_form_keys = set()

    # ─── Scope Validation ───
    def _in_scope(self, url):
        p = urlparse(url)
        if p.scheme not in ("http", "https"):
            return False
        host = (p.hostname or p.netloc).lower()
        scopes = self.cfg.get("target", {}).get("scope", [])
        for s in scopes:
            s_clean = s.lower().strip()
            # Check host with port
            if ":" in s_clean and p.netloc.lower() == s_clean:
                return True
            s_host = s_clean.split(":")[0]
            if host == s_host or host.endswith("." + s_host):
                return True
        return False

    def _excluded(self, url):
        low = url.lower()
        patterns = self.cfg.get("target", {}).get("exclude_patterns") or []
        return any(p.lower() in low for p in patterns)

    # ─── Link Extraction ───
    def _extract_links(self, base_url, html):
        links = set()
        soup = None
        try:
            soup = BeautifulSoup(html, "lxml")
        except Exception:
            try:
                soup = BeautifulSoup(html, "html.parser")
            except Exception:
                return links

        if not soup:
            return links

        for tag, attr in [
            ("a", "href"), ("link", "href"),
            ("script", "src"), ("img", "src"),
            ("form", "action"), ("iframe", "src"),
        ]:
            for el in soup.find_all(tag):
                v = el.get(attr)
                if v and isinstance(v, str):
                    v = v.strip()
                    if v and not v.startswith(("javascript:", "mailto:", "tel:", "#")):
                        links.add(urljoin(base_url, v))

        # من JavaScript
        if self.cfg.get("crawler", {}).get("parse_javascript", True):
            patterns = [
                r"""fetch\(["']([^"']+)["']\)""",
                r"""axios\.\w+\(["']([^"']+)["']\)""",
                r"""location\.href\s*=\s*["']([^"']+)["']""",
                r"""["']([^"']*?\.php\?[^"']+)["']""",
            ]
            for pat in patterns:
                for m in re.finditer(pat, html):
                    links.add(urljoin(base_url, m.group(1)))

        # تنظيف
        clean = set()
        for l in links:
            l, _ = urldefrag(l)
            if l and self._in_scope(l) and not self._excluded(l):
                clean.add(l)
        return clean

    # ─── Form Extraction & Deduplication ───
    def extract_forms(self, base_url, html):
        forms = []
        soup = None
        try:
            soup = BeautifulSoup(html, "lxml")
        except Exception:
            try:
                soup = BeautifulSoup(html, "html.parser")
            except Exception:
                return forms

        if not soup:
            return forms

        for form in soup.find_all("form"):
            raw_action = form.get("action")
            action = urljoin(base_url, raw_action if raw_action else base_url)
            if not self._in_scope(action):
                continue
            method = (form.get("method") or "get").lower()
            if method not in ("get", "post"):
                method = "get"

            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name:
                    continue
                inputs.append({
                    "name":  name,
                    "type":  (inp.get("type") or "text").lower(),
                    "value": inp.get("value") or "",
                })
            if inputs:
                forms.append({"action": action, "method": method,
                              "inputs": inputs})
        return forms

    def _add_form(self, form):
        """Add form with deduplication and convert GET forms to scanable URLs."""
        key = (
            form["action"],
            form["method"],
            tuple(sorted(i["name"] for i in form["inputs"]))
        )
        if key in self._seen_form_keys:
            return

        self._seen_form_keys.add(key)

        if form["method"] == "post":
            self.forms.append(form)
        elif form["method"] == "get":
            # Convert GET form into a scanable URL query
            params = []
            for inp in form["inputs"]:
                if inp["type"] not in ("submit", "button", "reset", "image"):
                    val = inp.get("value") or "test"
                    params.append(f"{inp['name']}={val}")
            if params:
                sep = "&" if "?" in form["action"] else "?"
                get_url = f"{form['action']}{sep}{'&'.join(params)}"
                if get_url not in self.visited:
                    self.visited.add(get_url)

    # ─── robots.txt + sitemap.xml ───
    def _seed_extras(self, seed):
        p = urlparse(seed)
        base = f"{p.scheme}://{p.netloc}"
        for path in ("/robots.txt", "/sitemap.xml"):
            try:
                r = self.sess.get(base + path, timeout=self.cfg.get("crawler", {}).get("timeout", 10))
                if r.status_code != 200:
                    continue
                if path == "/robots.txt":
                    for line in r.text.splitlines():
                        line = line.split("#")[0].strip()
                        if line.lower().startswith(("allow:", "disallow:")):
                            v = line.split(":", 1)[1].strip()
                            if v and v != "/" and not any(ch in v for ch in "*$"):
                                full_url = urljoin(base, v)
                                yield full_url
                else:
                    for m in re.finditer(r"<loc>([^<]+)</loc>", r.text, re.IGNORECASE):
                        full_url = m.group(1).strip()
                        yield full_url
            except Exception:
                pass

    # ─── Main Crawler (BFS) ───
    def crawl(self):
        seed = self.cfg["target"]["seed_url"]
        max_depth = self.cfg.get("target", {}).get("max_depth", 3)
        max_pages = self.cfg.get("target", {}).get("max_pages", 100)
        delay = self.cfg.get("crawler", {}).get("delay", 0)

        queue = deque([(seed, 0)])
        queued = {seed}

        if self.cfg.get("crawler", {}).get("respect_robots", True):
            for extra in self._seed_extras(seed):
                if self._in_scope(extra) and extra not in queued:
                    queue.append((extra, 1))
                    queued.add(extra)

        self.log.info(f"Starting crawl from: {seed}")
        pages = 0

        while queue and pages < max_pages:
            url, depth = queue.popleft()
            if url in self.visited or depth > max_depth:
                continue
            self.visited.add(url)

            try:
                r = self.sess.get(url, timeout=self.cfg.get("crawler", {}).get("timeout", 10))
                pages += 1

                if self.waf.is_blocked(r):
                    self.waf.handle_block()
                    continue
                self.waf.reset()

                content_type = r.headers.get("Content-Type", "").lower()
                if "text/html" in content_type:
                    for link in self._extract_links(url, r.text):
                        if link not in self.visited and link not in queued:
                            queue.append((link, depth + 1))
                            queued.add(link)

                    # Extract forms
                    if self.cfg.get("scanner", {}).get("test_post", True):
                        for form in self.extract_forms(url, r.text):
                            self._add_form(form)

                if pages % 5 == 0 or len(queue) == 0:
                    self.log.progress("crawl", pages, max_pages,
                                     f"in queue: {len(queue)}")

            except Exception as e:
                self.log.debug(f"Failed to crawl {url}: {e}")
                continue

            if delay:
                time.sleep(delay)

        print()  # Newline after progress bar
        self.log.info(f"Crawl completed: {pages} pages, {len(self.visited)} URLs, {len(self.forms)} POST forms")
        return list(self.visited)

    # ─── Filter Scanable URLs ───
    def filter_scanable(self, urls):
        return [u for u in urls if "?" in u and "=" in u.split("?", 1)[1]]
