# ═══════════════════════════════════════════════════════
#  session.py — Session Builder (SSL + Cookies + Headers + Proxy)
# ═══════════════════════════════════════════════════════

import ssl
import urllib3
from requests import Session
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


def build_session(config):
    """Builds a configured requests.Session instance."""
    sess = Session()

    # ─── SSL ───
    ssl_cfg = config.get("ssl", {})
    verify = ssl_cfg.get("verify", False)
    ca_bundle = ssl_cfg.get("ca_bundle")

    if not verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        sess.verify = False
    else:
        sess.verify = ca_bundle if ca_bundle else True

    # ─── Headers ───
    headers = config.get("session", {}).get("headers") or {}
    for k, v in headers.items():
        sess.headers[k] = str(v)

    # ─── Cookies ───
    cookies = config.get("session", {}).get("cookies") or {}
    for k, v in cookies.items():
        sess.cookies.set(k, str(v))

    # ─── Proxy ───
    proxy = config.get("session", {}).get("proxy")
    if proxy:
        if isinstance(proxy, str):
            sess.proxies = {"http": proxy, "https": proxy}
        elif isinstance(proxy, dict) and proxy:
            sess.proxies = proxy

    # ─── Network-Level Retries (502/503/504 gateway errors only) ───
    retry = Retry(total=2, backoff_factor=0.5,
                  status_forcelist=[502, 503, 504],
                  raise_on_status=False)
    adapter = HTTPAdapter(max_retries=retry)
    sess.mount("http://", adapter)
    sess.mount("https://", adapter)

    return sess
