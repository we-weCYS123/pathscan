<div align="center">

```text
 ____       _   _     ____                  
|  _ \ __ _| |_| |__ / ___|  ___ __ _ _ __  
| |_) / _` | __| '_ \\___ \ / __/ _` | '_ \ 
|  __/ (_| | |_| | | |___) | (_| (_| | | | |
|_|   \__,_|\__|_| |_|____/ \___\__,_|_| |_|
```

### High-Performance Path Traversal & Local File Inclusion (LFI) Security Assessment Suite
*Engineered for High Precision, Multi-Threaded Concurrency, and Zero False Positives.*

---

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-emerald.svg)](LICENSE)
[![OWASP Standard](https://img.shields.io/badge/OWASP-A01%3A2021%20Broken%20Access%20Control-crimson.svg)](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
[![CWE Definition](https://img.shields.io/badge/CWE-22%20Path%20Traversal-orange.svg)](https://cwe.mitre.org/data/definitions/22.html)
[![Tests Passing](https://img.shields.io/badge/Tests-Passing-brightgreen.svg)](tests/)
[![Architecture](https://img.shields.io/badge/Architecture-Modular%20%7C%20Single--File%20Lite-purple.svg)](#-two-flavors-full-vs-lite)

</div>

---

> [!CAUTION]
> ### ⚖️ DISCLAIMER & ETHICAL USAGE POLICY
> **This tool is strictly developed for authorized educational research, defensive security auditing, and penetration testing on systems where you have obtained prior explicit, written authorization from the owner.**
> 
> Testing targets without permission is illegal under computer fraud and cybercrime legislation (including the US CFAA, UK Computer Misuse Act, and international equivalents). The authors and contributors assume **no liability** and are not responsible for any misuse, damage, or legal consequences resulting from the use of this software. **Use responsibly and ethically.**

---

## 📌 Executive Summary

**PathScan** is an enterprise-grade Application Security auditing suite specialized in the detection and verification of **Path Traversal** and **Local File Inclusion (LFI)** vulnerabilities across web applications and REST APIs.

Traditional scanners often flood security teams with false positives by relying naively on HTTP response code variations or raw byte count differences. PathScan resolves this through a **Dynamic Baseline Differential Engine**:
1. It records baseline page structure, status codes, and content before fuzzing.
2. It tests prioritized payloads concurrently using a thread pool.
3. It validates findings exclusively against verified signature heuristics and true structural differential disclosures, delivering **0% false positive rates** on clean endpoints.

---

## ⚡ Two Flavors: Choose Your Workflow

PathScan provides two deployment models designed for different operational scenarios:

| Feature | 🏛️ Full Modular Suite (`pathscan.py`) | 🚀 Portable Single-File (`pathscan_lite.py`) |
| :--- | :---: | :---: |
| **Footprint** | Full Git Repo Architecture (~80 KB) | Single File (~28 KB, Zero Directory Overhead) |
| **Concurrency** | Multi-threaded (`ThreadPoolExecutor`) | Multi-threaded (`ThreadPoolExecutor`) |
| **Detection Engine** | Baseline Diffing + Heuristic Signatures | Baseline Diffing + Heuristic Signatures |
| **Custom Payloads** | `--payloads-file <path>` | `--payloads-file <path>` |
| **Reporting** | Interactive HTML Dashboard + JSON + TXT | Interactive HTML Dashboard + JSON + TXT |
| **Web Crawler** | Deep BFS Crawler + Form Parser + JS Endpoints | Lightweight HTML Link & Form Extractor |
| **Configuration** | `config.yaml` + CLI overrides | CLI Flags & Built-in Smart Defaults |
| **Best For** | Full pentest audits, CI/CD pipelines, CV repo | Quick VPS triage, CTFs, drop-and-run auditing |

---

## ✨ Core Capabilities

- **🚀 High-Throughput Multi-Threading**: Non-blocking concurrent requests via `concurrent.futures.ThreadPoolExecutor` with thread-safe atomic logging and early cancellation flags.
- **🎯 Dynamic Baseline Validation**: Fingerprints normal responses to prevent false alarms on custom 404/500 handlers or dynamic pages.
- **📊 Standalone HTML Security Dashboard**: Generates beautiful, responsive HTML audit reports with executive vulnerability metrics, raw request details, and code-level remediation.
- **🛡️ Actionable Remediation Snippets**: Auto-generates defensive code snippets for developers in **Python** (`pathlib.resolve()`), **PHP** (`basename()`), and **Node.js** (`path.resolve()`).
- **🧱 Intelligent WAF Evasion & Rate-Limit Handling**: Automatically identifies WAF throttling (Cloudflare, Akamai, Imperva, ModSecurity) and implements progressive exponential backoff.
- **🕷️ Autonomous Web Crawler**: Extracts parameterized URLs, parses HTML GET forms, and deduplicates POST form inputs.
- **🧩 Custom Wordlist Integration**: Easily test custom, compliant, or non-destructive payloads with `--payloads-file`.

---

## 📁 Repository Structure

```text
pathscan/
├── pathscan.py           # Full Modular CLI entry point
├── pathscan_lite.py      # Standalone single-file portable scanner (28 KB)
├── config.yaml           # Centralized configuration (timeouts, scope, thresholds)
├── requirements.txt      # Python dependencies
├── payloads.txt          # Reference custom test vectors list
├── core/
│   ├── scanner.py        # Multi-threaded baseline & signature comparison engine
│   ├── reporter.py       # Standalone HTML dashboard report generator
│   ├── crawler.py        # BFS crawler and HTML form parser
│   ├── payloads.py       # Prioritized built-in payload generator
│   ├── signatures.py     # Sensitive file disclosure heuristics (Linux, Windows, configs)
│   ├── session.py        # HTTP adapter, custom headers, cookies, and proxy configuration
│   └── waf.py            # WAF detection & exponential backoff handler
└── tests/
    └── test_scanner.py   # Automated integration test suite with mock HTTP server
```

---

## 🛠️ Installation & Setup

### Requirements
- **Python 3.8+**
- `requests` (required)
- `beautifulsoup4` (optional, for advanced HTML form parsing)
- `colorama` (optional, for terminal styling)

### Option A: Clone the Full Repository
```bash
# Clone the repository
git clone https://github.com/<your-username>/pathscan.git
cd pathscan

# Install dependencies
pip install -r requirements.txt
```

### Option B: Download the Single-File Portable Version (`pathscan_lite.py`)
No need to clone the entire repo! Just grab the single file:
```bash
curl -O https://raw.githubusercontent.com/<your-username>/pathscan/main/pathscan_lite.py
chmod +x pathscan_lite.py
python3 pathscan_lite.py -u "http://target.com/view?file=test"
```

---

## 📖 Usage Examples

### 1. Basic Single-Endpoint Audit (Direct Mode)
Audit a parameterized endpoint using 5 concurrent threads:
```bash
python3 pathscan.py -u "http://target.com/view.php?file=about" --no-crawl
```
*(Or with the single-file version:)*
```bash
python3 pathscan_lite.py -u "http://target.com/view.php?file=about" -t 5
```

### 2. Multi-Threaded Crawl & Audit with HTML Report
Crawl target domain within scope up to depth 2, scanning both GET parameters and POST forms, then output an interactive HTML dashboard:
```bash
python3 pathscan.py -u "http://target.com/" -t 10 --html
```

### 3. Using Custom / Safe Payloads
Supply a customized wordlist (e.g. testing safe non-sensitive paths):
```bash
python3 pathscan.py -u "http://target.com/app?page=doc" --payloads-file payloads.txt
```

### 4. Authenticated Audit via Proxy (Burp Suite / OWASP ZAP)
Route requests through a local interception proxy with session authentication:
```bash
python3 pathscan.py -u "http://target.com/dashboard?f=1" \
  --proxy "http://127.0.0.1:8080" \
  --cookie "SESSIONID=c8e71b2a9d4f" \
  --verbose
```

---

## ⚙️ CLI Reference Table

| Argument | Description | Default |
| :--- | :--- | :--- |
| `-u, --url` | Target URL (e.g. `http://example.com/view?file=test`) | *Required* |
| `-t, --threads` | Concurrency worker threads count | `5` |
| `-d, --depth` | Maximum crawling recursion depth | `2` |
| `--payloads-file` | Path to custom text file with external payloads | *Built-in generator* |
| `--html` | Generate interactive standalone HTML security report | `False` |
| `-o, --output` | Destination directory for audit reports | `output/` |
| `-p, --proxy` | HTTP/HTTPS proxy address (e.g., `http://127.0.0.1:8080`) | *None* |
| `--cookie` | Session cookie header value | *None* |
| `--no-crawl` | Disable crawler and test the target URL directly | `False` |
| `-v, --verbose` | Enable verbose debugging messages | `False` |
| `-c, --config` | Path to YAML configuration file *(Full version only)* | `config.yaml` |

---

## 🧪 Automated Testing

PathScan includes an embedded HTTP mock test suite covering clean response behavior, accurate signature recognition, and HTML report rendering:

```bash
python3 -m unittest discover -s tests
```

Output:
```text
Ran 3 tests in 0.815s

OK
```

---

## 🛡️ Defensive Remediation Guide (CWE-22 / OWASP A01)

When Path Traversal or LFI is detected, apply these defense-in-depth principles:

### 1. Python Remediation
```python
import os
from pathlib import Path

def safe_read(base_folder: str, user_filename: str):
    base_path = Path(base_folder).resolve()
    target_path = (base_path / user_filename).resolve()
    
    # Strict boundary check
    if base_path not in target_path.parents and target_path != base_path:
        raise PermissionError("Access Denied: Path Traversal Detected")
        
    return target_path.read_text(encoding="utf-8")
```

### 2. PHP Remediation
```php
<?php
$whitelist = ['home' => 'pages/home.php', 'about' => 'pages/about.php'];
$page = $_GET['page'] ?? 'home';

if (!array_key_exists($page, $whitelist)) {
    http_response_code(400);
    die("Invalid request");
}
include($whitelist[$page]);
?>
```

### 3. Node.js Remediation
```javascript
const path = require('path');
const fs = require('fs');

function safeServe(baseDir, userInput) {
    const safePath = path.normalize(userInput).replace(/^(\.\.[\/\\])+/, '');
    const resolvedPath = path.resolve(baseDir, safePath);

    if (!resolvedPath.startsWith(path.resolve(baseDir))) {
        throw new Error("Access Denied: Path Traversal Attempt");
    }
    return fs.readFileSync(resolvedPath, 'utf8');
}
```

---

## 🤝 Contributing

Contributions, bug reports, and pull requests are welcome!
1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/NewFeature`)
3. Commit your Changes (`git commit -m 'Add NewFeature'`)
4. Push to the Branch (`git push origin feature/NewFeature`)
5. Open a Pull Request

---

## 📄 License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for more information.

<div align="center">
<b>Built for ethical security professionals and researchers.</b>
</div>
