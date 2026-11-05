Viewed README.md:1-60

ممتاز جداً! الرفع عبر سحب الملفات من المتصفح حل ذكي وسريع ومباشر.

إليك كل ما تحتاجه لملء صفحة مشروعك على GitHub لتبدو بمستوى احترافي عالمي يبهر أي باحث أمني أو مسؤول توظيف:

---

### 1️⃣ الوصف المختصر للمستودع (GitHub About Box)
في الواجهة الرئيسية للمستودع على موقع GitHub، اضغط على أيقونة **⚙️ (Settings/Edit)** بجانب كلمة **About** في الشريط الجانبي الأيمن:

* **Description (الوصف):**
```text
High-performance, multi-threaded Path Traversal & LFI security assessment tool with baseline differential analysis, zero false-positives, and interactive HTML reporting. (For Educational & Authorized Auditing Only)
```

* **Topics / Tags (الوسوم):**
```text
python, cybersecurity, path-traversal, lfi, security-tools, penetration-testing, owasp, cwe-22, vulnerability-scanner, information-security
```

---

### 2️⃣ كيف تضيف الـ README عبر المتصفح بـ 3 نقرات:
1. داخل صفحة مستودعك على GitHub، اضغط على زر **Add file** ثم اختر **Create new file**.
2. في خانة اسم الملف اكتب: `README.md`
3. في مربع النص الكبير، **انسخ المحتوى الكامل الموجود في المربع أدناه والصقه مباشرة**.
4. انزل لأسفل الصفحة واضغط على الزر الأخضر **Commit changes...** ثم اضغط **Commit changes**.

---

### 3️⃣ النص الكامل لملف `README.md` (جاهز للنسخ مباشرة):

```markdown
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
[![Security Tool](https://img.shields.io/badge/Security-Defensive%20Auditing-blueviolet.svg)](#-disclaimer--ethical-usage-policy)

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

Traditional fuzzers often flood security teams with false positives by relying naively on HTTP response code variations or raw byte count differences. PathScan resolves this through a **Dynamic Baseline Differential Engine**:
1. **Dynamic Baseline Profiling**: Records baseline page structure, status codes, and normal content before fuzzing.
2. **Concurrent Multi-Threading**: Executes prioritized payloads concurrently via a thread pool with thread-safe atomic logging.
3. **Signature Heuristics Correlation**: Validates findings exclusively against verified signatures and structural differential disclosures, ensuring **0% false positive rates** on clean endpoints.
4. **Actionable Executive Reporting**: Automatically renders an interactive standalone HTML dashboard, complete with CWE-22/OWASP A01 references and code-level defensive remediation snippets.

---

## ✨ Key Features

- **🚀 Concurrent Multi-Threaded Engine**: Built with `ThreadPoolExecutor` for high-throughput testing with configurable worker threads (`-t` / `--threads`).
- **🎯 Baseline Differential Analysis**: Eliminates false positives by comparing fuzzing responses against baseline fingerprints before flagging findings.
- **📊 Interactive HTML Security Dashboard**: Generates comprehensive, modern HTML audit reports with statistics, vulnerability cards, and severity breakdowns.
- **🛡️ Defensive Remediation Snippets**: Auto-generates practical, secure code remediation snippets for developers in **Python**, **PHP**, and **Node.js**.
- **🧱 Intelligent WAF Evasion**: Automatically detects rate-limiting and WAF blocking (Cloudflare, Akamai, Imperva, ModSecurity) and applies exponential backoff.
- **🕷️ Autonomous Web Crawler**: Extracts parameterized URLs, parses HTML GET forms, and deduplicates POST form inputs.
- **📝 Custom Wordlist Support**: Easily test custom, compliant, or non-destructive payloads with `--payloads-file`.

---

## 🛠️ Quick Installation

### Requirements
- **Python 3.8 or higher**
- `requests` library

```bash
# 1. Install required dependencies
pip install requests beautifulsoup4 colorama

# 2. Run the tool
python3 pathscan_lite.py --help
```

---

## 📖 Usage Examples

### 1. Basic Single-Endpoint Audit
Audit a specific URL parameter using 5 concurrent worker threads:
```bash
python3 pathscan_lite.py -u "http://target.com/view.php?file=about" -t 5
```

### 2. Full Audit with Interactive HTML Dashboard Report
Audit the target and automatically generate a standalone HTML report:
```bash
python3 pathscan_lite.py -u "http://target.com/page?doc=test" --html
```

### 3. Scanning with a Custom Payloads File
Use your own safe or custom test vectors:
```bash
python3 pathscan_lite.py -u "http://target.com/view?file=test" --payloads-file payloads.txt
```

### 4. Authenticated Audit via Proxy (Burp Suite / OWASP ZAP)
Route requests through a local proxy with session cookie authentication:
```bash
python3 pathscan_lite.py -u "http://target.com/app?doc=1" \
  --proxy "http://127.0.0.1:8080" \
  --cookie "PHPSESSID=c8e71b2a9d4f" \
  --verbose
```

---

## ⚙️ CLI Reference Table

| Argument | Description | Default |
| :--- | :--- | :--- |
| `-u, --url` | Target URL (e.g., `http://example.com/view.php?file=test`) | *Required* |
| `-t, --threads` | Concurrency worker threads count | `5` |
| `-d, --depth` | Maximum crawling recursion depth | `2` |
| `--payloads-file` | Path to custom text file with external payloads | *Built-in generator* |
| `--html` | Generate interactive standalone HTML security report | `False` |
| `-o, --output` | Destination directory for audit reports | `output/` |
| `-p, --proxy` | HTTP/HTTPS proxy address (e.g., `http://127.0.0.1:8080`) | *None* |
| `--cookie` | Session cookie header value | *None* |
| `-v, --verbose` | Enable verbose debugging messages | `False` |

---

## 🛡️ Defensive Remediation Guide (CWE-22 / OWASP A01)

When Path Traversal or LFI vulnerabilities are identified, apply these secure coding standards:

### 1. Python Remediation
```python
from pathlib import Path

def safe_read(base_folder: str, user_filename: str):
    base_path = Path(base_folder).resolve()
    target_path = (base_path / user_filename).resolve()
    
    # Strict boundary check ensuring target stays within base directory
    if base_path not in target_path.parents and target_path != base_path:
        raise PermissionError("Access Denied: Path Traversal Detected")
        
    return target_path.read_text(encoding="utf-8")
```

### 2. PHP Remediation
```php
<?php
// Use strict allowlist mapping rather than direct file inclusion
$whitelist = [
    'home'  => 'pages/home.php',
    'about' => 'pages/about.php',
];
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

## 📄 License

Distributed under the **MIT License**. See `LICENSE` for more information.

<div align="center">
<b>Developed strictly for authorized security auditing, defensive research, and academic study.</b>
</div>
```
