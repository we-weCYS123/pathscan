# ═══════════════════════════════════════════════════════
#  reporter.py — Professional HTML Dashboard Reporter
#  Generates standalone, responsive security audit reports
#  with OWASP / CWE remediation guidelines.
# ═══════════════════════════════════════════════════════

import html
import json
import time
from pathlib import Path


def generate_html_report(config, findings, tested_count, duration_seconds=0.0):
    """
    Generates a modern, standalone HTML report with summary metrics,
    vulnerability cards, and code-level remediation snippets.
    """
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    target = config.get("target", {}).get("seed_url", "N/A")

    critical_count = sum(1 for f in findings if any(s[1] == "critical" for s in f.get("signatures", [])))
    high_count = sum(1 for f in findings if any(s[1] == "high" for s in f.get("signatures", [])))
    medium_count = sum(1 for f in findings if any(s[1] == "medium" for s in f.get("signatures", [])))
    low_count = sum(1 for f in findings if any(s[1] == "low" for s in f.get("signatures", [])))

    status_badge = "CRITICAL RISK" if critical_count > 0 else ("HIGH RISK" if high_count > 0 else ("CLEAN" if len(findings) == 0 else "WARNING"))
    status_class = "danger" if (critical_count + high_count) > 0 else ("success" if len(findings) == 0 else "warning")

    findings_rows = ""
    for idx, f in enumerate(findings, 1):
        m = f.get("method", "GET")
        url_esc = html.escape(f.get("url", ""))
        param_esc = html.escape(f.get("param", ""))
        payload_esc = html.escape(f.get("payload", ""))
        code = f.get("status_code", 200)
        diff = f.get("length_diff", 0)

        sigs_html = ""
        highest_sev = "low"
        for name, sev, desc in f.get("signatures", []):
            if sev == "critical":
                highest_sev = "critical"
            elif sev == "high" and highest_sev != "critical":
                highest_sev = "high"
            elif sev == "medium" and highest_sev not in ("critical", "high"):
                highest_sev = "medium"

            badge_color = "#dc2626" if sev == "critical" else ("#ea580c" if sev == "high" else ("#eab308" if sev == "medium" else "#3b82f6"))
            sigs_html += f'<span class="badge" style="background:{badge_color};">{html.escape(name)} [{sev.upper()}]</span> {html.escape(desc)}<br>'

        badge_bg = "#dc2626" if highest_sev == "critical" else ("#ea580c" if highest_sev == "high" else "#eab308")

        findings_rows += f"""
        <tr>
            <td><strong>#{idx}</strong></td>
            <td><span class="badge method-{m.lower()}">{m}</span></td>
            <td><code>{param_esc}</code></td>
            <td><span class="badge" style="background:{badge_bg};">{highest_sev.upper()}</span></td>
            <td><code>{code}</code> (Diff: {diff}B)</td>
            <td>{sigs_html}</td>
            <td><pre class="code-box">{payload_esc}</pre></td>
            <td style="max-width:320px; word-break:break-all;"><a href="{url_esc}" target="_blank" rel="noopener">{url_esc}</a></td>
        </tr>
        """

    if not findings_rows:
        findings_rows = """
        <tr>
            <td colspan="8" style="text-align:center; padding:30px; color:#10b981; font-weight:600;">
                ✓ No path traversal or file disclosure vulnerabilities detected.
            </td>
        </tr>
        """

    report_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PathScan Security Audit Report</title>
    <style>
        :root {{
            --bg-dark: #0f172a;
            --surface: #1e293b;
            --surface-hover: #334155;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --primary: #38bdf8;
            --danger: #ef4444;
            --warning: #f59e0b;
            --success: #10b981;
            --border: #334155;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif; }}
        body {{ background: var(--bg-dark); color: var(--text-main); padding: 30px 20px; line-height: 1.6; }}
        .container {{ max-width: 1300px; margin: 0 auto; }}
        
        header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 20px; margin-bottom: 30px; }}
        .brand h1 {{ font-size: 26px; font-weight: 700; color: var(--primary); letter-spacing: -0.5px; }}
        .brand p {{ color: var(--text-muted); font-size: 14px; }}
        .scan-status {{ padding: 8px 16px; border-radius: 9999px; font-weight: 700; font-size: 13px; text-transform: uppercase; }}
        .scan-status.danger {{ background: rgba(239, 68, 68, 0.2); color: var(--danger); border: 1px solid var(--danger); }}
        .scan-status.warning {{ background: rgba(245, 158, 11, 0.2); color: var(--warning); border: 1px solid var(--warning); }}
        .scan-status.success {{ background: rgba(16, 185, 129, 0.2); color: var(--success); border: 1px solid var(--success); }}

        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 30px; }}
        .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 20px; }}
        .card .label {{ font-size: 13px; color: var(--text-muted); text-transform: uppercase; font-weight: 600; margin-bottom: 8px; }}
        .card .value {{ font-size: 30px; font-weight: 800; color: var(--text-main); }}

        .section-title {{ font-size: 18px; font-weight: 700; margin-bottom: 16px; display: flex; align-items: center; gap: 8px; }}
        
        .table-container {{ overflow-x: auto; background: var(--surface); border: 1px solid var(--border); border-radius: 12px; margin-bottom: 40px; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 14px; text-align: left; }}
        th {{ background: #182234; color: var(--text-muted); padding: 14px 16px; font-weight: 600; border-bottom: 1px solid var(--border); }}
        td {{ padding: 14px 16px; border-bottom: 1px solid var(--border); vertical-align: middle; }}
        tr:hover td {{ background: var(--surface-hover); }}
        
        .badge {{ display: inline-block; padding: 3px 8px; border-radius: 6px; font-size: 11px; font-weight: 700; color: #fff; text-transform: uppercase; margin: 2px 0; }}
        .badge.method-get {{ background: #2563eb; }}
        .badge.method-post {{ background: #7c3aed; }}
        
        .code-box {{ background: #090d16; border: 1px solid #1e293b; padding: 6px 10px; border-radius: 6px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 12px; color: #38bdf8; word-break: break-all; white-space: pre-wrap; }}
        code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, monospace; color: #f43f5e; }}
        a {{ color: var(--primary); text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}

        .remediation {{ background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 24px; }}
        .remediation-block {{ margin-bottom: 24px; }}
        .remediation-block h3 {{ font-size: 16px; color: var(--primary); margin-bottom: 10px; font-weight: 600; }}
        .remediation-block p {{ color: var(--text-muted); font-size: 14px; margin-bottom: 12px; }}
        .code-example {{ background: #090d16; border: 1px solid #1e293b; border-radius: 8px; padding: 16px; font-family: ui-monospace, monospace; font-size: 13px; color: #cbd5e1; overflow-x: auto; line-height: 1.5; }}
        .code-example .keyword {{ color: #c084fc; }}
        .code-example .func {{ color: #38bdf8; }}
        .code-example .comment {{ color: #64748b; font-style: italic; }}

        footer {{ text-align: center; margin-top: 50px; color: var(--text-muted); font-size: 13px; border-top: 1px solid var(--border); padding-top: 20px; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="brand">
                <h1>PathScan v3.0 — Audit Report</h1>
                <p>Automated Directory Traversal & LFI Security Assessment</p>
            </div>
            <div class="scan-status {status_class}">
                {status_badge}
            </div>
        </header>

        <!-- Stats Overview -->
        <div class="stats-grid">
            <div class="card">
                <div class="label">Target Seed URL</div>
                <div class="value" style="font-size:16px; word-break:break-all; font-weight:600;">{html.escape(target)}</div>
            </div>
            <div class="card">
                <div class="label">Confirmed Findings</div>
                <div class="value" style="color:{'#ef4444' if len(findings) > 0 else '#10b981'};">{len(findings)}</div>
            </div>
            <div class="card">
                <div class="label">Total Requests</div>
                <div class="value">{tested_count}</div>
            </div>
            <div class="card">
                <div class="label">Critical / High Severity</div>
                <div class="value" style="color:#ef4444;">{critical_count + high_count}</div>
            </div>
            <div class="card">
                <div class="label">Scan Timestamp</div>
                <div class="value" style="font-size:15px; font-weight:600;">{ts}</div>
            </div>
        </div>

        <!-- Findings Table -->
        <div class="section-title">🔎 Identified Vulnerabilities</div>
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Method</th>
                        <th>Parameter</th>
                        <th>Severity</th>
                        <th>HTTP Status</th>
                        <th>Matched Signature</th>
                        <th>Payload</th>
                        <th>Target URL</th>
                    </tr>
                </thead>
                <tbody>
                    {findings_rows}
                </tbody>
            </table>
        </div>

        <!-- Remediation & Defense Guide -->
        <div class="section-title">🛡️ Remediation & Defensive Recommendations (CWE-22 / OWASP A01)</div>
        <div class="remediation">
            <div class="remediation-block">
                <h3>1. Canonical Path Resolution (Path Normalization)</h3>
                <p>Never concatenate unvalidated user inputs directly into filesystem operations. Resolve absolute canonical paths and verify they strictly reside within the intended root directory.</p>
                <div class="code-example">
<span class="comment"># Python Safe Path Resolution</span>
<span class="keyword">import</span> os
<span class="keyword">from</span> pathlib <span class="keyword">import</span> Path

BASE_DIR = Path(<span class="func">"/var/www/uploads"</span>).<span class="func">resolve</span>()

<span class="keyword">def</span> <span class="func">get_user_file</span>(filename):
    target = (BASE_DIR / filename).<span class="func">resolve</span>()
    <span class="keyword">if</span> BASE_DIR <span class="keyword">not in</span> target.parents:
        <span class="keyword">raise</span> PermissionError(<span class="func">"Path traversal attempt blocked!"</span>)
    <span class="keyword">return</span> target.<span class="func">read_bytes</span>()
                </div>
            </div>

            <div class="remediation-block">
                <h3>2. Strict Allowlisting (Recommended)</h3>
                <p>Instead of accepting arbitrary filesystem paths or file extensions from HTTP query parameters, map request parameters to an internal dictionary or allowlist of known identifiers.</p>
                <div class="code-example">
<span class="comment">// PHP Allowlist Map</span>
$allowed_pages = [
    <span class="func">'home'</span>    => <span class="func">'views/home.php'</span>,
    <span class="func">'about'</span>   => <span class="func">'views/about.php'</span>,
    <span class="func">'contact'</span> => <span class="func">'views/contact.php'</span>,
];

$page = $_GET[<span class="func">'page'</span>] ?? <span class="func">'home'</span>;
<span class="keyword">if</span> (!array_key_exists($page, $allowed_pages)) {{
    http_response_code(404);
    <span class="keyword">exit</span>(<span class="func">"Page not found"</span>);
}}
<span class="keyword">include</span> $allowed_pages[$page];
                </div>
            </div>

            <div class="remediation-block">
                <h3>3. Strip Directory Separators (Basename Isolation)</h3>
                <p>If user-supplied filenames must be stored or read, strip path components and directory traversals using standard filename sanitizers.</p>
                <div class="code-example">
<span class="comment">// Node.js / Express Path Isolation</span>
<span class="keyword">const</span> path = require(<span class="func">'path'</span>);
<span class="keyword">const</span> safeName = path.<span class="func">basename</span>(req.query.file); <span class="comment">// Strips traversal sequences</span>
<span class="keyword">const</span> safePath = path.<span class="func">join</span>(UPLOAD_DIR, safeName);
                </div>
            </div>
        </div>

        <footer>
            Generated automatically by <strong>PathScan v3.0</strong> — Open Source Application Security Tool
        </footer>
    </div>
</body>
</html>
"""
    return report_html
