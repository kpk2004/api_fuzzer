"""
Turns the ResponseAnalyzer's findings into a JSON report and a quick
human-readable HTML summary.
"""
import json
import os
from dataclasses import asdict
from datetime import datetime, timezone
from typing import List

from .analyzer import Finding

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def _sorted(findings: List[Finding]) -> List[Finding]:
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 4))


def write_json_report(findings: List[Finding], output_dir: str, filename: str = "report.json") -> str:
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, filename)
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "finding_count": len(findings),
        "findings": [asdict(f) for f in _sorted(findings)],
    }
    with open(path, "w") as f:
        json.dump(payload, f, indent=2)
    return path


def write_html_report(findings: List[Finding], output_dir: str, filename: str = "report.html") -> str:
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, filename)
    rows = "\n".join(
        f"<tr class='sev-{f.severity}'><td>{f.severity.upper()}</td><td>{f.category}</td>"
        f"<td>{f.method}</td><td>{f.endpoint}</td><td>{f.detail}</td></tr>"
        for f in _sorted(findings)
    )
    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>API Fuzzer Report</title>
<style>
body {{ font-family: -apple-system, Arial, sans-serif; margin: 2rem; }}
table {{ border-collapse: collapse; width: 100%; }}
td, th {{ border: 1px solid #ccc; padding: 6px 10px; font-size: 14px; text-align: left; }}
.sev-high {{ background: #fde2e2; }}
.sev-medium {{ background: #fff3cd; }}
.sev-low {{ background: #eef; }}
</style></head>
<body>
<h1>API Fuzzer Report</h1>
<p>Generated: {datetime.now(timezone.utc).isoformat()}</p>
<p>Total findings: {len(findings)}</p>
<table>
<tr><th>Severity</th><th>Category</th><th>Method</th><th>Endpoint</th><th>Detail</th></tr>
{rows}
</table>
</body></html>"""
    with open(path, "w") as f:
        f.write(html)
    return path
