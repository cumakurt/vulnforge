"""Custom JSON adapter.

Accepted input:

    {"findings": [{"url": "/php/x.php", "method": "GET", "parameter": "id",
                   "cwe": "CWE-89", "type": "sqli", "evidence": "..."}]}

A bare list of findings is also accepted.
"""

import json

from .common import make_finding


def load(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)

    entries = data.get("findings", []) if isinstance(data, dict) else data
    findings = []

    for entry in entries:
        if not isinstance(entry, dict) or not entry.get("url"):
            continue
        findings.append(make_finding(
            url=entry.get("url", ""),
            method=entry.get("method", "GET"),
            parameter=entry.get("parameter", ""),
            cwe=entry.get("cwe"),
            vtype=entry.get("type"),
            evidence=entry.get("evidence", ""),
        ))

    return findings
