"""ZAP JSON report adapter."""

import json

from .common import make_finding


def load(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)

    findings = []

    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            cwe_id = alert.get("cweid")
            cwe = f"CWE-{cwe_id}" if cwe_id and str(cwe_id).isdigit() and int(cwe_id) > 0 else None
            vtype = alert.get("alert", "")

            for instance in alert.get("instances", []):
                findings.append(make_finding(
                    url=instance.get("uri", ""),
                    method=instance.get("method", "GET"),
                    parameter=instance.get("param", ""),
                    cwe=cwe,
                    vtype=vtype,
                    evidence=instance.get("evidence", ""),
                ))

    return findings
