"""SARIF 2.1.0 adapter (minimal, common fields only)."""

import json

from .common import make_finding, normalize_cwe


def load(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)

    findings = []

    for run in data.get("runs", []):
        for result in run.get("results", []):
            locations = result.get("locations") or []
            if not locations:
                continue

            physical = locations[0].get("physicalLocation", {})
            uri = physical.get("artifactLocation", {}).get("uri", "")
            if not uri:
                continue

            properties = result.get("properties", {}) or {}
            rule_id = result.get("ruleId", "") or properties.get("cwe", "")

            findings.append(make_finding(
                url=uri,
                method=properties.get("method", "GET"),
                parameter=properties.get("parameter", ""),
                cwe=normalize_cwe(rule_id) or normalize_cwe(properties.get("cwe")),
                vtype=properties.get("type"),
                evidence=result.get("message", {}).get("text", ""),
            ))

    return findings
