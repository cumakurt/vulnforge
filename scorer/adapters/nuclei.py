"""Nuclei JSONL adapter (one JSON object per line)."""

import json

from .common import make_finding, normalize_cwe


def load(path: str) -> list[dict]:
    findings = []

    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            if not entry.get("matched-at") and not entry.get("host"):
                continue

            classification = entry.get("info", {}).get("classification", {}) or {}
            cwes = classification.get("cwe-id") or []
            cwe = normalize_cwe(cwes[0]) if cwes else None

            findings.append(make_finding(
                url=entry.get("matched-at") or entry.get("host", ""),
                method=entry.get("type", "GET"),
                parameter=entry.get("matcher-name", ""),
                cwe=cwe,
                vtype=entry.get("template-id"),
                evidence=entry.get("extracted-results", ""),
            ))

    return findings
