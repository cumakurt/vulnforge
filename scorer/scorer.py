#!/usr/bin/env python3
"""
VulnForge Lab — scanner scorer.

Compares scanner output (one of the supported adapters) against the generated
ground truth (vulns.json / controls.json) and produces JSON, CSV and HTML
reports with precision/recall/F1 breakdowns.

Usage:
  python3 scorer/scorer.py --findings scanner.json --format custom_json \
      --truth-dir lab/truth --out-dir scorer/out

  python3 scorer/scorer.py --findings scanner.json \
      --fail-under recall=0.80 --fail-over fp=0.05

Scoring model
─────────────
  * A finding matches a vulnerability when normalised URL, HTTP method and
    parameter are equal and (when both sides provide one) the CWE agrees.
  * Findings that match a safe control twin are *definite false positives*.
  * Duplicate findings for an already matched vulnerability are ignored.
  * A vulnerability with no matching finding is a false negative.
"""

import argparse
import csv
import html
import json
import sys
from collections import defaultdict
from pathlib import Path
from urllib.parse import unquote, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))

from adapters import load as load_findings  # noqa: E402


# ─── Normalisation ────────────────────────────────────────────────────────────

def normalize_url(url: str) -> str:
    if not url:
        return "/"

    parts = urlsplit(url)
    path = unquote(parts.path or "/")
    path = "/".join(segment for segment in path.split("/") if segment != "")
    path = "/" + path
    return path


def normalize_parameter(parameter: str) -> str:
    return (parameter or "").strip().lower()


def normalize_type(value: str | None) -> str:
    return (value or "").strip().lower()


def match_key(url: str, method: str, parameter: str) -> tuple[str, str, str]:
    return (normalize_url(url), (method or "GET").upper(), normalize_parameter(parameter))


# ─── Matching ────────────────────────────────────────────────────────────────

def cwe_agrees(vuln: dict, finding: dict) -> bool:
    vuln_cwes = {c.upper() for c in vuln.get("cwe", [])}
    finding_cwe = (finding.get("cwe") or "").upper()

    if not finding_cwe:
        return True
    if not vuln_cwes:
        return True
    return finding_cwe in vuln_cwes


def type_agrees(vuln: dict, finding: dict) -> bool:
    finding_type = normalize_type(finding.get("type"))
    if not finding_type:
        return True

    vuln_type = normalize_type(vuln.get("type"))
    if not vuln_type:
        return True

    return finding_type in vuln_type or vuln_type in finding_type


def agrees(vuln: dict, finding: dict) -> bool:
    """A supplied CWE is authoritative; otherwise fall back to the type name."""
    if finding.get("cwe"):
        return cwe_agrees(vuln, finding)
    return type_agrees(vuln, finding)


class Matcher:
    def __init__(self, vulns: list[dict], controls: list[dict]):
        self.vulns = vulns
        self.by_key: dict[tuple, list[dict]] = defaultdict(list)
        self.by_url_method: dict[tuple, list[dict]] = defaultdict(list)
        self.control_keys: dict[tuple, dict] = {}
        self.control_by_url_method: dict[tuple, dict] = {}

        for vuln in vulns:
            key = match_key(vuln["url"], vuln["method"], vuln.get("parameter", ""))
            self.by_key[key].append(vuln)
            self.by_url_method[(key[0], key[1])].append(vuln)

        for control in controls:
            key = match_key(control["url"], control["method"], control.get("parameter", ""))
            self.control_keys[key] = control
            self.control_by_url_method[(key[0], key[1])] = control

    def classify(self, finding: dict) -> tuple[str, dict | None]:
        """
        Return ("tp" | "control_fp" | "fp", matched vuln or control).

        Exact parameter matches win. If the scanner omitted the parameter, a
        URL+method match is accepted as a best effort.
        """
        key = match_key(finding["url"], finding["method"], finding.get("parameter", ""))

        control = self.control_keys.get(key)
        if control:
            return "control_fp", control

        if not finding.get("parameter"):
            control = self.control_by_url_method.get((key[0], key[1]))
            if control and not self.by_key.get(key):
                return "control_fp", control

        candidates = self.by_key.get(key)
        if not candidates and not finding.get("parameter"):
            candidates = self.by_url_method.get((key[0], key[1]))

        if not candidates:
            return "fp", None

        agreeing = [v for v in candidates if agrees(v, finding)]
        if not agreeing:
            return "fp", None

        # Prefer the most specific (highest difficulty) match.
        agreeing.sort(key=lambda v: v.get("difficulty", 0), reverse=True)
        return "tp", agreeing[0]


def score(
    vulns: list[dict],
    controls: list[dict],
    findings: list[dict],
    triggered_ids: set[str],
) -> dict:
    matcher = Matcher(vulns, controls)
    matched: dict[str, dict] = {}
    duplicate_findings = 0
    false_positives: list[dict] = []
    control_hits: list[dict] = []

    for finding in findings:
        verdict, target = matcher.classify(finding)

        if verdict == "control_fp":
            finding = dict(finding)
            finding["control_id"] = target["id"]
            control_hits.append(finding)
            continue

        if verdict == "tp":
            vuln_id = target["id"]
            if vuln_id in matched:
                duplicate_findings += 1
                continue
            matched[vuln_id] = finding
            continue

        false_positives.append(finding)

    total_vulns = len(vulns)
    tp = len(matched)
    fn = total_vulns - tp
    fp = len(false_positives) + len(control_hits)
    precision = tp / (tp + fp) if (tp + fp) else (1.0 if tp else 0.0)
    recall = tp / total_vulns if total_vulns else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    matched_ids = set(matched)
    triggered = matched_ids & triggered_ids

    metrics = {
        "total_vulnerabilities": total_vulns,
        "total_findings": len(findings),
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "control_false_positives": len(control_hits),
        "unmatched_false_positives": len(false_positives),
        "duplicate_findings": duplicate_findings,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "fp_rate": round(fp / (tp + fp), 4) if (tp + fp) else 0.0,
        "exploit_proof": {
            "matched": tp,
            "triggered": len(triggered),
            "detection_only": tp - len(triggered),
            "triggered_vuln_ids": sorted(triggered),
        },
    }

    def breakdown(field: str, key_name: str) -> dict:
        groups: dict[str, dict] = defaultdict(lambda: {"total": 0, "tp": 0})
        for vuln in vulns:
            value = vuln.get(field) or "unknown"
            if isinstance(value, list):
                value = ",".join(value) if value else "unknown"
            groups[str(value)][key_name] = str(value)
            groups[str(value)]["total"] += 1
            if vuln["id"] in matched_ids:
                groups[str(value)]["tp"] += 1
        result = {}
        for value, stats in sorted(groups.items()):
            total = stats["total"]
            hit = stats["tp"]
            result[value] = {
                key_name: stats[key_name],
                "total": total,
                "detected": hit,
                "recall": round(hit / total, 4) if total else 0.0,
            }
        return result

    return {
        "metrics": metrics,
        "breakdown": {
            "owasp_web_2021": breakdown("owasp_web_2021", "owasp_web_2021"),
            "owasp_api_2023": breakdown("owasp_api_2023", "owasp_api_2023"),
            "cwe": breakdown("cwe", "cwe"),
            "service": breakdown("service", "service"),
            "difficulty": breakdown("difficulty", "difficulty"),
            "detection_class": breakdown("detection_class", "detection_class"),
        },
        "controls": {
            "total": len(controls),
            "findings_on_controls": len(control_hits),
            "fp_rate": round(len(control_hits) / len(controls), 4) if controls else 0.0,
        },
        "missed": [
            {
                "id": vuln["id"],
                "name": vuln.get("name", ""),
                "url": vuln["url"],
                "method": vuln["method"],
                "parameter": vuln.get("parameter", ""),
                "cwe": vuln.get("cwe", []),
                "difficulty": vuln.get("difficulty", 0),
            }
            for vuln in vulns
            if vuln["id"] not in matched_ids
        ],
        "false_positives": false_positives,
        "control_hits": control_hits,
    }


# ─── Events ──────────────────────────────────────────────────────────────────

def load_triggered_ids(events_source: str | None) -> set[str]:
    if not events_source:
        return set()

    try:
        if events_source.startswith("http://") or events_source.startswith("https://"):
            from urllib.request import urlopen

            with urlopen(events_source, timeout=10) as response:  # noqa: S310 - operator supplied lab URL
                events = json.load(response)
        else:
            with open(events_source, encoding="utf-8") as handle:
                events = json.load(handle)
    except Exception as exc:  # noqa: BLE001 - report should still be produced
        print(f"[warn] could not load events: {exc}", file=sys.stderr)
        return set()

    if isinstance(events, dict):
        events = events.get("events", [])

    return {
        event.get("vuln_id") for event in events
        if isinstance(event, dict) and event.get("kind") == "vuln_triggered" and event.get("vuln_id")
    }


# ─── Output ──────────────────────────────────────────────────────────────────

def write_json(path: Path, report: dict) -> None:
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def write_csv(path: Path, vulns: list[dict], matched_ids: set[str], triggered_ids: set[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow([
            "vuln_id", "status", "exploit_triggered", "cwe", "difficulty",
            "service", "detection_class", "url", "method", "parameter",
        ])
        for vuln in vulns:
            status = "detected" if vuln["id"] in matched_ids else "missed"
            triggered = vuln["id"] in triggered_ids
            writer.writerow([
                vuln["id"], status, str(triggered).lower(), ";".join(vuln.get("cwe", [])),
                vuln.get("difficulty", ""), vuln.get("service", ""),
                vuln.get("detection_class", ""), vuln["url"], vuln["method"],
                vuln.get("parameter", ""),
            ])


def write_html(path: Path, report: dict, vulns: list[dict], matched_ids: set[str],
               triggered_ids: set[str], scanner_name: str) -> None:
    metrics = report["metrics"]
    controls = report["controls"]

    def pct(value: float) -> str:
        return f"{value * 100:.1f}%"

    rows = []
    for vuln in vulns:
        detected = vuln["id"] in matched_ids
        triggered = vuln["id"] in triggered_ids
        rows.append(
            "<tr class='{cls}'><td>{id}</td><td>{name}</td><td>{level}</td>"
            "<td>{service}</td><td><code>{url}</code></td><td>{param}</td>"
            "<td>{detected}</td><td>{triggered}</td></tr>".format(
                cls="ok" if detected else "miss",
                id=html.escape(vuln["id"]),
                name=html.escape(vuln.get("name", "")),
                level=vuln.get("difficulty", ""),
                service=html.escape(vuln.get("service", "")),
                url=html.escape(vuln["url"]),
                param=html.escape(vuln.get("parameter", "")),
                detected="yes" if detected else "no",
                triggered="yes" if triggered else "no",
            )
        )

    breakdown_rows = []
    for name, groups in report["breakdown"].items():
        for value, stats in groups.items():
            breakdown_rows.append(
                f"<tr><td>{html.escape(name)}</td><td>{html.escape(value)}</td>"
                f"<td>{stats['detected']}/{stats['total']}</td>"
                f"<td>{pct(stats['recall'])}</td></tr>"
            )

    missed_rows = "".join(
        f"<tr><td>{html.escape(v['id'])}</td><td>{html.escape(v['name'])}</td>"
        f"<td>{html.escape(v['url'])}</td><td>{html.escape(str(v['cwe']))}</td></tr>"
        for v in report["missed"]
    ) or "<tr><td colspan='4'>None</td></tr>"

    document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>VulnForge Lab — Scanner Report</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #1b1b1b; }}
h1, h2 {{ font-weight: 600; }}
.cards {{ display: flex; gap: 1rem; flex-wrap: wrap; margin: 1rem 0; }}
.card {{ border: 1px solid #ddd; border-radius: 8px; padding: 1rem 1.25rem; min-width: 150px; }}
.card .value {{ font-size: 1.7rem; font-weight: 700; }}
table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; font-size: 0.9rem; }}
th, td {{ border: 1px solid #e2e2e2; padding: 0.45rem 0.6rem; text-align: left; vertical-align: top; }}
th {{ background: #f6f6f6; }}
tr.miss td {{ background: #fff1f1; }}
tr.ok td {{ background: #f2fff4; }}
code {{ font-size: 0.85rem; }}
</style>
</head>
<body>
<h1>VulnForge Lab — Scanner Report</h1>
<p>Scanner: <strong>{html.escape(scanner_name)}</strong></p>

<div class="cards">
  <div class="card"><div class="value">{pct(metrics['recall'])}</div><div>Recall</div></div>
  <div class="card"><div class="value">{pct(metrics['precision'])}</div><div>Precision</div></div>
  <div class="card"><div class="value">{pct(metrics['f1'])}</div><div>F1</div></div>
  <div class="card"><div class="value">{metrics['true_positives']}/{metrics['total_vulnerabilities']}</div><div>Detected</div></div>
  <div class="card"><div class="value">{metrics['false_positives']}</div><div>False positives</div></div>
  <div class="card"><div class="value">{controls['findings_on_controls']}</div><div>Findings on safe twins</div></div>
</div>

<h2>Exploit proof</h2>
<p>{metrics['exploit_proof']['triggered']} of {metrics['exploit_proof']['matched']} detected vulnerabilities
also produced a server-side trigger event (detection vs exploitation).</p>

<h2>Breakdown</h2>
<table>
<thead><tr><th>Dimension</th><th>Value</th><th>Detected</th><th>Recall</th></tr></thead>
<tbody>{''.join(breakdown_rows)}</tbody>
</table>

<h2>All vulnerabilities</h2>
<table>
<thead><tr><th>ID</th><th>Name</th><th>Level</th><th>Service</th><th>URL</th><th>Parameter</th><th>Detected</th><th>Triggered</th></tr></thead>
<tbody>{''.join(rows)}</tbody>
</table>

<h2>Missed vulnerabilities</h2>
<table>
<thead><tr><th>ID</th><th>Name</th><th>URL</th><th>CWE</th></tr></thead>
<tbody>{missed_rows}</tbody>
</table>
</body>
</html>
"""
    path.write_text(document, encoding="utf-8")


# ─── CLI ─────────────────────────────────────────────────────────────────────

def parse_threshold(value: str) -> tuple[str, float]:
    if "=" not in value:
        raise argparse.ArgumentTypeError("expected name=value, e.g. recall=0.80")
    name, raw = value.split("=", 1)
    return name.strip(), float(raw)


def main() -> int:
    parser = argparse.ArgumentParser(description="Score scanner output against VulnForge ground truth")
    parser.add_argument("--findings", required=True, help="scanner output file")
    parser.add_argument("--format", default="custom_json", help="adapter name (custom_json, sarif, zap, nuclei)")
    parser.add_argument("--truth-dir", default="lab/truth")
    parser.add_argument("--out-dir", default="scorer/out")
    parser.add_argument("--events", default=None, help="lab-control events JSON file or URL for exploit proof")
    parser.add_argument("--scanner-name", default="unknown")
    parser.add_argument("--fail-under", action="append", default=[], type=parse_threshold,
                        metavar="METRIC=VALUE", help="exit 1 when metric is below value (e.g. recall=0.80)")
    parser.add_argument("--fail-over", action="append", default=[], type=parse_threshold,
                        metavar="METRIC=VALUE", help="exit 1 when metric is above value (e.g. fp=0.05)")
    args = parser.parse_args()

    truth_dir = Path(args.truth_dir)
    vulns = json.loads((truth_dir / "vulns.json").read_text(encoding="utf-8"))
    controls = json.loads((truth_dir / "controls.json").read_text(encoding="utf-8"))

    try:
        findings = load_findings(args.format, args.findings)
    except (OSError, ValueError) as exc:
        print(f"[error] could not load findings: {exc}", file=sys.stderr)
        return 2

    triggered_ids = load_triggered_ids(args.events)
    report = score(vulns, controls, findings, triggered_ids)
    report["scanner"] = {"name": args.scanner_name, "adapter": args.format, "source": args.findings}
    report["lab"] = {
        "name": "VulnForge Lab",
        "version": "1.0.0",
        "author": "Cuma KURT",
        "license": "AGPL-3.0-only",
        "github": "https://github.com/cumakurt/vulnforge",
    }

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    matched_ids = {
        entry["id"] for entry in vulns
        if entry["id"] not in {missed["id"] for missed in report["missed"]}
    }

    write_json(out_dir / "report.json", report)
    write_csv(out_dir / "report.csv", vulns, matched_ids, triggered_ids)
    write_html(out_dir / "report.html", report, vulns, matched_ids, triggered_ids, args.scanner_name)

    metrics = report["metrics"]
    print(f"Recall:    {metrics['recall'] * 100:.1f}%  ({metrics['true_positives']}/{metrics['total_vulnerabilities']})")
    print(f"Precision: {metrics['precision'] * 100:.1f}%  (FP: {metrics['false_positives']})")
    print(f"F1:        {metrics['f1'] * 100:.1f}%")
    print(f"Safe-twin findings: {report['controls']['findings_on_controls']}")
    print(f"Reports: {out_dir / 'report.html'}, {out_dir / 'report.json'}, {out_dir / 'report.csv'}")

    failed = False
    slack = {
        "recall": metrics["recall"],
        "precision": metrics["precision"],
        "f1": metrics["f1"],
        "fp": metrics["fp_rate"],
        "fp_rate": metrics["fp_rate"],
        "control_fp": report["controls"]["fp_rate"],
    }

    for name, minimum in args.fail_under:
        actual = slack.get(name)
        if actual is None:
            print(f"[error] unknown threshold metric '{name}'", file=sys.stderr)
            return 2
        if actual < minimum:
            print(f"[fail] {name}={actual:.4f} is below {minimum}", file=sys.stderr)
            failed = True

    for name, maximum in args.fail_over:
        actual = slack.get(name)
        if actual is None:
            print(f"[error] unknown threshold metric '{name}'", file=sys.stderr)
            return 2
        if actual > maximum:
            print(f"[fail] {name}={actual:.4f} is above {maximum}", file=sys.stderr)
            failed = True

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
