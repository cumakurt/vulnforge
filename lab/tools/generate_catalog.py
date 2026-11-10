#!/usr/bin/env python3
"""
Generate the vulnerability catalog from the ground-truth files.

Usage:
  python3 lab/tools/generate_catalog.py [--truth-dir lab/truth] [--out docs/vulnerability-catalog.md]
"""

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


TEXTS = {
    "en": {
        "title": "# Vulnerability catalog",
        "intro": [
            "Auto-generated from the `@vuln` source tags by",
            "`lab/tools/generate_catalog.py`. Do not edit by hand; regenerate with",
            "`make catalog`.",
        ],
        "total": "Total vulnerabilities",
        "controls": "Safe control twins",
        "distribution": "## Distribution",
        "dimension": "Dimension",
        "value": "Value",
        "count": "Count",
        "difficulty": "Difficulty",
        "owasp_web": "OWASP Web 2021",
        "owasp_api": "OWASP API 2023",
        "detection": "Detection class",
        "service": "Service",
        "id": "ID", "level": "Level", "type": "Type", "method": "Method",
        "url": "URL", "param": "Parameter", "cwe": "CWE", "twin": "Twin",
    },
    "tr": {
        "title": "# Zafiyet kataloğu",
        "intro": [
            "`@vuln` kaynak etiketlerinden otomatik üretilir",
            "(`lab/tools/generate_catalog.py`). Elle düzenlemeyin; `make catalog`",
            "komutuyla yeniden üretin.",
        ],
        "total": "Toplam zafiyet",
        "controls": "Güvenli kontrol ikizi",
        "distribution": "## Dağılım",
        "dimension": "Boyut",
        "value": "Değer",
        "count": "Adet",
        "difficulty": "Zorluk",
        "owasp_web": "OWASP Web 2021",
        "owasp_api": "OWASP API 2023",
        "detection": "Tespit sınıfı",
        "service": "Servis",
        "id": "ID", "level": "Seviye", "type": "Tür", "method": "Metot",
        "url": "URL", "param": "Parametre", "cwe": "CWE", "twin": "İkiz",
    },
}


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate the vulnerability catalog")
    parser.add_argument("--truth-dir", default="lab/truth")
    parser.add_argument("--out", default=None)
    parser.add_argument("--lang", choices=["en", "tr"], default="en")
    args = parser.parse_args()

    text = TEXTS[args.lang]
    if args.out is None:
        args.out = "docs/vulnerability-catalog.md" if args.lang == "en" else "docs/tr/zafiyet-katalogu.md"

    truth = Path(args.truth_dir)
    vulns = load(truth / "vulns.json")
    controls = load(truth / "controls.json")
    control_by_twin = {control["twin_of"]: control for control in controls}

    by_service = defaultdict(list)
    for vuln in vulns:
        by_service[vuln["service"]].append(vuln)

    levels = Counter(vuln["difficulty"] for vuln in vulns)
    owasp = Counter(vuln.get("owasp_web_2021") or "other" for vuln in vulns)
    api = Counter(vuln.get("owasp_api_2023") for vuln in vulns if vuln.get("owasp_api_2023"))
    detection = Counter(vuln["detection_class"] for vuln in vulns)

    lines: list[str] = []
    lines.append(text["title"])
    lines.append("")
    lines.extend(text["intro"])
    lines.append("")
    lines.append(f"{text['total']}: **{len(vulns)}**")
    lines.append(f"{text['controls']}: **{len(controls)}**")
    lines.append("")
    lines.append(text["distribution"])
    lines.append("")
    lines.append(f"| {text['dimension']} | {text['value']} | {text['count']} |")
    lines.append("|---|---|---|")
    for level in sorted(levels):
        lines.append(f"| {text['difficulty']} | L{level} | {levels[level]} |")
    for category, count in sorted(owasp.items()):
        lines.append(f"| {text['owasp_web']} | {category} | {count} |")
    for category, count in sorted(api.items()):
        lines.append(f"| {text['owasp_api']} | {category} | {count} |")
    for kind, count in sorted(detection.items()):
        lines.append(f"| {text['detection']} | {kind} | {count} |")
    for service, entries in sorted(by_service.items()):
        lines.append(f"| {text['service']} | {service} | {len(entries)} |")
    lines.append("")

    for service in sorted(by_service):
        lines.append(f"## {service}")
        lines.append("")
        lines.append(
            f"| {text['id']} | {text['level']} | {text['type']} | {text['method']} | "
            f"{text['url']} | {text['param']} | OWASP | {text['cwe']} | {text['twin']} |"
        )
        lines.append("|---|---|---|---|---|---|---|---|---|")
        for vuln in sorted(by_service[service], key=lambda item: item["id"]):
            twin = control_by_twin.get(vuln["id"])
            lines.append(
                "| {id} | L{level} | {type} | {method} | `{url}` | `{param}` | {owasp} | {cwe} | {twin} |".format(
                    id=vuln["id"],
                    level=vuln["difficulty"],
                    type=vuln["type"],
                    method=vuln["method"],
                    url=vuln["url"],
                    param=vuln.get("parameter", ""),
                    owasp=vuln.get("owasp_web_2021") or "-",
                    cwe=", ".join(vuln.get("cwe", [])),
                    twin=f"`{twin['url']}`" if twin else "-",
                )
            )
        lines.append("")

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote catalog with {len(vulns)} entries → {args.out}")


if __name__ == "__main__":
    main()
