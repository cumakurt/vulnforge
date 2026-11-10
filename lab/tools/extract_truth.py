#!/usr/bin/env python3
"""
extract_truth.py — VulnForge Lab ground-truth extractor.

Scans all service source files for @vuln / @control tags (inline comments or
decorators) and emits:
  lab/truth/vulns.json    — exploitable vulnerability entries
  lab/truth/controls.json — safe "twin" control entries

Supported tag formats
─────────────────────
PHP / JS / Go / Java (single-line comment):
  // @vuln id=SQLI-001 cwe=CWE-89 owasp=A03:2021 type=error-based level=1 param=id method=GET service=php-web url=/php/sqli/products.php param_loc=query needs_oob=false auth=false detection=active tags=injection,database proof_kind=marker proof_desc="DB error contains version()"

Python (decorator or comment):
  # @vuln id=SSTI-003 cwe=CWE-1336 ...
  @vuln(id="SSTI-003", cwe="CWE-1336", ...)

Control (safe twin):
  // @control id=SQLI-001-C twin_of=SQLI-001 url=/php/sqli/products_safe.php method=GET param=id service=php-web param_loc=query
  # @control id=SQLI-001-C twin_of=SQLI-001 ...

Usage:
  python3 lab/tools/extract_truth.py [--root <repo_root>] [--out-dir <output_dir>] [--validate] [--verbose]
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path

# ─── Schema for validation (mirrors lab/truth/schema.json) ───────────────────

VALID_SERVICES = {
    "php-web", "node-api", "flask-svc", "spring-svc", "go-svc",
    "graphql-svc", "crawl-lab", "legacy-svc", "auth-svc", "gateway", "infra",
}
VALID_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "ANY"}
VALID_PARAM_LOCS = {"query", "body", "header", "cookie", "path", "multipart", "json", "fragment"}
VALID_DETECTION = {"active", "passive", "sca", "config", "logic", "api"}
VALID_PROOF_KINDS = {"marker", "oob", "event", "diff"}
VALID_OWASP_WEB = {f"A{i:02d}" for i in range(1, 11)} | {None}
VALID_OWASP_API = {f"API{i}" for i in range(1, 11)} | {None}

# Files / dirs to skip
SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "vendor",
    "target", "build", "dist", ".mvn",
}
SCAN_EXTENSIONS = {
    ".php", ".js", ".ts", ".py", ".go", ".java", ".rb", ".cs",
    ".yaml", ".yml", ".json", ".html", ".tpl", ".j2", ".txt",
}

# ─── Tag parsers ─────────────────────────────────────────────────────────────

# Matches key=value or key="value with spaces"
KV_RE = re.compile(r'(\w+)=(?:"([^"]*?)"|([^\s"]+))')

# Single-line comment @vuln / @control
INLINE_TAG_RE = re.compile(
    r'(?://|#|--)\s*@(vuln|control)\s+(.*)',
    re.IGNORECASE,
)

# Python decorator @vuln(...)
DECORATOR_RE = re.compile(
    r'@vuln\(([^)]+)\)',
    re.IGNORECASE,
)


def _parse_kv(raw: str) -> dict:
    """Parse space-separated key=value pairs from a tag line."""
    result = {}
    for m in KV_RE.finditer(raw):
        key = m.group(1).lower()
        val = m.group(2) if m.group(2) is not None else m.group(3)
        result[key] = val
    return result


def _coerce_vuln(raw: dict, source_file: str, line_no: int) -> dict | None:
    """
    Coerce raw key/value dict into a canonical vuln entry.
    Returns None if required fields are missing.
    """
    errors = []

    def req(key):
        if key not in raw:
            errors.append(f"missing required field '{key}'")
        return raw.get(key)

    vuln_id = req("id")
    name = raw.get("name") or f"Vulnerability {vuln_id}"
    cwe_raw = req("cwe")
    service = req("service")
    url = req("url")
    method = (req("method") or "GET").upper()
    param = req("param")
    param_loc = raw.get("param_loc", "query").lower()
    vuln_type = req("type")
    level_raw = req("level")
    detection = raw.get("detection", "active").lower()

    # OWASP mapping (accept both "A03:2021" and "A03")
    owasp_raw = raw.get("owasp", "")
    owasp = None
    if owasp_raw:
        m = re.match(r'(A\d{2})', owasp_raw, re.IGNORECASE)
        owasp = m.group(1).upper() if m else None

    owasp_api_raw = raw.get("owasp_api", "")
    owasp_api = None
    if owasp_api_raw:
        m = re.match(r'(API\d+)', owasp_api_raw, re.IGNORECASE)
        owasp_api = m.group(1).upper() if m else None

    if errors:
        return None

    # Validate values
    if service not in VALID_SERVICES:
        errors.append(f"unknown service '{service}'")
    if method not in VALID_METHODS:
        errors.append(f"unknown method '{method}'")
    if param_loc not in VALID_PARAM_LOCS:
        errors.append(f"unknown param_loc '{param_loc}'")
    if detection not in VALID_DETECTION:
        errors.append(f"unknown detection class '{detection}'")

    try:
        difficulty = int(level_raw)
        if not (0 <= difficulty <= 4):
            errors.append(f"difficulty {difficulty} out of range 0-4")
    except (TypeError, ValueError):
        errors.append(f"invalid level '{level_raw}'")
        difficulty = 1

    if errors:
        print(f"  [WARN] {source_file}:{line_no} id={vuln_id}: {'; '.join(errors)}", file=sys.stderr)
        return None

    cwe_list = [c.strip() for c in cwe_raw.split(",") if c.strip()]

    # Optional fields
    cve_list = [c.strip() for c in raw.get("cve", "").split(",") if c.strip()]
    auth_required = raw.get("auth", "false").lower() in ("true", "1", "yes")
    needs_oob = raw.get("needs_oob", "false").lower() in ("true", "1", "yes")
    preconditions = [p.strip() for p in raw.get("preconditions", "").split(",") if p.strip()]
    tags = [t.strip() for t in raw.get("tags", "").split(",") if t.strip()]
    proof_kind = raw.get("proof_kind", "marker")
    proof_desc = raw.get("proof_desc", "")

    if proof_kind not in VALID_PROOF_KINDS:
        proof_kind = "marker"

    return {
        "id": vuln_id,
        "name": name,
        "cwe": cwe_list,
        "cve": cve_list,
        "owasp_web_2021": owasp,
        "owasp_api_2023": owasp_api,
        "service": service,
        "url": url,
        "method": method,
        "parameter": param,
        "parameter_location": param_loc,
        "type": vuln_type,
        "difficulty": difficulty,
        "auth_required": auth_required,
        "preconditions": preconditions,
        "detection_class": detection,
        "needs_oob": needs_oob,
        "exploit_proof": {
            "kind": proof_kind,
            "description": proof_desc,
        },
        "references": [],
        "tags": tags,
        "_source": f"{source_file}:{line_no}",
    }


def _coerce_control(raw: dict, source_file: str, line_no: int) -> dict | None:
    """Coerce raw kv dict into a canonical control (safe-twin) entry."""
    errors = []

    def req(key):
        if key not in raw:
            errors.append(f"missing required field '{key}'")
        return raw.get(key)

    ctrl_id = req("id")
    twin_of = req("twin_of")
    url = req("url")
    method = (raw.get("method") or "GET").upper()
    param = req("param")

    if errors:
        return None

    return {
        "id": ctrl_id,
        "twin_of": twin_of,
        "url": url,
        "method": method,
        "parameter": param,
        "expected": "no-finding",
        "_source": f"{source_file}:{line_no}",
    }


# ─── File scanner ─────────────────────────────────────────────────────────────

def scan_file(path: Path, root: Path) -> tuple[list[dict], list[dict]]:
    """Return (vulns, controls) extracted from a single source file."""
    vulns, controls = [], []
    rel = str(path.relative_to(root))
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        print(f"  [WARN] Cannot read {rel}: {e}", file=sys.stderr)
        return vulns, controls

    for lineno, line in enumerate(text.splitlines(), start=1):
        # Inline comment tags (// @vuln ..., # @vuln ..., -- @vuln ...)
        m = INLINE_TAG_RE.search(line)
        if m:
            tag_type = m.group(1).lower()
            raw = _parse_kv(m.group(2))
            if tag_type == "vuln":
                entry = _coerce_vuln(raw, rel, lineno)
                if entry:
                    vulns.append(entry)
            elif tag_type == "control":
                entry = _coerce_control(raw, rel, lineno)
                if entry:
                    controls.append(entry)
            continue

        # Python decorator @vuln(...)
        dm = DECORATOR_RE.search(line)
        if dm:
            raw = _parse_kv(dm.group(1))
            entry = _coerce_vuln(raw, rel, lineno)
            if entry:
                vulns.append(entry)

    return vulns, controls


def scan_tree(root: Path, verbose: bool = False) -> tuple[list[dict], list[dict]]:
    """Walk the repo tree and collect all @vuln / @control entries."""
    all_vulns: list[dict] = []
    all_controls: list[dict] = []

    self_path = Path(__file__).resolve()

    for dirpath, dirnames, filenames in os.walk(root):
        # Prune skipped directories in-place
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]

        for fname in filenames:
            fpath = Path(dirpath) / fname
            if fpath.suffix.lower() not in SCAN_EXTENSIONS:
                continue
            # The extractor's docstring contains example tags; never treat them
            # as real ground truth.
            if fpath.resolve() == self_path:
                continue
            if verbose:
                print(f"  Scanning {fpath.relative_to(root)}")
            v, c = scan_file(fpath, root)
            all_vulns.extend(v)
            all_controls.extend(c)

    return all_vulns, all_controls


# ─── Validation ───────────────────────────────────────────────────────────────

def validate(vulns: list[dict], controls: list[dict]) -> list[str]:
    """Return list of validation error strings."""
    errors: list[str] = []
    seen_ids: set[str] = set()
    vuln_id_set = {v["id"] for v in vulns}

    for v in vulns:
        vid = v["id"]
        if vid in seen_ids:
            errors.append(f"Duplicate vuln id '{vid}' at {v['_source']}")
        seen_ids.add(vid)

    ctrl_ids: set[str] = set()
    twin_ids: set[str] = set()
    for c in controls:
        cid = c["id"]
        if cid in ctrl_ids:
            errors.append(f"Duplicate control id '{cid}' at {c['_source']}")
        ctrl_ids.add(cid)
        twin_ids.add(c["twin_of"])

        twin = c["twin_of"]
        if twin not in vuln_id_set:
            errors.append(
                f"Control '{cid}' references unknown vuln '{twin}' at {c['_source']}"
            )

    for vuln in vulns:
        if vuln["id"] not in twin_ids:
            errors.append(
                f"Vuln '{vuln['id']}' has no control twin at {vuln['_source']}"
            )

    return errors


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Extract @vuln / @control tags and emit vulns.json + controls.json",
    )
    parser.add_argument(
        "--root",
        default=".",
        help="Repository root to scan (default: current directory)",
    )
    parser.add_argument(
        "--out-dir",
        default=None,
        help="Output directory (default: <root>/lab/truth/)",
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Validate generated files; exit 1 on errors",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
    )
    args = parser.parse_args()

    root = Path(args.root).resolve()
    out_dir = Path(args.out_dir).resolve() if args.out_dir else root / "lab" / "truth"
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[extract_truth] Scanning: {root}")
    vulns, controls = scan_tree(root, verbose=args.verbose)

    # Sort for deterministic output
    vulns.sort(key=lambda x: x["id"])
    controls.sort(key=lambda x: x["id"])

    # Strip internal _source field before writing (keep for validation output)
    def strip_internal(entries):
        return [{k: v for k, v in e.items() if not k.startswith("_")} for e in entries]

    vulns_path = out_dir / "vulns.json"
    controls_path = out_dir / "controls.json"

    vulns_path.write_text(
        json.dumps(strip_internal(vulns), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    controls_path.write_text(
        json.dumps(strip_internal(controls), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    print(f"[extract_truth] Wrote {len(vulns)} vulns  → {vulns_path}")
    print(f"[extract_truth] Wrote {len(controls)} controls → {controls_path}")

    if args.validate:
        errors = validate(vulns, controls)
        if errors:
            print("\n[extract_truth] VALIDATION ERRORS:")
            for e in errors:
                print(f"  ✗ {e}")
            sys.exit(1)
        else:
            print("[extract_truth] Validation passed ✓")


if __name__ == "__main__":
    main()
