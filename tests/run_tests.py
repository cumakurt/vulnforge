#!/usr/bin/env python3
"""
VulnForge Lab — exploitability (smoke) and safe-twin (control) test runner.

The runner is data driven: tests/payloads.json maps every vulnerability id to a
sequence of HTTP steps plus a check that proves the vulnerability. The same
steps are replayed against the control twin and must NOT satisfy the check.

Supported step keys
───────────────────
  method, path, params, data, json, headers, files
  use_token           name of a token captured earlier (adds Bearer header)
  capture_token       store response JSON field "token" under this alias
  capture_cookie      store the PHPSESSID cookie under this alias
  use_cookie          send a previously captured PHPSESSID value
  parallel            send the step N times concurrently
  check               step-level check (short-circuits the run)

Top-level keys:
  login      {url, json|data, params, token_path} or legacy {username, password}
  steps      list of steps
  check      final assertion
  control_check  assertion used for the safe twin instead of "exploit rejected"
  allow_redirects  (default true)

Usage:
  python3 tests/run_tests.py --mode smoke
  python3 tests/run_tests.py --mode controls
  python3 tests/run_tests.py --mode all --base-url http://127.0.0.1:8000
"""

import argparse
import json
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent
PAYLOADS = ROOT / "payloads.json"
VULNS = ROOT.parent / "lab" / "truth" / "vulns.json"
CONTROLS = ROOT.parent / "lab" / "truth" / "controls.json"


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"[error] missing file: {path}", file=sys.stderr)
        raise SystemExit(2)


def reset_lab(lab_control: str) -> None:
    try:
        response = requests.post(f"{lab_control}/__lab/reset", timeout=60)
        if response.status_code != 200:
            print(f"  [warn] reset returned HTTP {response.status_code}")
    except requests.RequestException as exc:
        print(f"  [warn] reset failed: {exc}")


def evaluate(response, elapsed: float, check: dict) -> tuple[bool, str]:
    body = response.text

    for needle in check.get("body_contains", []):
        if needle not in body:
            return False, f"body missing {needle!r}"
    for needle in check.get("not_body_contains", []):
        if needle in body:
            return False, f"body unexpectedly contains {needle!r}"

    pattern = check.get("body_regex")
    if pattern and not re.search(pattern, body):
        return False, f"body does not match {pattern!r}"

    if "status" in check and response.status_code != check["status"]:
        return False, f"expected status {check['status']}, got {response.status_code}"

    for name, expected in check.get("header_contains", {}).items():
        actual = response.headers.get(name, "")
        if expected not in actual:
            return False, f"header {name} missing {expected!r} (got {actual!r})"

    if "min_time" in check and elapsed < check["min_time"]:
        return False, f"elapsed {elapsed:.2f}s < {check['min_time']}s"

    return True, "ok"


def perform_login(session: requests.Session, base_url: str, login: dict):
    """Return a token (str), True for cookie logins, or None on failure."""
    try:
        if "url" in login:
            response = session.request(
                login.get("method", "POST"),
                f"{base_url}{login['url']}",
                params=login.get("params"),
                json=login.get("json"),
                data=login.get("data"),
                headers=login.get("headers", {}),
                timeout=20,
            )
            if response.status_code >= 400:
                return None
            if login.get("token_path"):
                node = response.json()
                for part in login["token_path"].split("."):
                    node = node[part]
                return node
            return True

        response = session.post(
            f"{base_url}/php/auth/login.php",
            data={"username": login["username"], "password": login["password"]},
            timeout=20,
        )
        if response.status_code == 200 and '"authenticated":true' in response.text:
            return True
        return None
    except (requests.RequestException, ValueError, KeyError) as exc:
        print(f"  [warn] login failed: {exc}")
        return None


def send_step(session, base_url, step, path, headers, tokens, cookies, allow_redirects):
    local_headers = dict(step.get("headers", {}))
    local_headers.update(headers)

    if "use_token" in step:
        value = tokens.get(step["use_token"])
        if not value:
            return None, 0.0, f"token alias {step['use_token']!r} was not captured"
        local_headers["Authorization"] = f"Bearer {value}"

    if "use_cookie" in step:
        value = cookies.get(step["use_cookie"])
        if not value:
            return None, 0.0, f"cookie alias {step['use_cookie']!r} was not captured"
        local_headers["Cookie"] = f"PHPSESSID={value}"

    files = None
    if "files" in step:
        files = {
            field: (spec["filename"], spec["content"], spec.get("content_type", "application/octet-stream"))
            for field, spec in step["files"].items()
        }

    started = time.monotonic()
    response = session.request(
        step.get("method", "GET"),
        f"{base_url}{path}",
        params=step.get("params"),
        data=step.get("data"),
        json=step.get("json"),
        headers=local_headers,
        files=files,
        allow_redirects=allow_redirects,
        timeout=40,
    )
    elapsed = time.monotonic() - started

    if "capture_token" in step:
        try:
            tokens[step["capture_token"]] = response.json()["token"]
        except (ValueError, KeyError):
            return None, elapsed, "token capture failed"

    if "capture_cookie" in step:
        value = session.cookies.get("PHPSESSID")
        if not value:
            return None, elapsed, "no PHPSESSID cookie to capture"
        cookies[step["capture_cookie"]] = value

    return response, elapsed, None


def execute_and_check(vuln, spec, base_url, control, mode):
    session = requests.Session()
    tokens: dict[str, str] = {}
    cookies: dict[str, str] = {}

    if "login" in spec:
        result = perform_login(session, base_url, spec["login"])
        if result is None:
            return False, "login failed"
        if isinstance(result, str):
            tokens["default"] = result

    vulnerability_url = vuln["url"]
    control_url = control["url"] if control else None
    control_check = spec.get("control_check")
    allow_redirects = spec.get("allow_redirects", True)

    steps = spec["steps"]
    if mode == "controls" and control_check:
        steps = [step for step in steps if step.get("path", vulnerability_url) == vulnerability_url]

    # Every step that targets the vulnerable URL is redirected to the twin when
    # the caller did not pin an explicit path.
    def target_path(step):
        return step.get("path", vulnerability_url)

    response = None
    elapsed = 0.0

    for step in steps:
        path = target_path(step)
        if mode == "controls" and control_url and path == vulnerability_url:
            path = control_url

        headers = {}
        if step.get("use_token") == "default" and "default" in tokens:
            headers["Authorization"] = f"Bearer {tokens['default']}"

        parallel = int(step.get("parallel", 0))
        if parallel > 1:
            def worker(_index):
                local = requests.Session()
                local.headers.update(session.headers)
                for cookie in session.cookies:
                    local.cookies.set(cookie.name, cookie.value)
                return send_step(local, base_url, step, path, headers, tokens, cookies, allow_redirects)

            with ThreadPoolExecutor(max_workers=parallel) as pool:
                outcomes = list(pool.map(worker, range(parallel)))

            failures = [outcome for outcome in outcomes if outcome[2]]
            if failures:
                return False, failures[0][2]
            successful = [outcome for outcome in outcomes if outcome[0] is not None]
            if not successful:
                return False, "parallel step produced no response"
            response, elapsed = successful[-1][0], successful[-1][1]
            continue

        try:
            response, elapsed, error = send_step(
                session, base_url, step, path, headers, tokens, cookies, allow_redirects
            )
        except requests.RequestException as exc:
            return False, f"request failed: {exc}"

        if error:
            return False, error
        if response is None:
            return False, "no response"

        if "check" in step:
            passed, reason = evaluate(response, elapsed, step["check"])
            if not passed:
                return False, reason

    if response is None:
        return False, "no steps executed"

    check = control_check if (mode == "controls" and control_check) else spec["check"]
    passed, reason = evaluate(response, elapsed, check)

    if mode == "controls" and not control_check:
        if passed:
            return False, "control twin satisfied the exploit check"
        return True, "control rejected exploit"

    return passed, reason


def main() -> int:
    parser = argparse.ArgumentParser(description="VulnForge smoke/control test runner")
    parser.add_argument("--mode", choices=["smoke", "controls", "all"], default="smoke")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--lab-control", default="http://127.0.0.1:9100")
    parser.add_argument("--no-reset", action="store_true", help="do not reset the lab before each test")
    parser.add_argument("--filter", default="", help="only run vuln ids containing this substring")
    args = parser.parse_args()

    vulns = load_json(VULNS)
    controls = load_json(CONTROLS)
    payloads = load_json(PAYLOADS)

    control_by_twin = {control["twin_of"]: control for control in controls}
    vulns_by_id = {vuln["id"]: vuln for vuln in vulns}

    modes = ["smoke", "controls"] if args.mode == "all" else [args.mode]
    failures: list[tuple[str, str, str]] = []
    tested = 0

    for mode in modes:
        print(f"\n=== {mode.upper()} ===")
        for vuln_id in sorted(payloads):
            if args.filter and args.filter not in vuln_id:
                continue
            if vuln_id not in vulns_by_id:
                print(f"  [skip] {vuln_id}: not present in vulns.json")
                continue

            spec = payloads[vuln_id]
            control = control_by_twin.get(vuln_id)

            if mode == "controls" and control is None:
                failures.append((vuln_id, "controls", "no control twin defined"))
                print(f"  FAIL {vuln_id}: no control twin defined")
                continue

            if not args.no_reset:
                reset_lab(args.lab_control)

            passed, reason = execute_and_check(vulns_by_id[vuln_id], spec, args.base_url, control, mode)
            tested += 1
            print(f"  {'PASS' if passed else 'FAIL'} {vuln_id}: {reason}")
            if not passed:
                failures.append((vuln_id, mode, reason))

    print(f"\n{tested} test(s) run, {len(failures)} failure(s)")
    for vuln_id, mode, reason in failures:
        print(f"  - {mode}/{vuln_id}: {reason}")

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
