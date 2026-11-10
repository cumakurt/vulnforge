"""
VulnForge Lab — flask-svc

Intentionally vulnerable Python service used for scanner benchmarking.
Covers SSTI, insecure deserialization, path traversal, SSRF, command
injection, weak randomness and related classes.

WARNING: never expose this service outside an isolated lab.
"""

import base64
import json
import os
import pickle
import random
import re
import secrets
import subprocess
import time
import urllib.parse
import urllib.request

import yaml
from flask import Flask, Response, make_response, redirect, render_template_string, request

app = Flask(__name__)

LAB_CONTROL_URL = os.environ.get("LAB_CONTROL_URL", "http://lab-control:9100")
OOB_COLLECTOR_URL = os.environ.get("OOB_COLLECTOR_URL", "http://oob-collector:9000")
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

# Deterministic seed so the "predictable token" finding is reproducible.
random.seed(1337)


def lab_trigger(vuln_id: str, extra: dict | None = None) -> None:
    payload = json.dumps({
        "kind": "vuln_triggered",
        "vuln_id": vuln_id,
        "service": "flask-svc",
        "request_id": request.headers.get("X-Request-Id", ""),
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
        **(extra or {}),
    }).encode()

    req = urllib.request.Request(
        f"{LAB_CONTROL_URL}/__lab/events",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=1).close()
    except Exception:
        pass


@app.get("/health")
def health():
    return {"status": "ok", "service": "flask-svc"}


# @vuln id=PY-001 name="Server-side template injection in greeting renderer" cwe=CWE-1336 owasp=A03:2021 type=ssti level=1 param=name method=GET service=flask-svc url=/py/ssti param_loc=query needs_oob=false auth=false detection=active tags=injection,ssti,template proof_kind=marker proof_desc="Jinja2 expression such as {{7*7}} is evaluated in the response"
@app.get("/py/ssti")
def ssti():
    name = request.args.get("name", "guest")

    # !! INTENTIONALLY VULNERABLE — user input becomes the template source !!
    rendered = render_template_string("Hello " + name + "!")

    if "{{" in name or "{%" in name:
        lab_trigger("PY-001", {"payload": name})
    return Response(rendered, mimetype="text/html")


# @control id=PY-001-C twin_of=PY-001 url=/py/ssti_safe method=GET param=name service=flask-svc param_loc=query
@app.get("/py/ssti_safe")
def ssti_safe():
    name = request.args.get("name", "guest")
    # SAFE: the template is constant and the value is a bound variable.
    rendered = render_template_string("Hello {{ name }}!", name=name)
    return Response(rendered, mimetype="text/html")


# @vuln id=PY-002 name="Insecure pickle deserialization of session payload" cwe=CWE-502 owasp=A08:2021 type=insecure-deserialization level=1 param=data method=POST service=flask-svc url=/py/pickle param_loc=body needs_oob=false auth=false detection=active tags=deserialization,pickle,rce proof_kind=marker proof_desc="A crafted pickle payload is deserialized and executes arbitrary Python"
@app.post("/py/pickle")
def pickle_view():
    raw = request.form.get("data") or request.get_data(as_text=True)

    try:
        decoded = base64.b64decode(raw)
    except Exception:
        return {"error": "data must be base64"}, 400

    # !! INTENTIONALLY VULNERABLE — pickle.loads on untrusted bytes !!
    try:
        result = pickle.loads(decoded)
    except Exception as exc:
        return {"error": str(exc)}, 400

    lab_trigger("PY-002", {"size": len(decoded)})
    return {"deserialized": str(result)}


# @control id=PY-002-C twin_of=PY-002 url=/py/pickle_safe method=POST param=data service=flask-svc param_loc=body
@app.post("/py/pickle_safe")
def pickle_safe():
    raw = request.form.get("data") or request.get_data(as_text=True)
    try:
        decoded = base64.b64decode(raw).decode("utf-8")
        result = json.loads(decoded)
    except Exception:
        return {"error": "data must be base64 encoded JSON"}, 400
    return {"deserialized": result}


# @vuln id=PY-003 name="yaml.load on untrusted input enables object construction" cwe=CWE-502 owasp=A08:2021 type=unsafe-yaml level=1 param=config method=POST service=flask-svc url=/py/yaml param_loc=body needs_oob=false auth=false detection=active tags=deserialization,yaml proof_kind=marker proof_desc="YAML tags such as !!python/object/apply are honoured by yaml.load"
@app.post("/py/yaml")
def yaml_view():
    raw = request.form.get("config") or request.get_data(as_text=True)

    # !! INTENTIONALLY VULNERABLE — full loader allows python object tags !!
    try:
        parsed = yaml.load(raw, Loader=yaml.Loader)
    except Exception as exc:
        return {"error": str(exc)}, 400

    lab_trigger("PY-003", {"keys": list(parsed.keys()) if isinstance(parsed, dict) else "scalar"})
    return {"parsed": str(parsed)}


# @control id=PY-003-C twin_of=PY-003 url=/py/yaml_safe method=POST param=config service=flask-svc param_loc=body
@app.post("/py/yaml_safe")
def yaml_safe():
    raw = request.form.get("config") or request.get_data(as_text=True)
    try:
        parsed = yaml.safe_load(raw)
    except Exception as exc:
        return {"error": str(exc)}, 400
    return {"parsed": parsed}


# @vuln id=PY-004 name="Path traversal in report download" cwe=CWE-22 owasp=A01:2021 type=path-traversal level=1 param=file method=GET service=flask-svc url=/py/download param_loc=query needs_oob=false auth=false detection=active tags=file,traversal,download proof_kind=marker proof_desc="Arbitrary files such as /etc/passwd are returned"
@app.get("/py/download")
def download():
    name = request.args.get("file", "welcome.txt")
    path = os.path.join(DATA_DIR, name)

    # !! INTENTIONALLY VULNERABLE — no normalisation, no allowlist !!
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            body = handle.read()
    except OSError:
        return {"error": f"file not found: {name}"}, 404

    if ".." in name or name.startswith("/"):
        lab_trigger("PY-004", {"payload": name})
    return Response(body, mimetype="text/plain")


# @control id=PY-004-C twin_of=PY-004 url=/py/download_safe method=GET param=file service=flask-svc param_loc=query
ALLOWED_REPORTS = {"welcome.txt", "about.txt", "contact.txt"}


@app.get("/py/download_safe")
def download_safe():
    name = request.args.get("file", "welcome.txt")
    if name not in ALLOWED_REPORTS:
        return {"error": "invalid file"}, 400

    path = os.path.join(DATA_DIR, name)
    try:
        with open(path, encoding="utf-8") as handle:
            return Response(handle.read(), mimetype="text/plain")
    except OSError:
        return {"error": "file not found"}, 404


# @vuln id=PY-005 name="SSRF in URL preview endpoint" cwe=CWE-918 owasp=A10:2021 type=ssrf level=1 param=url method=GET service=flask-svc url=/py/fetch param_loc=query needs_oob=false auth=false detection=active tags=ssrf proof_kind=marker proof_desc="Internal metadata service is fetched and returned to the client"
@app.get("/py/fetch")
def fetch():
    target = request.args.get("url", "")

    # !! INTENTIONALLY VULNERABLE — no scheme or host validation !!
    try:
        with urllib.request.urlopen(target, timeout=4) as response:
            body = response.read(4000).decode("utf-8", errors="replace")
            status = response.status
    except Exception as exc:
        return {"error": str(exc)}, 502

    lab_trigger("PY-005", {"url": target, "status": status})
    return {"status": status, "body": body}


# @control id=PY-005-C twin_of=PY-005 url=/py/fetch_safe method=GET param=url service=flask-svc param_loc=query
PRIVATE_PREFIXES = ("127.", "10.", "192.168.", "169.254.", "localhost", "0.0.0.0")


@app.get("/py/fetch_safe")
def fetch_safe():
    target = request.args.get("url", "")
    parsed = urllib.parse.urlparse(target)

    if parsed.scheme not in ("http", "https"):
        return {"error": "scheme not allowed"}, 400
    if not parsed.hostname or parsed.hostname.startswith(PRIVATE_PREFIXES):
        return {"error": "destination not allowed"}, 400

    try:
        with urllib.request.urlopen(target, timeout=4) as response:
            return {"status": response.status}
    except Exception:
        return {"error": "upstream unavailable"}, 502


# @vuln id=PY-006 name="OS command injection in host checker" cwe=CWE-78 owasp=A03:2021 type=os-command level=1 param=host method=GET service=flask-svc url=/py/ping param_loc=query needs_oob=false auth=false detection=active tags=injection,command,rce proof_kind=marker proof_desc="Shell metacharacters execute and their output is returned"
@app.get("/py/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")

    # !! INTENTIONALLY VULNERABLE — shell=True with concatenated input !!
    output = subprocess.run(
        f"echo {host}",
        shell=True,
        capture_output=True,
        text=True,
        timeout=10,
    )

    if any(char in host for char in ";|&`$()"):
        lab_trigger("PY-006", {"payload": host})
    return {"host": host, "output": output.stdout + output.stderr}


# @control id=PY-006-C twin_of=PY-006 url=/py/ping_safe method=GET param=host service=flask-svc param_loc=query
@app.get("/py/ping_safe")
def ping_safe():
    host = request.args.get("host", "127.0.0.1")
    if not re.fullmatch(r"[A-Za-z0-9.\-]{1,253}", host):
        return {"error": "invalid host"}, 400

    output = subprocess.run(
        ["echo", host],
        shell=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    return {"host": host, "output": output.stdout}


# @vuln id=PY-007 name="Werkzeug debugger console reachable" cwe=CWE-94 owasp=A05:2021 type=debug-console level=1 param=none method=GET service=flask-svc url=/py/console param_loc=path needs_oob=false auth=false detection=config tags=misconfiguration,debug,rce proof_kind=marker proof_desc="Interactive traceback console page is served with the PIN hint and stack frame list"
@app.get("/py/console")
def console():
    lab_trigger("PY-007", {})
    return Response(
        """<!doctype html><html><body>
<h1>Interactive Console</h1>
<p>Werkzeug powered traceback interpreter (debug mode enabled).</p>
<pre>Traceback (most recent call last):
  File "/app/app.py", line 42, in console
    raise RuntimeError("debug console")
RuntimeError: debug console</pre>
<form action="/py/console/execute" method="post">
  <textarea name="code" rows="6" cols="60">import os; os.getcwd()</textarea>
  <button type="submit">Execute</button>
</form>
</body></html>""",
        mimetype="text/html",
    )


# @control id=PY-007-C twin_of=PY-007 url=/py/console_safe method=GET param=none service=flask-svc param_loc=path
@app.get("/py/console_safe")
def console_safe():
    return {"error": "not found"}, 404


# @vuln id=PY-008 name="Open redirect after login" cwe=CWE-601 owasp=A01:2021 type=open-redirect level=1 param=next method=GET service=flask-svc url=/py/redirect param_loc=query needs_oob=false auth=false detection=active tags=redirect proof_kind=marker proof_desc="Location header points to an arbitrary external host"
@app.get("/py/redirect")
def open_redirect():
    target = request.args.get("next", "/")
    if target.startswith(("http://", "https://", "//")):
        lab_trigger("PY-008", {"payload": target})
    return redirect(target, code=302)


# @control id=PY-008-C twin_of=PY-008 url=/py/redirect_safe method=GET param=next service=flask-svc param_loc=query
@app.get("/py/redirect_safe")
def redirect_safe():
    target = request.args.get("next", "/")
    if target not in ("/", "/py/ssti_safe", "/py/download_safe"):
        return {"error": "invalid redirect target"}, 400
    return redirect(target, code=302)


# @vuln id=PY-009 name="Predictable password reset token" cwe=CWE-330 owasp=A02:2021 type=weak-random level=2 param=user method=GET service=flask-svc url=/py/reset_token param_loc=query needs_oob=false auth=false detection=active tags=crypto,random,token proof_kind=marker proof_desc="Repeated requests with the same seed produce the same predictable token sequence"
@app.get("/py/reset_token")
def reset_token():
    user = request.args.get("user", "guest")

    # !! INTENTIONALLY VULNERABLE — deterministic seed, not a CSPRNG !!
    # Re-seeding on every request makes the output trivially predictable.
    random.seed(1337)
    token = "".join(random.choice("0123456789abcdef") for _ in range(16))

    lab_trigger("PY-009", {"user": user, "token": token})
    return {"user": user, "token": token}


# @control id=PY-009-C twin_of=PY-009 url=/py/reset_token_safe method=GET param=user service=flask-svc param_loc=query
@app.get("/py/reset_token_safe")
def reset_token_safe():
    user = request.args.get("user", "guest")
    # SAFE: cryptographically secure randomness.
    return {"user": user, "token": secrets.token_urlsafe(24)}


# @vuln id=PY-010 name="Session cookie without security flags" cwe=CWE-614 owasp=A07:2021 type=insecure-cookie level=1 param=session method=GET service=flask-svc url=/py/login param_loc=cookie needs_oob=false auth=false detection=config tags=auth,session,cookie proof_kind=marker proof_desc="Set-Cookie lacks HttpOnly, Secure and SameSite attributes"
@app.get("/py/login")
def login():
    user = request.args.get("user", "guest")
    response = make_response({"logged_in": True, "user": user})

    # !! INTENTIONALLY VULNERABLE — no HttpOnly / Secure / SameSite !!
    response.set_cookie("session", f"user={user};role=admin")

    lab_trigger("PY-010", {"user": user})
    return response


# @control id=PY-010-C twin_of=PY-010 url=/py/login_safe method=GET param=session service=flask-svc param_loc=cookie
@app.get("/py/login_safe")
def login_safe():
    user = request.args.get("user", "guest")
    response = make_response({"logged_in": True, "user": user})
    # SAFE: opaque value plus all protective flags.
    response.set_cookie(
        "session",
        secrets.token_urlsafe(32),
        httponly=True,
        secure=True,
        samesite="Lax",
        max_age=1800,
    )
    return response


# @vuln id=PY-011 name="Catastrophic backtracking in email validator" cwe=CWE-1333 owasp=A04:2021 type=redos level=2 param=email method=GET service=flask-svc url=/py/validate param_loc=query needs_oob=false auth=false detection=active tags=dos,regex,redos proof_kind=diff proof_desc="Crafted input causes regex evaluation to take several seconds"
EMAIL_RE = re.compile(r"^([a-zA-Z0-9]+)*@([a-zA-Z0-9]+\.)+[a-zA-Z]{2,}$")


@app.get("/py/validate")
def validate():
    email = request.args.get("email", "user@example.com")

    started = time.monotonic()
    # !! INTENTIONALLY VULNERABLE — nested quantifier allows exponential backtracking !!
    valid = bool(EMAIL_RE.match(email))
    elapsed = time.monotonic() - started

    if elapsed >= 1.0:
        lab_trigger("PY-011", {"elapsed": round(elapsed, 2)})
    return {"email": email, "valid": valid, "elapsed": round(elapsed, 3)}


# @control id=PY-011-C twin_of=PY-011 url=/py/validate_safe method=GET param=email service=flask-svc param_loc=query
SAFE_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}$")


@app.get("/py/validate_safe")
def validate_safe():
    email = request.args.get("email", "user@example.com")
    started = time.monotonic()
    valid = bool(SAFE_EMAIL_RE.match(email[:320]))
    return {"email": email, "valid": valid, "elapsed": round(time.monotonic() - started, 3)}


# ─── Internal lab endpoints ──────────────────────────────────────────────────

@app.post("/__lab/internal/reset")
def lab_reset():
    random.seed(1337)
    return {"reset": True}


@app.post("/__lab/internal/seed")
def lab_seed():
    random.seed(1337)
    return {"seeded": True, "profile": request.args.get("profile", "small")}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
