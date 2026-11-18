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
    # Also clear auth state
    _auth_codes.clear()
    _access_tokens.clear()
    return {"reset": True}


@app.post("/__lab/internal/seed")
def lab_seed():
    random.seed(1337)
    return {"seeded": True, "profile": request.args.get("profile", "small")}


# ═══════════════════════════════════════════════════════════════════════════════
# AUTH-SVC ROUTES (merged from auth-svc — OAUTH-001..007)
# Previously: separate Python stdlib server on port 8080
# Now: Flask blueprint at /auth/*
# ═══════════════════════════════════════════════════════════════════════════════

import secrets as _secrets

_USERS = {"alice": "password1", "bob": "qwerty", "admin": "admin123"}
_ALLOWED_REDIRECTS = {
    "http://127.0.0.1:8000/auth/callback",
    "http://localhost:8000/auth/callback",
}
_auth_codes: dict = {}
_access_tokens: dict = {}


def _auth_trigger(vuln_id: str, extra: dict | None = None) -> None:
    payload = json.dumps({
        "kind": "vuln_triggered",
        "vuln_id": vuln_id,
        "service": "auth-svc",
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
def _health_check():
    return {"status": "ok", "service": "flask-svc"}


@app.get("/auth/health")
def auth_health():
    return {"status": "ok", "service": "auth-svc"}


@app.get("/auth/.well-known/openid-configuration")
def auth_oidc_config():
    return {
        "issuer": "http://127.0.0.1:8000/auth",
        "authorization_endpoint": "/auth/authorize",
        "token_endpoint": "/auth/token",
        "response_types_supported": ["code", "token"],
        "scopes_supported": ["read", "write", "admin"],
    }


# @vuln id=OAUTH-001 name="OAuth redirect_uri is not validated" cwe=CWE-601 owasp=A01:2021 type=open-redirect-uri level=1 param=redirect_uri method=GET service=auth-svc url=/auth/authorize param_loc=query needs_oob=false auth=false detection=active tags=oauth,redirect,authorization proof_kind=marker proof_desc="Authorization code is delivered to an attacker-controlled redirect_uri"
# @vuln id=OAUTH-002 name="OAuth authorization request does not require state" cwe=CWE-352 owasp=A01:2021 type=missing-state level=2 param=state method=GET service=auth-svc url=/auth/authorize param_loc=query needs_oob=false auth=false detection=active tags=oauth,csrf,state proof_kind=marker proof_desc="Authorization succeeds without a state parameter, enabling login CSRF"
@app.get("/auth/authorize")
def auth_authorize():
    redirect_uri = request.args.get("redirect_uri", "")
    code = _secrets.token_hex(8)
    _auth_codes[code] = {"user": "alice", "scope": request.args.get("scope", "read")}
    target = f"{redirect_uri}?code={code}"
    if request.args.get("state"):
        target += f"&state={request.args['state']}"
    _auth_trigger("OAUTH-001", {"redirect_uri": redirect_uri})
    if redirect_uri.startswith(("http://", "https://")) and redirect_uri not in _ALLOWED_REDIRECTS:
        _auth_trigger("OAUTH-002", {"state_provided": bool(request.args.get("state"))})
    return redirect(target, code=302)


@app.get("/auth/authorize_safe")
def auth_authorize_safe():
    redirect_uri = request.args.get("redirect_uri", "")
    if redirect_uri not in _ALLOWED_REDIRECTS:
        return {"error": "invalid redirect_uri"}, 400
    if not request.args.get("state"):
        return {"error": "state is required"}, 400
    code = _secrets.token_hex(8)
    _auth_codes[code] = {"user": "alice", "scope": "read"}
    return redirect(f"{redirect_uri}?code={code}&state={request.args['state']}", code=302)


# @vuln id=OAUTH-003 name="Implicit flow returns the access token in the fragment" cwe=CWE-598 owasp=A07:2021 type=implicit-flow level=2 param=redirect_uri method=GET service=auth-svc url=/auth/implicit param_loc=query needs_oob=false auth=false detection=active tags=oauth,implicit,token-leak proof_kind=marker proof_desc="Location header contains #access_token=..."
@app.get("/auth/implicit")
def auth_implicit():
    redirect_uri = request.args.get("redirect_uri", "")
    token = _secrets.token_hex(16)
    _access_tokens[token] = {"user": "alice", "scope": "read"}
    _auth_trigger("OAUTH-003", {"redirect_uri": redirect_uri})
    return redirect(f"{redirect_uri}#access_token={token}&token_type=bearer", code=302)


@app.get("/auth/implicit_safe")
def auth_implicit_safe():
    return {"error": "implicit flow is disabled, use authorization code with PKCE"}, 400


# @vuln id=OAUTH-005 name="Scope escalation accepted without consent" cwe=CWE-269 owasp=A01:2021 type=scope-escalation level=2 param=scope method=GET service=auth-svc url=/auth/scope param_loc=query needs_oob=false auth=true detection=active tags=oauth,scope,privilege-escalation proof_kind=marker proof_desc="Requesting admin scope returns an admin token for a normal user"
@app.get("/auth/scope")
def auth_scope():
    scope = request.args.get("scope", "read")
    token = _secrets.token_hex(16)
    _access_tokens[token] = {"user": "alice", "scope": scope}
    _auth_trigger("OAUTH-005", {"scope": scope})
    from flask import Response as _FlaskResp
    return _FlaskResp(
        json.dumps({"access_token": token, "scope": scope, "role": "admin" if "admin" in scope else "user"}, separators=(', ', ': ')),
        mimetype="application/json"
    )


@app.get("/auth/scope_safe")
def auth_scope_safe():
    token = _secrets.token_hex(16)
    _access_tokens[token] = {"user": "alice", "scope": "read"}
    return {"access_token": token, "scope": "read", "role": "user"}


# @vuln id=OAUTH-004 name="Token endpoint does not require PKCE" cwe=CWE-287 owasp=A07:2021 type=missing-pkce level=2 param=code method=POST service=auth-svc url=/auth/token param_loc=body needs_oob=false auth=false detection=active tags=oauth,pkce,authorization proof_kind=marker proof_desc="An authorization code is exchanged without any code_verifier"
@app.post("/auth/token")
def auth_token():
    code = request.form.get("code", "")
    token = _secrets.token_hex(16)
    _access_tokens[token] = {"user": "alice", "scope": "read"}
    _auth_trigger("OAUTH-004", {"code": code, "pkce": bool(request.form.get("code_verifier"))})
    return {"access_token": token, "token_type": "bearer", "expires_in": 3600}


@app.post("/auth/token_safe")
def auth_token_safe():
    if not request.form.get("code_verifier"):
        return {"error": "code_verifier is required (PKCE)"}, 400
    token = _secrets.token_hex(16)
    return {"access_token": token, "token_type": "bearer"}


# @vuln id=OAUTH-006 name="SAML assertion accepted without signature validation" cwe=CWE-347 owasp=A07:2021 type=saml-unsigned level=2 param=SAMLResponse method=POST service=auth-svc url=/auth/saml/acs param_loc=body needs_oob=false auth=false detection=active tags=saml,auth,signature proof_kind=marker proof_desc="An unsigned assertion is accepted and grants the admin role"
import base64 as _b64

@app.post("/auth/saml/acs")
def auth_saml_acs():
    raw = request.form.get("SAMLResponse", "")
    try:
        xml = _b64.b64decode(raw).decode("utf-8", errors="replace")
    except Exception:
        xml = ""
    if "<saml" not in xml.lower():
        return {"error": "invalid SAMLResponse"}, 400
    _auth_trigger("OAUTH-006", {"signed": "SignatureValue" in xml})
    from flask import Response as _FlaskResp2
    return _FlaskResp2(
        json.dumps({"authenticated": True, "user": "admin", "role": "admin", "signature_verified": False}, separators=(', ', ': ')),
        mimetype="application/json"
    )


@app.post("/auth/saml/acs_safe")
def auth_saml_acs_safe():
    raw = request.form.get("SAMLResponse", "")
    try:
        xml = _b64.b64decode(raw).decode("utf-8", errors="replace")
    except Exception:
        xml = ""
    if "SignatureValue" not in xml:
        return {"error": "assertion is not signed"}, 400
    return {"authenticated": True, "signature_verified": True}


# @vuln id=OAUTH-007 name="Username enumeration in the login endpoint" cwe=CWE-204 owasp=A07:2021 type=user-enumeration level=1 param=username method=POST service=auth-svc url=/auth/login param_loc=body needs_oob=false auth=false detection=passive tags=auth,enumeration,info-leak proof_kind=marker proof_desc="Unknown users and wrong passwords produce different messages"
@app.post("/auth/login")
def auth_login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    if username not in _USERS:
        _auth_trigger("OAUTH-007", {"username": username, "exists": False})
        return {"error": "unknown user"}, 401
    if _USERS[username] != password:
        return {"error": "wrong password"}, 401
    return {"authenticated": True, "token": _secrets.token_hex(16)}


@app.post("/auth/login_safe")
def auth_login_safe():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    if _USERS.get(username) == password:
        return {"authenticated": True, "token": _secrets.token_hex(16)}
    return {"authenticated": False, "error": "invalid credentials"}, 401


@app.get("/__lab/internal/reset_auth")
def auth_lab_reset():
    _auth_codes.clear()
    _access_tokens.clear()
    return {"reset": True}


# ═══════════════════════════════════════════════════════════════════════════════
# LEGACY-SVC ROUTES (merged from legacy-svc — LEG-001..007)
# Previously: separate Python stdlib server on port 8888 simulating Apache/PHP
# Now: Flask routes at /legacy/*
# ═══════════════════════════════════════════════════════════════════════════════

_LEGACY_BANNER = "Apache/2.2.15 (CentOS)"

_LEGACY_INDEX = """<!doctype html>
<html>
<head><title>Legacy Shop</title></head>
<body>
<h1>Legacy Shop</h1>
<p>Welcome to our store.</p>
<script src="/legacy/assets/jquery-1.8.3.min.js"></script>
<script src="/legacy/assets/app.js"></script>
<!-- admin panel: /legacy/admin/login.php -->
</body>
</html>"""

_LEGACY_JQUERY = """/*! jQuery v1.8.3 jquery.com | (c) 2010-2012 John Resig */
/* Intentionally old jQuery build used for SCA testing. */
(function(window, undefined) { window.jQuery = function(selector) { return { selector: selector }; }; })(window);"""

_LEGACY_BACKUP = """<!doctype html>
<html><head><title>Index of /backup</title></head>
<body><h1>Index of /backup</h1>
<ul>
<li><a href="db-2024-01.sql">db-2024-01.sql</a></li>
<li><a href="site-2024-01.tar.gz">site-2024-01.tar.gz</a></li>
<li><a href="config.old.php">config.old.php</a></li>
</ul></body></html>"""


def _legacy_trigger(vuln_id: str, extra: dict | None = None) -> None:
    payload = json.dumps({
        "kind": "vuln_triggered",
        "vuln_id": vuln_id,
        "service": "legacy-svc",
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


def _legacy_response(body: str, status: int = 200, content_type: str = "text/html; charset=utf-8", extra_headers: dict | None = None):
    from flask import Response as _Resp
    resp = _Resp(body, status=status, mimetype=content_type)
    resp.headers["Server"] = _LEGACY_BANNER
    resp.headers["X-Powered-By"] = "PHP/5.3.3"
    if extra_headers:
        for k, v in extra_headers.items():
            resp.headers[k] = v
    return resp


@app.get("/legacy/health")
def legacy_health():
    return {"status": "ok", "service": "legacy-svc"}


# @vuln id=LEG-001 name="End-of-life jQuery 1.8.3 shipped to clients" cwe=CWE-1104 owasp=A06:2021 type=outdated-component level=1 param=none method=GET service=legacy-svc url=/legacy/ param_loc=path needs_oob=false auth=false detection=sca tags=sca,outdated,jquery proof_kind=marker proof_desc="The page references jquery-1.8.3.min.js, a version with known XSS CVEs"
@app.get("/legacy/")
@app.get("/legacy/index.html")
@app.get("/legacy/index.php")
def legacy_index():
    _legacy_trigger("LEG-001", {})
    return _legacy_response(_LEGACY_INDEX)


@app.get("/legacy/index_safe.html")
def legacy_index_safe():
    return _legacy_response("<!doctype html><html><head><title>Legacy Shop (hardened)</title></head><body><h1>Legacy Shop</h1><script src='/legacy/assets/app_safe.js'></script></body></html>")


@app.get("/legacy/assets/jquery-1.8.3.min.js")
def legacy_jquery():
    return _legacy_response(_LEGACY_JQUERY, content_type="application/javascript")


@app.get("/legacy/assets/app.js")
@app.get("/legacy/assets/app_safe.js")
def legacy_app_js():
    return _legacy_response("console.log('legacy app loaded');\n", content_type="application/javascript")


# @vuln id=LEG-002 name="Backup configuration file publicly readable" cwe=CWE-538 owasp=A05:2021 type=backup-file level=1 param=none method=GET service=legacy-svc url=/legacy/config.php.bak param_loc=path needs_oob=false auth=false detection=config tags=misconfiguration,info-leak,backup proof_kind=marker proof_desc="config.php.bak contains database credentials"
@app.get("/legacy/config.php.bak")
def legacy_config_bak():
    _legacy_trigger("LEG-002", {})
    body = "<?php\ndefine('DB_HOST','mysql');\ndefine('DB_USER','legacy_user');\ndefine('DB_PASSWORD','legacy_backup_password');\ndefine('DB_NAME','legacy_shop');\n"
    return _legacy_response(body, content_type="text/plain")


@app.get("/legacy/config_safe.bak")
def legacy_config_safe():
    return _legacy_response("not found", status=404, content_type="text/plain")


# @vuln id=LEG-003 name="Exposed .git metadata allows source reconstruction" cwe=CWE-527 owasp=A05:2021 type=vcs-exposure level=1 param=none method=GET service=legacy-svc url=/legacy/.git/config param_loc=path needs_oob=false auth=false detection=config tags=misconfiguration,info-leak,git proof_kind=marker proof_desc=".git/config is served with the repository remote and local paths"
@app.get("/legacy/.git/config")
def legacy_git_config():
    _legacy_trigger("LEG-003", {})
    body = '[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n[remote "origin"]\n\turl = https://git.example.invalid/legacy-shop.git\n'
    return _legacy_response(body, content_type="text/plain")


@app.get("/legacy/git_safe/config")
def legacy_git_safe():
    return _legacy_response("not found", status=404, content_type="text/plain")


# @vuln id=LEG-004 name="Directory listing exposes database dumps" cwe=CWE-548 owasp=A05:2021 type=directory-listing level=1 param=none method=GET service=legacy-svc url=/legacy/backup/ param_loc=path needs_oob=false auth=false detection=config tags=misconfiguration,info-leak,directory-listing proof_kind=marker proof_desc="Apache style index lists SQL and archive backups"
@app.get("/legacy/backup/")
@app.get("/legacy/backup")
def legacy_backup():
    _legacy_trigger("LEG-004", {})
    return _legacy_response(_LEGACY_BACKUP)


@app.get("/legacy/backup_safe/")
@app.get("/legacy/backup_safe")
def legacy_backup_safe():
    return _legacy_response("Forbidden", status=403, content_type="text/plain")


# @vuln id=LEG-005 name="Default administrative credentials admin/admin" cwe=CWE-1392 owasp=A07:2021 type=default-credentials level=1 param=username method=POST service=legacy-svc url=/legacy/admin/login.php param_loc=body needs_oob=false auth=false detection=active tags=auth,default-credentials proof_kind=marker proof_desc="admin/admin authenticates and returns an administrative session"
# @vuln id=LEG-006 name="Server banner discloses end-of-life software versions" cwe=CWE-200 owasp=A05:2021 type=banner-disclosure level=1 param=none method=GET service=legacy-svc url=/legacy/banner param_loc=path needs_oob=false auth=false detection=config tags=misconfiguration,info-leak,banner proof_kind=marker proof_desc="Server header reports Apache 2.2.15 and PHP 5.3.3"
# @vuln id=LEG-007 name="WordPress readme reveals the CMS version" cwe=CWE-200 owasp=A06:2021 type=cms-version-disclosure level=1 param=none method=GET service=legacy-svc url=/legacy/readme.html param_loc=path needs_oob=false auth=false detection=sca tags=sca,info-leak,wordpress proof_kind=marker proof_desc="readme.html states WordPress 4.1, a version with known vulnerabilities"

@app.get("/legacy/admin/login.php")
def legacy_admin_login_form():
    return _legacy_response("<form method='post'><input name='username'><input name='password' type='password'><button>Login</button></form>")


@app.post("/legacy/admin/login.php")
def legacy_admin_login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    if username == "admin" and password == "admin":
        import base64 as _b
        _legacy_trigger("LEG-005", {"username": username})
        return _legacy_response(
            json.dumps({"authenticated": True, "role": "admin", "session": _b.b64encode(b"admin:legacy").decode()}),
            content_type="application/json",
        )
    return _legacy_response(json.dumps({"authenticated": False}), status=401, content_type="application/json")


@app.post("/legacy/admin/login_safe.php")
def legacy_admin_login_safe():
    return _legacy_response(json.dumps({"error": "default credentials disabled"}), status=403, content_type="application/json")


@app.get("/legacy/banner")
def legacy_banner():
    _legacy_trigger("LEG-006", {})
    return _legacy_response("Apache/2.2.15 (CentOS) PHP/5.3.3 mod_ssl/2.2.15", content_type="text/plain")


@app.get("/legacy/banner_safe")
def legacy_banner_safe():
    from flask import Response as _Resp
    resp = _Resp("web server", mimetype="text/plain")
    resp.headers["Server"] = "nginx"
    return resp


@app.get("/legacy/readme.html")
def legacy_readme():
    _legacy_trigger("LEG-007", {})
    return _legacy_response("<h1>WordPress</h1><p>Version 4.1</p>")


@app.get("/legacy/readme_safe.html")
def legacy_readme_safe():
    return _legacy_response("not found", status=404, content_type="text/plain")


@app.get("/__lab/internal/reset_legacy")
def legacy_lab_reset():
    return {"reset": True}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
