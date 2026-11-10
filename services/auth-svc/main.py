"""
VulnForge Lab — auth-svc

Simulates an OAuth 2.0 / OIDC / SAML identity provider with intentionally weak
validation: open redirect_uri, missing state, implicit flow, no PKCE, scope
escalation, unsigned SAML assertions and username enumeration.

WARNING: never expose this service outside an isolated lab.
"""

import base64
import json
import os
import secrets
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LAB_CONTROL_URL = os.environ.get("LAB_CONTROL_URL", "http://lab-control:9100")
PORT = int(os.environ.get("PORT", "8080"))

ALLOWED_REDIRECTS = {"http://127.0.0.1:8000/auth/callback", "http://localhost:8000/auth/callback"}

USERS = {
    "alice": "password1",
    "bob": "qwerty",
    "admin": "admin123",
}

AUTH_CODES: dict[str, dict] = {}
ACCESS_TOKENS: dict[str, dict] = {}


def lab_trigger(vuln_id: str, handler, extra: dict | None = None) -> None:
    payload = json.dumps({
        "kind": "vuln_triggered",
        "vuln_id": vuln_id,
        "service": "auth-svc",
        "request_id": handler.headers.get("X-Request-Id", ""),
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
        **(extra or {}),
    }).encode()

    request = urllib.request.Request(
        f"{LAB_CONTROL_URL}/__lab/events",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(request, timeout=1).close()
    except Exception:
        pass


class Handler(BaseHTTPRequestHandler):
    server_version = "VulnForgeAuth/1.0"

    def log_message(self, fmt, *args):
        pass

    def _send(self, status: int, body: str, content_type="application/json", headers=None):
        encoded = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(encoded)

    def _redirect(self, location: str):
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _form(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        return {key: values[0] for key, values in urllib.parse.parse_qs(body).items()}

    # ─── GET ────────────────────────────────────────────────────────────────

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = {key: values[0] for key, values in urllib.parse.parse_qs(parsed.query).items()}

        if path == "/health":
            return self._send(200, json.dumps({"status": "ok", "service": "auth-svc"}))

        if path == "/.well-known/openid-configuration":
            return self._send(200, json.dumps({
                "issuer": "http://127.0.0.1:8000/auth",
                "authorization_endpoint": "/auth/authorize",
                "token_endpoint": "/auth/token",
                "response_types_supported": ["code", "token"],
                "scopes_supported": ["read", "write", "admin"],
            }))

        # @vuln id=OAUTH-002 name="OAuth authorization request does not require state" cwe=CWE-352 owasp=A01:2021 type=missing-state level=2 param=state method=GET service=auth-svc url=/auth/authorize param_loc=query needs_oob=false auth=false detection=active tags=oauth,csrf,state proof_kind=marker proof_desc="Authorization succeeds without a state parameter, enabling login CSRF"
        # @vuln id=OAUTH-001 name="OAuth redirect_uri is not validated" cwe=CWE-601 owasp=A01:2021 type=open-redirect-uri level=1 param=redirect_uri method=GET service=auth-svc url=/auth/authorize param_loc=query needs_oob=false auth=false detection=active tags=oauth,redirect,authorization proof_kind=marker proof_desc="Authorization code is delivered to an attacker-controlled redirect_uri"
        if path == "/authorize":
            redirect_uri = params.get("redirect_uri", "")
            code = secrets.token_hex(8)
            AUTH_CODES[code] = {"user": "alice", "scope": params.get("scope", "read")}

            # !! INTENTIONALLY VULNERABLE — redirect_uri accepted as-is !!
            target = f"{redirect_uri}?code={code}"
            if params.get("state"):
                target += f"&state={params['state']}"

            lab_trigger("OAUTH-001", self, {"redirect_uri": redirect_uri})
            if redirect_uri.startswith(("http://", "https://")) and not redirect_uri.startswith(tuple(ALLOWED_REDIRECTS)):
                lab_trigger("OAUTH-002", self, {"state_provided": bool(params.get("state"))})
            return self._redirect(target)

        # @control id=OAUTH-001-C twin_of=OAUTH-001 url=/auth/authorize_safe method=GET param=redirect_uri service=auth-svc param_loc=query
        if path == "/authorize_safe":
            redirect_uri = params.get("redirect_uri", "")
            if redirect_uri not in ALLOWED_REDIRECTS:
                return self._send(400, json.dumps({"error": "invalid redirect_uri"}))
            if not params.get("state"):
                return self._send(400, json.dumps({"error": "state is required"}))
            code = secrets.token_hex(8)
            AUTH_CODES[code] = {"user": "alice", "scope": "read"}
            return self._redirect(f"{redirect_uri}?code={code}&state={params['state']}")

        # @control id=OAUTH-002-C twin_of=OAUTH-002 url=/auth/authorize_state_safe method=GET param=state service=auth-svc param_loc=query
        if path == "/authorize_state_safe":
            redirect_uri = params.get("redirect_uri", "")
            if redirect_uri not in ALLOWED_REDIRECTS or not params.get("state"):
                return self._send(400, json.dumps({"error": "invalid authorization request"}))
            code = secrets.token_hex(8)
            AUTH_CODES[code] = {"user": "alice", "scope": "read"}
            return self._redirect(f"{redirect_uri}?code={code}&state={params['state']}")

        # @vuln id=OAUTH-003 name="Implicit flow returns the access token in the fragment" cwe=CWE-598 owasp=A07:2021 type=implicit-flow level=2 param=redirect_uri method=GET service=auth-svc url=/auth/implicit param_loc=query needs_oob=false auth=false detection=active tags=oauth,implicit,token-leak proof_kind=marker proof_desc="Location header contains #access_token=..."
        if path == "/implicit":
            redirect_uri = params.get("redirect_uri", "")
            token = secrets.token_hex(16)
            ACCESS_TOKENS[token] = {"user": "alice", "scope": "read"}
            lab_trigger("OAUTH-003", self, {"redirect_uri": redirect_uri})
            return self._redirect(f"{redirect_uri}#access_token={token}&token_type=bearer")

        # @control id=OAUTH-003-C twin_of=OAUTH-003 url=/auth/implicit_safe method=GET param=redirect_uri service=auth-svc param_loc=query
        if path == "/implicit_safe":
            return self._send(400, json.dumps({"error": "implicit flow is disabled, use authorization code with PKCE"}))

        # @vuln id=OAUTH-005 name="Scope escalation accepted without consent" cwe=CWE-269 owasp=A01:2021 type=scope-escalation level=2 param=scope method=GET service=auth-svc url=/auth/scope param_loc=query needs_oob=false auth=true detection=active tags=oauth,scope,privilege-escalation proof_kind=marker proof_desc="Requesting admin scope returns an admin token for a normal user"
        if path == "/scope":
            scope = params.get("scope", "read")
            token = secrets.token_hex(16)
            ACCESS_TOKENS[token] = {"user": "alice", "scope": scope}
            lab_trigger("OAUTH-005", self, {"scope": scope})
            return self._send(200, json.dumps({"access_token": token, "scope": scope, "role": "admin" if "admin" in scope else "user"}))

        # @control id=OAUTH-005-C twin_of=OAUTH-005 url=/auth/scope_safe method=GET param=scope service=auth-svc param_loc=query
        if path == "/scope_safe":
            granted = "read"
            token = secrets.token_hex(16)
            ACCESS_TOKENS[token] = {"user": "alice", "scope": granted}
            return self._send(200, json.dumps({"access_token": token, "scope": granted, "role": "user"}))

        if path == "/__lab/internal/reset":
            AUTH_CODES.clear()
            ACCESS_TOKENS.clear()
            return self._send(200, json.dumps({"reset": True}))

        self._send(404, json.dumps({"error": "not found"}))

    # ─── POST ───────────────────────────────────────────────────────────────

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        form = self._form()

        # @vuln id=OAUTH-004 name="Token endpoint does not require PKCE" cwe=CWE-287 owasp=A07:2021 type=missing-pkce level=2 param=code method=POST service=auth-svc url=/auth/token param_loc=body needs_oob=false auth=false detection=active tags=oauth,pkce,authorization proof_kind=marker proof_desc="An authorization code is exchanged without any code_verifier"
        if path == "/token":
            code = form.get("code", "")
            token = secrets.token_hex(16)
            ACCESS_TOKENS[token] = {"user": "alice", "scope": "read"}
            lab_trigger("OAUTH-004", self, {"code": code, "pkce": "code_verifier" in form})
            return self._send(200, json.dumps({"access_token": token, "token_type": "bearer", "expires_in": 3600}))

        # @control id=OAUTH-004-C twin_of=OAUTH-004 url=/auth/token_safe method=POST param=code service=auth-svc param_loc=body
        if path == "/token_safe":
            if not form.get("code_verifier"):
                return self._send(400, json.dumps({"error": "code_verifier is required (PKCE)"}))
            token = secrets.token_hex(16)
            return self._send(200, json.dumps({"access_token": token, "token_type": "bearer"}))

        # @vuln id=OAUTH-006 name="SAML assertion accepted without signature validation" cwe=CWE-347 owasp=A07:2021 type=saml-unsigned level=2 param=SAMLResponse method=POST service=auth-svc url=/auth/saml/acs param_loc=body needs_oob=false auth=false detection=active tags=saml,auth,signature proof_kind=marker proof_desc="An unsigned assertion is accepted and grants the admin role"
        if path == "/saml/acs":
            raw = form.get("SAMLResponse", "")
            try:
                xml = base64.b64decode(raw).decode("utf-8", errors="replace")
            except Exception:
                xml = ""

            if "<saml" not in xml.lower():
                return self._send(400, json.dumps({"error": "invalid SAMLResponse"}))

            # !! INTENTIONALLY VULNERABLE — the signature is never verified !!
            lab_trigger("OAUTH-006", self, {"signed": "SignatureValue" in xml})
            return self._send(200, json.dumps({
                "authenticated": True,
                "user": "admin",
                "role": "admin",
                "signature_verified": False,
            }))

        # @control id=OAUTH-006-C twin_of=OAUTH-006 url=/auth/saml/acs_safe method=POST param=SAMLResponse service=auth-svc param_loc=body
        if path == "/saml/acs_safe":
            raw = form.get("SAMLResponse", "")
            try:
                xml = base64.b64decode(raw).decode("utf-8", errors="replace")
            except Exception:
                xml = ""
            if "SignatureValue" not in xml:
                return self._send(400, json.dumps({"error": "assertion is not signed"}))
            return self._send(200, json.dumps({"authenticated": True, "signature_verified": True}))

        # @vuln id=OAUTH-007 name="Username enumeration in the login endpoint" cwe=CWE-204 owasp=A07:2021 type=user-enumeration level=1 param=username method=POST service=auth-svc url=/auth/login param_loc=body needs_oob=false auth=false detection=passive tags=auth,enumeration,info-leak proof_kind=marker proof_desc="Unknown users and wrong passwords produce different messages"
        if path == "/login":
            username = form.get("username", "")
            password = form.get("password", "")

            if username not in USERS:
                lab_trigger("OAUTH-007", self, {"username": username, "exists": False})
                return self._send(401, json.dumps({"error": "unknown user"}))
            if USERS[username] != password:
                return self._send(401, json.dumps({"error": "wrong password"}))

            return self._send(200, json.dumps({"authenticated": True, "token": secrets.token_hex(16)}))

        # @control id=OAUTH-007-C twin_of=OAUTH-007 url=/auth/login_safe method=POST param=username service=auth-svc param_loc=body
        if path == "/login_safe":
            username = form.get("username", "")
            password = form.get("password", "")
            if USERS.get(username) == password:
                return self._send(200, json.dumps({"authenticated": True, "token": secrets.token_hex(16)}))
            return self._send(401, json.dumps({"authenticated": False, "error": "invalid credentials"}))

        self._send(404, json.dumps({"error": "not found"}))


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"[auth-svc] listening on {PORT}")
    server.serve_forever()
