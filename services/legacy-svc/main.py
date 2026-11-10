"""
VulnForge Lab — legacy-svc

Simulates an unmaintained PHP/WordPress-era deployment: outdated client
libraries, exposed backups, exposed VCS metadata, directory listing, default
credentials and banner disclosure.

WARNING: never expose this service outside an isolated lab.
"""

import base64
import json
import os
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LAB_CONTROL_URL = os.environ.get("LAB_CONTROL_URL", "http://lab-control:9100")
PORT = int(os.environ.get("PORT", "8888"))

BANNER = "Apache/2.2.15 (CentOS)"

INDEX = """<!doctype html>
<html>
<head><title>Legacy Shop</title></head>
<body>
<h1>Legacy Shop</h1>
<p>Welcome to our store.</p>
<script src="/assets/jquery-1.8.3.min.js"></script>
<script src="/assets/app.js"></script>
<!-- admin panel: /admin/login.php -->
</body>
</html>
"""

INDEX_SAFE = """<!doctype html>
<html>
<head><title>Legacy Shop (hardened)</title></head>
<body>
<h1>Legacy Shop</h1>
<script src="/assets/app_safe.js"></script>
</body>
</html>
"""

JQUERY_183 = """/*! jQuery v1.8.3 jquery.com | (c) 2010-2012 John Resig */
/* Intentionally old jQuery build used for SCA testing. */
(function(window, undefined) { window.jQuery = function(selector) { return { selector: selector }; }; })(window);
"""

APP_JS = "console.log('legacy app loaded');\n"

BACKUP_LISTING = """<!doctype html>
<html><head><title>Index of /backup</title></head>
<body>
<h1>Index of /backup</h1>
<ul>
<li><a href="db-2024-01.sql">db-2024-01.sql</a></li>
<li><a href="site-2024-01.tar.gz">site-2024-01.tar.gz</a></li>
<li><a href="config.old.php">config.old.php</a></li>
</ul>
</body></html>
"""


def lab_trigger(vuln_id: str, handler, extra: dict | None = None) -> None:
    payload = json.dumps({
        "kind": "vuln_triggered",
        "vuln_id": vuln_id,
        "service": "legacy-svc",
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
    server_version = BANNER
    sys_version = ""

    def log_message(self, fmt, *args):  # keep the lab output readable
        pass

    def _send(self, status: int, body: str, content_type="text/html; charset=utf-8", extra_headers=None):
        encoded = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("X-Powered-By", "PHP/5.3.3")
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(encoded)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/health":
            return self._send(200, json.dumps({"status": "ok", "service": "legacy-svc"}), "application/json")

        # @vuln id=LEG-001 name="End-of-life jQuery 1.8.3 shipped to clients" cwe=CWE-1104 owasp=A06:2021 cve=CVE-2012-6708,CVE-2015-9251 type=outdated-component level=1 param=none method=GET service=legacy-svc url=/legacy/ param_loc=path needs_oob=false auth=false detection=sca tags=sca,outdated,jquery proof_kind=marker proof_desc="The page references jquery-1.8.3.min.js, a version with known XSS CVEs"
        if path in ("/", "/index.html", "/index.php"):
            lab_trigger("LEG-001", self, {})
            return self._send(200, INDEX)

        # @control id=LEG-001-C twin_of=LEG-001 url=/legacy/index_safe.html method=GET param=none service=legacy-svc param_loc=path
        if path == "/index_safe.html":
            return self._send(200, INDEX_SAFE)

        if path == "/assets/jquery-1.8.3.min.js":
            return self._send(200, JQUERY_183, "application/javascript")

        if path == "/assets/app.js":
            return self._send(200, APP_JS, "application/javascript")

        if path == "/assets/app_safe.js":
            return self._send(200, APP_JS, "application/javascript")

        # @vuln id=LEG-002 name="Backup configuration file publicly readable" cwe=CWE-538 owasp=A05:2021 type=backup-file level=1 param=none method=GET service=legacy-svc url=/legacy/config.php.bak param_loc=path needs_oob=false auth=false detection=config tags=misconfiguration,info-leak,backup proof_kind=marker proof_desc="config.php.bak contains database credentials"
        if path == "/config.php.bak":
            lab_trigger("LEG-002", self, {})
            return self._send(200, """<?php
// Legacy database configuration
define('DB_HOST', 'mysql');
define('DB_USER', 'legacy_user');
define('DB_PASSWORD', 'legacy_backup_password');
define('DB_NAME', 'legacy_shop');
""", "text/plain")

        # @control id=LEG-002-C twin_of=LEG-002 url=/legacy/config_safe.bak method=GET param=none service=legacy-svc param_loc=path
        if path == "/config_safe.bak":
            return self._send(404, "not found", "text/plain")

        # @vuln id=LEG-003 name="Exposed .git metadata allows source reconstruction" cwe=CWE-527 owasp=A05:2021 type=vcs-exposure level=1 param=none method=GET service=legacy-svc url=/legacy/.git/config param_loc=path needs_oob=false auth=false detection=config tags=misconfiguration,info-leak,git proof_kind=marker proof_desc=".git/config is served with the repository remote and local paths"
        if path == "/.git/config":
            lab_trigger("LEG-003", self, {})
            return self._send(200, "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n[remote \"origin\"]\n\turl = https://git.example.invalid/legacy-shop.git\n", "text/plain")

        # @control id=LEG-003-C twin_of=LEG-003 url=/legacy/git_safe/config method=GET param=none service=legacy-svc param_loc=path
        if path == "/git_safe/config":
            return self._send(404, "not found", "text/plain")

        # @vuln id=LEG-004 name="Directory listing exposes database dumps" cwe=CWE-548 owasp=A05:2021 type=directory-listing level=1 param=none method=GET service=legacy-svc url=/legacy/backup/ param_loc=path needs_oob=false auth=false detection=config tags=misconfiguration,info-leak,directory-listing proof_kind=marker proof_desc="Apache style index lists SQL and archive backups"
        if path in ("/backup/", "/backup"):
            lab_trigger("LEG-004", self, {})
            return self._send(200, BACKUP_LISTING)

        # @control id=LEG-004-C twin_of=LEG-004 url=/legacy/backup_safe/ method=GET param=none service=legacy-svc param_loc=path
        if path in ("/backup_safe/", "/backup_safe"):
            return self._send(403, "Forbidden", "text/plain")

        # @vuln id=LEG-005 name="Default administrative credentials admin/admin" cwe=CWE-1392 owasp=A07:2021 type=default-credentials level=1 param=username method=POST service=legacy-svc url=/legacy/admin/login.php param_loc=body needs_oob=false auth=false detection=active tags=auth,default-credentials proof_kind=marker proof_desc="admin/admin authenticates and returns an administrative session"
        # @vuln id=LEG-006 name="Server banner discloses end-of-life software versions" cwe=CWE-200 owasp=A05:2021 type=banner-disclosure level=1 param=none method=GET service=legacy-svc url=/legacy/banner param_loc=path needs_oob=false auth=false detection=config tags=misconfiguration,info-leak,banner proof_kind=marker proof_desc="Server header reports Apache 2.2.15 and PHP 5.3.3"
        # @vuln id=LEG-007 name="WordPress readme reveals the CMS version" cwe=CWE-200 owasp=A06:2021 type=cms-version-disclosure level=1 param=none method=GET service=legacy-svc url=/legacy/readme.html param_loc=path needs_oob=false auth=false detection=sca tags=sca,info-leak,wordpress proof_kind=marker proof_desc="readme.html states WordPress 4.1, a version with known vulnerabilities"

        if path == "/admin/login.php":
            self._send(200, "<form method='post'><input name='username'><input name='password'></form>")
            return

        if path == "/banner":
            lab_trigger("LEG-006", self, {})
            return self._send(200, "Apache/2.2.15 (CentOS) PHP/5.3.3 mod_ssl/2.2.15", "text/plain")

        if path == "/readme.html":
            lab_trigger("LEG-007", self, {})
            return self._send(200, "<h1>WordPress</h1><p>Version 4.1</p>")

        # controls
        # @control id=LEG-005-C twin_of=LEG-005 url=/legacy/admin/login_safe.php method=POST param=username service=legacy-svc param_loc=body
        if path == "/admin/login_safe.php":
            return self._send(403, json.dumps({"error": "default credentials disabled"}), "application/json")

        # @control id=LEG-006-C twin_of=LEG-006 url=/legacy/banner_safe method=GET param=none service=legacy-svc param_loc=path
        if path == "/banner_safe":
            return self._send(200, "web server", "text/plain", {"Server": "nginx"})

        # @control id=LEG-007-C twin_of=LEG-007 url=/legacy/readme_safe.html method=GET param=none service=legacy-svc param_loc=path
        if path == "/readme_safe.html":
            return self._send(404, "not found", "text/plain")

        if path == "/__lab/internal/reset":
            return self._send(200, json.dumps({"reset": True}), "application/json")

        self._send(404, "<h1>404 Not Found</h1>")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        form = urllib.parse.parse_qs(body)

        if parsed.path == "/admin/login.php":
            username = form.get("username", [""])[0]
            password = form.get("password", [""])[0]

            # !! INTENTIONALLY VULNERABLE — default credentials accepted !!
            if username == "admin" and password == "admin":
                lab_trigger("LEG-005", self, {"username": username})
                self._send(200, json.dumps({
                    "authenticated": True,
                    "role": "admin",
                    "session": base64.b64encode(b"admin:legacy").decode(),
                }), "application/json")
                return

            self._send(401, json.dumps({"authenticated": False}), "application/json")
            return

        if parsed.path == "/admin/login_safe.php":
            # SAFE: default password rejected, message is generic.
            self._send(401, json.dumps({"authenticated": False, "error": "invalid credentials"}), "application/json")
            return

        self._send(404, json.dumps({"error": "not found"}), "application/json")


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"[legacy-svc] listening on {PORT}")
    server.serve_forever()
