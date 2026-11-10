# Scanner integration

VulnForge exposes every service through a single gateway:

```
http://127.0.0.1:8000/
```

| Prefix | Service | Ground-truth scope |
|---|---|---|
| `/php/` | php-web | SQLi, XSS, CMDi, LFI, upload, CSRF, IDOR, auth |
| `/api/` | node-api | OWASP API Top 10 (BOLA, BOPLA, BFLA, JWT, NoSQLi, SSRF) |
| `/py/` | flask-svc | SSTI, deserialization, path traversal, SSRF, CMDi, ReDoS |
| `/java/` | spring-svc | XXE, XMLDecoder, EL injection, JNDI, weak crypto |
| `/go/` | go-svc | SSRF, race condition, business logic, OTP brute force |
| `/graphql` | graphql-svc | introspection, batching, alias DoS, BOLA |
| `/graphql_safe` | graphql-svc | hardened twin used for control measurement |
| `/spa/` | crawl-lab | SPA routing, robots, source maps, soft-404, SSE |
| `/legacy/` | legacy-svc | outdated components, backups, default credentials |
| `/auth/` | auth-svc | OAuth/OIDC/SAML weaknesses |

`lab-control` listens on `127.0.0.1:9100` and is deliberately **out of scope**
for scanners. Use it to reset state and start/stop a measurement session:

```bash
curl -X POST http://127.0.0.1:9100/__lab/session/start \
     -H 'Content-Type: application/json' \
     -d '{"scanner_name":"my-scanner","scanner_version":"1.0"}'

# ... run the scan ...

curl -X POST http://127.0.0.1:9100/__lab/session/stop
```

The stop response lists `triggered_vuln_ids` observed during the session.

## Ground-truth endpoints

* `GET /__lab/vulns` — filtered ground truth (respects mode)
* `GET /__lab/controls` — safe twins
* `GET /__lab/events` — `vuln_triggered` and session events
* `POST /__lab/reset` — deterministic reset
* `POST /__lab/seed?profile=small|large` — data volume
* `PUT /__lab/mode` — restrict by service, OWASP category and level
* `PUT /__lab/waf` — select a WAF profile

## Recommended workflow

1. Reset the lab.
2. Start a session.
3. Run the scanner against the gateway only.
4. Stop the session and export `/__lab/events`.
5. Score the scanner output:

```bash
python3 scorer/scorer.py \
  --findings scanner.json \
  --truth-dir lab/truth \
  --events http://127.0.0.1:9100/__lab/events \
  --out-dir scorer/out
```

Keep the lab version, scanner version and report together so results remain
comparable across runs.

## Excluded paths

Exclude these from the scanner scope; they are harness components and scanning
them corrupts the score:

* `127.0.0.1:9100` (lab-control)
* `127.0.0.1:9000` (OOB collector)
* `127.0.0.1:8025` (MailHog UI)

## Authentication notes

Some findings need a session or token:

| Service | How to authenticate |
|---|---|
| php-web | `POST /php/auth/login.php` with `username`/`password`, keep the `PHPSESSID` cookie |
| node-api | `POST /api/v1/login` with JSON, then `Authorization: Bearer <token>` |
| auth-svc | `POST /auth/login`, then use the returned token |

Use the synthetic accounts listed in the README. Scanners that support
authenticated scanning should be configured with these credentials to reach the
`auth=true` findings.
