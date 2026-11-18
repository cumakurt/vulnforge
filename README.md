# VulnForge Lab

> **WARNING — intentionally vulnerable software.**
> VulnForge Lab exists to benchmark web vulnerability scanners. Run it only on
> a machine you control, inside an isolated network. Never expose it to the
> internet and never deploy it in production. All host ports bind to
> `127.0.0.1` by default.

VulnForge Lab is a multi-language, intentionally vulnerable web application
exposed through a single URL — `http://127.0.0.1:8000/` — as a realistic
e-commerce site (**ShopForge**).

| | |
|---|---|
| **Status** | v2.0 — 9 containers in the full profile |
| **Vulnerabilities** | 99 (L1–L3) with 99 safe control twins |
| **Scanner portal** | `http://127.0.0.1:8000/` — ShopForge e-commerce site |
| **Containers** | `full` and `core` 9, `api` and `waf` 5 each |
| **License** | **AGPL-3.0 only** |
| **Author** | Cuma KURT — [cumakurt@gmail.com](mailto:cumakurt@gmail.com) |

- LinkedIn: <https://www.linkedin.com/in/cuma-kurt-34414917/>
- GitHub: <https://github.com/cumakurt/vulnforge>

---

## 1. Quick start

```bash
git clone https://github.com/cumakurt/vulnforge.git
cd vulnforge
./docker_install.sh          # starts all 9 containers (full profile)
```

The installer detects the host OS, verifies Docker, picks a free port,
builds images and runs the smoke suite.

```bash
# Optional flags
./docker_install.sh --port 18000 --yes --skip-tests
```

| Flag | Default | Meaning |
|---|---|---|
| `--profile core\|full\|api\|waf` | `full` | Compose profile |
| `--port <n>` | `8000` | Gateway HTTP port |
| `--yes` | false | Skip package install prompts |
| `--skip-build` | false | Reuse existing images |
| `--skip-tests` | false | Skip smoke suite |

### Manual start

```bash
cp .env.example .env
docker compose --profile full up -d --build
```

If you are upgrading an existing installation, add `--remove-orphans` to
the Compose start command to remove the old ShopForge container.

### Stop / reset

```bash
make down      # stop all containers
make reset     # reset databases and event log
```

---

## 2. Scanner target — the ShopForge portal

**Point your scanner at a single URL:**

```
http://127.0.0.1:8000/
```

ShopForge includes 16 fictional products with names, prices, categories and
descriptions. The catalog and product detail pages share the seed records in
`services/shopforge/catalog.json`. Scan coverage depends on the scanner's
crawl and session settings.

| Path | Service (backend) | Vulnerability groups |
|---|---|---|
| `/` → `/products`, `/search`, … | gateway (ShopForge) | Navigation surface |
| `/php/` | php-web (PHP 8 + MySQL) | SQLi, XSS, CMDi, LFI, Upload, CSRF, IDOR, Auth |
| `/api/` | node-api (Node 20) | BOLA, BOPLA, BFLA, Mass assignment, JWT, NoSQLi, SSRF |
| `/graphql` | node-api (Node 20) | Introspection, batching, alias DoS, BOLA |
| `/spa/` | node-api (Node 20) | SPA routing, robots, source maps, soft-404, SSE, CSWSH |
| `/py/` | flask-svc (Python) | SSTI, Pickle RCE, YAML, path traversal, SSRF, CMDi, ReDoS |
| `/auth/` | flask-svc (Python) | OAuth redirect_uri, state, PKCE, SAML, enumeration |
| `/legacy/` | flask-svc (Python) | Outdated jQuery, backups, `.git`, default credentials |
| `/java/` | spring-svc (Java 17) | XXE, XMLDecoder RCE, EL injection, JNDI, weak crypto |
| `/go/` | go-svc (Go 1.22) | SSRF, race condition, path traversal, CMDi, OTP brute force |

Control twins (hardened safe endpoints) live next to each vulnerable endpoint.

### HTTPS listener

```
https://127.0.0.1:8443/   (status response with a self-signed certificate)
```

### Synthetic credentials

| Service | Username | Password |
|---|---|---|
| PHP web / Node API / OAuth | `alice` | `password1` |
| PHP admin | `admin` | `admin123` |
| Legacy admin | `admin` | `admin` (intentional default credential) |

All data is synthetic. No real personal data or secrets included.

---

## 3. Lab infrastructure (out of scanner scope)

| Endpoint | Purpose |
|---|---|
| `http://127.0.0.1:9100/__lab/health` | Service health |
| `http://127.0.0.1:9100/__lab/vulns` | Ground truth (all 99 vulns) |
| `http://127.0.0.1:9100/__lab/events` | Triggered vuln events |
| `http://127.0.0.1:9100/__lab/docs` | Interactive API docs |
| `curl -X POST http://127.0.0.1:9100/__lab/reset` | Reset all state |
| `http://127.0.0.1:9000/` | OOB callback collector |

---

## 4. Container architecture (v2.0)

The `full` profile runs nine containers. Nginx and ShopForge share the
gateway container. ShopForge listens on the container's loopback interface,
and the gateway restarts if either process exits unexpectedly. The other
services retain their container and network boundaries.

| # | Container | Role | Vulns |
|---|---|---|---|
| 1 | `vulnforge-gateway` | Nginx reverse proxy + TLS + WAF + ShopForge | routing |
| 2 | `vulnforge-lab-control` | Control plane + IMDSv1 SSRF target | — |
| 3 | `vulnforge-oob-collector` | HTTP + DNS out-of-band collector | — |
| 4 | `vulnforge-php-web` | PHP 8 / Apache | 26 |
| 5 | `vulnforge-mysql` | MySQL 8 (required by php-web) | — |
| 6 | `vulnforge-node-api` | Node.js 20 (API + GraphQL + SPA merged) | 28 |
| 7 | `vulnforge-flask-svc` | Python Flask (PY + OAuth + Legacy merged) | 25 |
| 8 | `vulnforge-spring-svc` | Java 17 (JVM-exclusive vulns) | 10 |
| 9 | `vulnforge-go-svc` | Go 1.22 (goroutine race, debug.Stack) | 10 |

### Merged services (v2.0)

Services that ran as separate containers in v1.0 are now merged:

| Removed container | Merged into | Reason |
|---|---|---|
| `crawl-lab` (Node.js) | `node-api` | Same runtime, `/spa/*` routes added |
| `graphql-svc` (Node.js) | `node-api` | Same runtime, `/graphql` routes added |
| `auth-svc` (Python) | `flask-svc` | Same runtime, `/auth/*` routes added |
| `legacy-svc` (Python) | `flask-svc` | Same runtime, `/legacy/*` routes added |
| `internal-metadata` | `lab-control` | Same runtime; fixed IP `169.254.169.100` on `internal_net` |

### Dropped containers

| Removed | Reason |
|---|---|
| `postgres` | flask-svc/spring-svc env var set but code never connects |
| `mongodb` | node-api uses in-memory NoSQL operator simulator |
| `redis` | go-svc env var set but code uses in-memory Go structs |
| `mailhog` | No vuln directly tests SMTP |

---

## 5. Verification

Run `python3 tests/test_shopforge.py` against a running gateway to check the
portal and synthetic catalog. Set `BASE_URL` if the HTTP port differs.

```bash
pip install -r tests/requirements.txt

make smoke      # all 99 vulns must trigger  → 99/99 pass
make controls   # all 99 safe twins must hold → 99/99 pass
make test       # both suites (198 checks)
```

Expected on a healthy `full` profile:

```
=== SMOKE ===
99 test(s) run, 0 failure(s), 0 skipped
```

---

## 6. Scoring scanner output

```bash
python3 scorer/scorer.py \
  --findings scanner-results.json \
  --format custom_json \
  --truth-dir lab/truth \
  --out-dir scorer/out \
  --events http://127.0.0.1:9100/__lab/events
```

Adapters: `custom_json`, `sarif`, `zap`, `nuclei`.
Outputs: `report.html`, `report.json`, `report.csv`.

See [docs/scoring.md](docs/scoring.md) and
[docs/scanner-integration.md](docs/scanner-integration.md).

---

## 7. Vulnerability catalog summary

| Group | IDs | OWASP | Service |
|---|---|---|---|
| SQL Injection | SQLI-001..007 | A03 | php-web |
| XSS | XSS-001..003 | A03 | php-web |
| Authentication | AUTH-001..004 | A07 | php-web |
| Command Injection | CMDI-001..002 | A03 | php-web |
| IDOR | IDOR-001..002 | A01 | php-web |
| LFI / Path Traversal | LFI-001 | A01 | php-web |
| CSRF | CSRF-001 | A01 | php-web |
| Crypto | CRYPTO-001 | A02 | php-web |
| Misc Config | CONF-001..002, INFO-001 | A05 | php-web |
| Upload | UPLOAD-001 | A04 | php-web |
| Redirect | REDIR-001 | A01 | php-web |
| API Access Control | API-001..004 | A01 | node-api |
| API Injection | API-005, API-008 | A03/A08 | node-api |
| API Auth | API-006, API-007, API-012..014 | A07/A05 | node-api |
| API DoS | API-009..011 | A04/A10 | node-api |
| GraphQL | GQL-001..006 | A01..A05 | node-api |
| SPA / Crawl | CRAWL-001..008 | A01..A05 | node-api |
| Python / SSTI | PY-001..011 | A01..A08 | flask-svc |
| OAuth / SAML | OAUTH-001..007 | A07 | flask-svc |
| Legacy / SCA | LEG-001..007 | A05..A07 | flask-svc |
| Java / XXE | JAVA-001..010 | A02..A08 | spring-svc |
| Go / Race | GO-001..011 | A01..A10 | go-svc |

Full details: [docs/vulnerability-catalog.md](docs/vulnerability-catalog.md)

---

## 8. Makefile reference

```bash
make install     # one-shot install (./docker_install.sh --profile full)
make up          # docker compose --profile full up -d --build
make down        # stop all containers
make reset       # reset databases and events
make smoke       # run smoke suite
make controls    # run controls suite
make test        # smoke + controls
make score       # score sample findings
make truth       # regenerate lab/truth/vulns.json
make catalog     # regenerate vulnerability catalog docs
```
