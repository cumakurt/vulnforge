# VulnForge Lab

> **WARNING — intentionally vulnerable software.**
> VulnForge Lab exists to benchmark web vulnerability scanners. Run it only on
> a machine you control, inside an isolated network. Never expose it to the
> internet and never deploy it in production. All host ports bind to
> `127.0.0.1` by default.

VulnForge Lab is a multi-language, intentionally vulnerable application suite
with machine-readable ground truth, a safe "control twin" for every
vulnerability, an exploit-trigger event log, and a scorer that turns scanner
output into precision/recall reports.

| | |
|---|---|
| **Status** | v1.0 — `full` profile runs end-to-end |
| **Vulnerabilities** | 99 (L1–L3) with 99 safe control twins |
| **Services** | 9 application tiers + infrastructure + lab tooling |
| **License** | **AGPL-3.0 only** |
| **Author** | Cuma KURT — [cumakurt@gmail.com](mailto:cumakurt@gmail.com) |

- LinkedIn: <https://www.linkedin.com/in/cuma-kurt-34414917/>
- GitHub: <https://github.com/cumakurt/vulnforge>

---

## 1. Quick start

### One-shot installer (recommended)

```bash
git clone https://github.com/cumakurt/vulnforge.git
cd vulnforge
./docker_install.sh                 # core profile
./docker_install.sh --profile full  # every service
```

The installer:

1. detects the host OS and package manager (apt, dnf, yum, pacman, zypper, apk, brew),
2. checks Docker, the Compose plugin, curl and python3,
3. **asks for approval before installing any missing package**,
4. creates `.env` when needed and automatically picks a free HTTP port,
5. builds and starts the selected profile,
6. waits for health checks and prints the access information,
7. optionally runs the smoke suite to prove the lab is exploitable.

Useful flags:

| Flag | Meaning |
|---|---|
| `--profile core\|full\|api\|infra\|waf\|crawl` | Compose profile to start |
| `--port <port>` | Host gateway HTTP port (default `8000`, next free if busy) |
| `--https-port <port>` | Host gateway HTTPS port (default `8443`) |
| `--lab-port <port>` | Host `lab-control` port (default `9100`) |
| `--yes` | Never prompt (CI / unattended) |
| `--skip-build` | Reuse existing images |
| `--skip-tests` | Do not run the smoke suite |

### Manual start

```bash
cp .env.example .env
docker compose --profile full up -d --build
curl -X POST http://127.0.0.1:9100/__lab/reset
```

### Stop / reset

```bash
make down      # stop the stack
make reset     # reset databases, uploads and events
```

---

## 2. Where to point the scanner

Everything is served through a single gateway.

| What | Address |
|---|---|
| Gateway (scanner target) | `http://127.0.0.1:8000/` |
| HTTPS (self-signed) | `https://127.0.0.1:8443/` |
| Lab control (out of scanner scope) | `http://127.0.0.1:9100/` |
| OOB collector (full profile) | `http://127.0.0.1:9000/` |

| Path | Service | Focus |
|---|---|---|
| `/php/` | php-web (PHP 8 + MySQL) | SQLi, XSS, CMDi, LFI, upload, CSRF, IDOR, auth |
| `/api/` | node-api (Node 20) | BOLA, BOPLA, BFLA, mass assignment, JWT, NoSQLi, SSRF |
| `/py/` | flask-svc (Python/Flask) | SSTI, pickle, YAML, path traversal, SSRF, CMDi, ReDoS |
| `/java/` | spring-svc (Java 17) | XXE, deserialization, EL injection, JNDI, weak crypto |
| `/go/` | go-svc (Go) | SSRF, race condition, traversal, CMDi, OTP brute force |
| `/graphql` | graphql-svc (Node) | introspection, batching, alias DoS, BOLA |
| `/spa/` | crawl-lab (Node) | SPA routing, robots, source maps, soft-404, SSE |
| `/legacy/` | legacy-svc (Python) | outdated jQuery, backups, `.git`, default credentials |
| `/auth/` | auth-svc (Python) | OAuth redirect_uri, state, PKCE, SAML, enumeration |

Control twins live next to each vulnerable endpoint and are listed in
[`docs/vulnerability-catalog.md`](docs/vulnerability-catalog.md).

### Example targets

```bash
curl 'http://127.0.0.1:8000/php/sqli/products.php?id=1'
curl 'http://127.0.0.1:8000/api/v1/products?limit=20'
curl 'http://127.0.0.1:8000/py/ssti?name=World'
curl 'http://127.0.0.1:8000/graphql' -H 'content-type: application/json' -d '{"query":"{ hello }"}'
```

### Synthetic credentials

| Service | Credentials |
|---|---|
| php-web / node-api / auth-svc | `alice` / `password1` |
| php-web admin | `admin` / `admin123` |
| legacy-svc | `admin` / `admin` (default credentials on purpose) |

All data is synthetic. No real personal data, secrets or API keys are included.

---

## 3. How the benchmark works

### 3.1 Ground truth from source tags

Every vulnerable endpoint and its safe twin are declared in source:

```php
// @vuln id=SQLI-001 name="Error-based SQL Injection in product lookup" cwe=CWE-89 owasp=A03:2021 type=error-based level=1 param=id method=GET service=php-web url=/php/sqli/products.php param_loc=query needs_oob=false auth=false detection=active tags=injection,database,mysql proof_kind=marker proof_desc="MySQL error visible"
// @control id=SQLI-001-C twin_of=SQLI-001 url=/php/sqli/products_safe.php method=GET param=id service=php-web param_loc=query
```

Regenerate the machine-readable truth:

```bash
make truth      # -> lab/truth/vulns.json + controls.json (validated)
make catalog    # -> docs/vulnerability-catalog.md + docs/tr/zafiyet-katalogu.md
```

The extractor validates duplicate ids, unknown services, invalid levels,
dangling control references, and **missing twins**.

### 3.2 Levels

| Level | Meaning |
|---|---|
| L0 | Safe control (measured as false positives) |
| L1 | No filter, obvious |
| L2 | Simple filter / blind-only |
| L3 | Strong filter, multi-step or context dependent |
| L4 | Behind a WAF / heavily context dependent (reserved) |

### 3.3 Exploit proof

Vulnerable endpoints call `lab_trigger(vuln_id)` when the exploit path is
reached. `lab-control` records these as `vuln_triggered` events, which lets the
scorer distinguish **reported** from **actually exploited**.

### 3.4 Verification suites

```bash
pip install -r tests/requirements.txt

make smoke      # every vulnerability must be exploitable
make controls   # every safe twin must reject the same payload
make test       # both (198 checks)
```

The runner asks `lab-control` which services are running. Vulnerabilities that
belong to a service that is not part of the started compose profile are
reported as `SKIP` (not failures), so the suites work with any profile:

```
=== SMOKE ===
  SKIP API-001: service 'node-api' is not running
  ...
26 test(s) run, 0 failure(s), 73 skipped
```

Pass `--require-all-services` to treat a missing service as a failure instead
(useful in CI, where only the `full` profile should be used):

```bash
python3 tests/run_tests.py --mode all --require-all-services
```

Expected result on a healthy `full` profile:

```
=== SMOKE ===
99 test(s) run, 0 failure(s), 0 skipped

=== CONTROLS ===
99 test(s) run, 0 failure(s), 0 skipped
```

---

## 4. Scoring

```bash
python3 scorer/scorer.py \
  --findings scanner-results.json \
  --format custom_json \
  --truth-dir lab/truth \
  --out-dir scorer/out \
  --events http://127.0.0.1:9100/__lab/events \
  --fail-under recall=0.80 --fail-over fp=0.05
```

Adapters: `custom_json`, `sarif`, `zap`, `nuclei`.
Outputs: `report.html`, `report.json`, `report.csv`.

Metrics include TP/FP/FN, precision/recall/F1, per-OWASP/CWE/service/level
breakdown, safe-twin false-positive rate, and detection-vs-exploitation counts.

See [docs/scoring.md](docs/scoring.md) and
[docs/scanner-integration.md](docs/scanner-integration.md).

---

## 5. Lab control API

`lab-control` binds to `127.0.0.1:9100` and is deliberately excluded from the
scanner scope.

| Endpoint | Purpose |
|---|---|
| `POST /__lab/reset` | Reset every service to its seed state |
| `POST /__lab/seed?profile=small\|large` | Choose data volume |
| `GET /__lab/vulns` | Filtered ground truth |
| `GET /__lab/controls` | Safe twins |
| `GET/PUT /__lab/mode` | Restrict by service, OWASP category, level |
| `GET/PUT /__lab/waf` | Select a WAF profile |
| `GET/POST /__lab/events` | Exploit-trigger event log |
| `POST /__lab/session/start\|stop` | Timed measurement session |
| `GET /__lab/health` | Health of every service |

---

## 6. Repository layout

```
vulnforge/
├── docker_install.sh          one-shot installer and launcher
├── docker-compose.yml         profiles, networks, resource limits
├── Makefile                   install/up/down/reset/truth/catalog/test/score
├── LICENSE                    AGPL-3.0 only
├── NOTICE                     author and license summary
├── README.md / README.tr.md   English and Turkish overview
├── gateway/                   Nginx entry point, WAF/TLS profiles
├── services/
│   ├── php-web/               SQLi, XSS, CMDi, LFI, upload, CSRF, IDOR, auth
│   ├── node-api/              REST API and OWASP API Top 10
│   ├── flask-svc/             SSTI, deserialization, SSRF, ReDoS
│   ├── spring-svc/            XXE, XMLDecoder, EL injection, JNDI
│   ├── go-svc/                SSRF, race condition, business logic
│   ├── graphql-svc/           GraphQL-specific weaknesses
│   ├── crawl-lab/             crawler coverage surface
│   ├── legacy-svc/            outdated components and exposed files
│   └── auth-svc/              OAuth / OIDC / SAML weaknesses
├── infra/                     OOB collector, metadata simulator, mailhog, exposed services
├── lab/
│   ├── lab-control/           reset, seed, mode, events, sessions
│   ├── tools/                 extract_truth.py, generate_catalog.py
│   └── truth/                 generated vulns.json, controls.json, schema.json
├── scorer/                    adapters + report generator
├── tests/                     smoke/control runner and payload specs
└── docs/                      English docs + docs/tr Turkish versions
```

---

## 7. Documentation

| English | Türkçe |
|---|---|
| [docs/installation.md](docs/installation.md) | [docs/tr/kurulum.md](docs/tr/kurulum.md) |
| [docs/scoring.md](docs/scoring.md) | [docs/tr/skorlama.md](docs/tr/skorlama.md) |
| [docs/scanner-integration.md](docs/scanner-integration.md) | [docs/tr/tarayici-entegrasyonu.md](docs/tr/tarayici-entegrasyonu.md) |
| [docs/vulnerability-catalog.md](docs/vulnerability-catalog.md) | [docs/tr/zafiyet-katalogu.md](docs/tr/zafiyet-katalogu.md) |
| [docs/security.md](docs/security.md) | [docs/tr/guvenlik.md](docs/tr/guvenlik.md) |
| [README.md](README.md) | [README.tr.md](README.tr.md) |

---

## 8. Safety model

- All host ports bind to `127.0.0.1`; never publish them.
- Containers run with `no-new-privileges` and CPU/memory limits.
- `data_net` and `internal_net` are internal Docker networks.
- RCE-class scenarios execute harmless commands inside the container only;
  no host mounts, no Docker socket, no outbound internet by default.
- Weak TLS, default credentials and exposed services are intentional and
  documented; they must not be reused anywhere else.
- All seed data is synthetic.

Read [docs/security.md](docs/security.md) before running the lab on a shared
host.

---

## 9. License

Copyright (C) 2026 Cuma KURT.

VulnForge Lab is free software licensed under the **GNU Affero General Public
License v3.0 only** (`AGPL-3.0-only`). See [LICENSE](LICENSE) for the full text.

Because this is a network-accessible application, the AGPL requires that users
interacting with it over a network be offered the corresponding source code.
If you deploy a modified version, you must publish your changes under the same
license.

This program is distributed in the hope that it will be useful, but **without
any warranty**; without even the implied warranty of merchantability or fitness
for a particular purpose.

---

## 10. Author

**Cuma KURT**

- E-mail: <cumakurt@gmail.com>
- LinkedIn: <https://www.linkedin.com/in/cuma-kurt-34414917/>
- GitHub: <https://github.com/cumakurt/vulnforge>

Use this lab only for authorised security testing and education. Never use the
techniques it contains against systems you do not own or have explicit
permission to test.
