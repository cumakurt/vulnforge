# Installation

VulnForge Lab runs as a Docker Compose stack. The recommended path is the
one-shot installer, which detects missing packages and asks before installing
anything.

## Requirements

| Component | Minimum | Notes |
|---|---|---|
| Docker Engine | 20.10+ | Rootless or sudo is fine |
| Docker Compose plugin | 2.20+ | `docker compose` (v2), not `docker-compose` v1 |
| curl | any | Health probes and installer checks |
| python3 + pip | 3.10+ | Only for the smoke suite and the scorer |
| RAM | 2 GB (core) / 8 GB (full) | Full profile runs 18 containers |
| Disk | 6 GB | Base images and build cache |

## Automated installation

```bash
./docker_install.sh                  # core: gateway, php-web, mysql, lab-control
./docker_install.sh --profile full   # every service
```

The script performs these steps:

1. Detects the OS and package manager (`apt`, `dnf`, `yum`, `pacman`, `zypper`,
   `apk`, `brew`).
2. Checks Docker, the Compose plugin, curl and python3.
3. If something is missing, prints the exact package list and **waits for
   approval** before running the package manager.
4. Starts the Docker daemon when it is installed but stopped (with approval).
5. Creates `.env` from `.env.example` when needed.
6. Chooses a free host port, because `8000` is often already taken by another
   container (the script falls back to `18000`, `18080`, `28000`, `38000`).
7. Builds and starts the selected Compose profile.
8. Polls `lab-control` and the gateway until they are healthy.
9. Runs the smoke suite when `python3-requests` is available.
10. Prints every access URL, demo credential and useful `make` target.

### Flags

```
--profile <core|full|api|infra|waf|crawl>
--port <port>            gateway HTTP port
--https-port <port>      gateway HTTPS port
--lab-port <port>        lab-control port
--yes                    never prompt (CI)
--skip-build             reuse existing images
--skip-tests             do not run the smoke suite
--help
```

### Unattended example

```bash
./docker_install.sh --profile full --port 18000 --yes --skip-tests
```

## Manual installation

```bash
cp .env.example .env
docker compose --profile full up -d --build
curl -X POST http://127.0.0.1:9100/__lab/reset
```

Check health:

```bash
docker compose --profile full ps
curl -s http://127.0.0.1:9100/__lab/health | python3 -m json.tool
```

## Profiles

| Profile | Services |
|---|---|
| `core` | gateway, php-web, mysql, lab-control |
| `full` | every service, infrastructure and lab tooling |
| `api` | API-focused subset (node-api, flask-svc, graphql-svc, mongodb, postgres) |
| `infra` | exposed infrastructure (redis, mailhog, OOB collector, metadata) |
| `waf` | gateway plus WAF/TLS profile work |
| `crawl` | crawl-lab and the gateway |

## Configuration

Copy `.env.example` to `.env` and adjust:

| Variable | Default | Purpose |
|---|---|---|
| `BIND_HOST` | `127.0.0.1` | Host interface for published ports |
| `GATEWAY_HTTP_PORT` | `8000` | Gateway HTTP port |
| `GATEWAY_HTTPS_PORT` | `8443` | Gateway HTTPS port |
| `LAB_CONTROL_PORT` | `9100` | lab-control port |
| `WAF_PROFILE` | `waf-off` | WAF profile name |
| `SEED_PROFILE` | `small` | `small` or `large` seed data |
| `ALLOW_EGRESS` | `false` | Permit outbound internet from SSRF targets |

Never set `BIND_HOST=0.0.0.0` on a shared or internet-facing host.

## Verification

```bash
pip install -r tests/requirements.txt
make smoke      # 99 checks: every vulnerability is exploitable
make controls   # 99 checks: every safe twin rejects the payload
make test       # both
```

## Troubleshooting

### Port already allocated

Another process (often Portainer) owns `8000`. Either pass `--port 18000` or let
the installer choose a free port automatically.

### `docker compose` not found

Install the Compose v2 plugin. The legacy `docker-compose` v1 binary is not
supported.

### A service stays unhealthy

```bash
docker compose --profile full logs <service>
docker compose --profile full ps
```

`lab-control` reports which service is down:

```bash
curl -s http://127.0.0.1:9100/__lab/health | python3 -m json.tool
```

### SSRF tests fail in the core profile

`internal-metadata`, `oob-collector` and the Go/Flask SSRF targets belong to the
`full` profile. Run `./docker_install.sh --profile full` for the complete suite.

### Permission denied on the Docker socket

Add your user to the `docker` group and re-login, or run the installer with
`sudo`.
