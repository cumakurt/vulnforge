#!/usr/bin/env bash
#
# VulnForge Lab — one-shot installer and launcher.
#
# What it does
#   1. Detects the host OS and package manager.
#   2. Verifies Docker, the Compose plugin and the other required tools.
#   3. Asks for explicit approval before installing any missing package.
#   4. Creates .env when needed and picks a free HTTP port.
#   5. Builds and starts the requested Compose profile.
#   6. Waits for health, then prints the access information.
#
# WARNING: VulnForge Lab is intentionally vulnerable. Only run it on a machine
# you control, bound to loopback, never exposed to the internet.
#
# Usage:
#   ./docker_install.sh                     # core profile
#   ./docker_install.sh --profile full      # every service
#   ./docker_install.sh --port 18000 --yes  # unattended
#   ./docker_install.sh --help

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PROFILE="core"
HTTP_PORT=""
ASSUME_YES="false"
SKIP_TESTS="false"
SKIP_BUILD="false"
LAB_CONTROL_PORT="9100"
HTTPS_PORT=""

# ─── Output helpers ──────────────────────────────────────────────────────────

if [ -t 1 ]; then
  C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m'; C_RED=$'\033[31m'; C_CYAN=$'\033[36m'
else
  C_RESET=""; C_BOLD=""; C_GREEN=""; C_YELLOW=""; C_RED=""; C_CYAN=""
fi

info()  { printf '%s[*]%s %s\n' "$C_CYAN" "$C_RESET" "$*"; }
ok()    { printf '%s[+]%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn()  { printf '%s[!]%s %s\n' "$C_YELLOW" "$C_RESET" "$*"; }
fail()  { printf '%s[x]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; }
die()   { fail "$*"; exit 1; }

banner() {
  printf '%s\n' "$C_BOLD"
  cat <<'EOF'
 __     __      _  __ _____
 \ \   / /_   _| |/ _|  ___|__  _ __ __ _  ___
  \ \ / /| | | | | |_| |_ / _ \| '__/ _` |/ _ \
   \ V / | |_| | |  _|  _| (_) | | | (_| |  __/
    \_/   \__,_|_|_| |_|  \___/|_|  \__, |\___|
                                    |___/
EOF
  printf '%s\n' "$C_RESET"
  printf 'VulnForge Lab — intentionally vulnerable scanner benchmark\n'
  printf 'Author: Cuma KURT <cumakurt@gmail.com>\n'
  printf 'License: AGPL-3.0 only\n\n'
}

usage() {
  cat <<'EOF'
Usage: ./docker_install.sh [options]

Options:
  --profile <core|full|api|infra|waf|crawl>
                          Compose profile to start (default: core)
  --port <port>           Host HTTP port for the gateway (default: 8000 or next free)
  --https-port <port>     Host HTTPS port for the gateway (default: 8443)
  --lab-port <port>       Host port for lab-control (default: 9100)
  --yes                   Do not ask for confirmation before installing packages
  --skip-build            Reuse existing images
  --skip-tests            Do not run the smoke suite after startup
  --help                  Show this help

Examples:
  ./docker_install.sh
  ./docker_install.sh --profile full --yes
  ./docker_install.sh --port 18000 --skip-tests
EOF
}

# ─── Argument parsing ────────────────────────────────────────────────────────

while [ $# -gt 0 ]; do
  case "$1" in
    --profile)     PROFILE="${2:-}"; shift 2 ;;
    --port)        HTTP_PORT="${2:-}"; shift 2 ;;
    --https-port)  HTTPS_PORT="${2:-}"; shift 2 ;;
    --lab-port)    LAB_CONTROL_PORT="${2:-}"; shift 2 ;;
    --yes|-y)      ASSUME_YES="true"; shift ;;
    --skip-build)  SKIP_BUILD="true"; shift ;;
    --skip-tests)  SKIP_TESTS="true"; shift ;;
    --help|-h)     usage; exit 0 ;;
    *)             die "unknown option: $1 (see --help)" ;;
  esac
done

case "$PROFILE" in
  core|full|api|infra|waf|crawl) ;;
  *) die "invalid profile '$PROFILE' (core|full|api|infra|waf|crawl)" ;;
esac

# ─── OS / package manager detection ─────────────────────────────────────────

detect_platform() {
  OS_NAME="$(uname -s)"
  PKG_MANAGER=""
  INSTALL_CMD=""

  if [ "$OS_NAME" = "Darwin" ]; then
    if command -v brew >/dev/null 2>&1; then
      PKG_MANAGER="brew"; INSTALL_CMD="brew install"
    fi
    return
  fi

  if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    DISTRO="${ID:-unknown}"
  else
    DISTRO="unknown"
  fi

  if command -v apt-get >/dev/null 2>&1; then
    PKG_MANAGER="apt"; INSTALL_CMD="apt-get install -y"
  elif command -v dnf >/dev/null 2>&1; then
    PKG_MANAGER="dnf"; INSTALL_CMD="dnf install -y"
  elif command -v yum >/dev/null 2>&1; then
    PKG_MANAGER="yum"; INSTALL_CMD="yum install -y"
  elif command -v pacman >/dev/null 2>&1; then
    PKG_MANAGER="pacman"; INSTALL_CMD="pacman -S --noconfirm"
  elif command -v zypper >/dev/null 2>&1; then
    PKG_MANAGER="zypper"; INSTALL_CMD="zypper install -y"
  elif command -v apk >/dev/null 2>&1; then
    PKG_MANAGER="apk"; INSTALL_CMD="apk add"
  fi
}

require_root_helper() {
  if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
  elif command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
  else
    SUDO=""
  fi
}

confirm() {
  local prompt="$1"
  if [ "$ASSUME_YES" = "true" ]; then
    return 0
  fi
  if [ ! -t 0 ]; then
    return 1
  fi
  local answer
  read -r -p "$prompt [y/N] " answer
  case "$answer" in
    y|Y|yes|YES) return 0 ;;
    *) return 1 ;;
  esac
}

install_packages() {
  local packages="$*"
  if [ -z "$PKG_MANAGER" ]; then
    die "no supported package manager found; install manually: $packages"
  fi

  warn "The following packages are missing: $packages"
  warn "Package manager: $PKG_MANAGER"
  if ! confirm "Install them now?"; then
    die "installation cancelled by the user; re-run with --yes to install automatically"
  fi

  info "Installing: $packages"
  # shellcheck disable=SC2086
  if [ "$PKG_MANAGER" = "apt" ]; then
    $SUDO apt-get update -y
    $SUDO apt-get install -y $packages
  elif [ "$PKG_MANAGER" = "pacman" ]; then
    $SUDO pacman -Sy --noconfirm $packages
  else
    # shellcheck disable=SC2086
    $SUDO $INSTALL_CMD $packages
  fi
}

ensure_command() {
  local command_name="$1"
  local package_name="${2:-$1}"
  if command -v "$command_name" >/dev/null 2>&1; then
    return 0
  fi
  MISSING_PACKAGES="${MISSING_PACKAGES:-} $package_name"
  return 1
}

# ─── Docker preparation ─────────────────────────────────────────────────────

DOCKER=""

detect_docker() {
  if command -v docker >/dev/null 2>&1; then
    if docker info >/dev/null 2>&1; then
      DOCKER="docker"
    elif command -v sudo >/dev/null 2>&1 && sudo docker info >/dev/null 2>&1; then
      DOCKER="sudo docker"
      warn "docker requires sudo on this host; using 'sudo docker'"
    else
      warn "docker is installed but the daemon is not reachable"
      if confirm "Try to start the Docker daemon?"; then
        if command -v systemctl >/dev/null 2>&1; then
          $SUDO systemctl enable --now docker || true
        elif command -v service >/dev/null 2>&1; then
          $SUDO service docker start || true
        elif [ "$OS_NAME" = "Darwin" ]; then
          open -a Docker || true
        fi
        sleep 5
        if docker info >/dev/null 2>&1; then
          DOCKER="docker"
        elif sudo docker info >/dev/null 2>&1; then
          DOCKER="sudo docker"
        fi
      fi
    fi
  fi

  [ -n "$DOCKER" ] || return 1
  $DOCKER compose version >/dev/null 2>&1 || return 2
  return 0
}

# ─── Port helpers ───────────────────────────────────────────────────────────

port_in_use() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -ltn 2>/dev/null | awk -v p=":$port" '$4 ~ p"$" {found=1} END {exit found?0:1}'
  elif command -v lsof >/dev/null 2>&1; then
    lsof -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1
  elif command -v netstat >/dev/null 2>&1; then
    netstat -ltn 2>/dev/null | awk -v p=":$port" '$4 ~ p"$" {found=1} END {exit found?0:1}'
  else
    return 1
  fi
}

choose_port() {
  local preferred="$1"
  if [ -n "$HTTP_PORT" ]; then
    echo "$HTTP_PORT"
    return
  fi
  if ! port_in_use "$preferred"; then
    echo "$preferred"
    return
  fi
  local candidate
  for candidate in 18000 18080 28000 38000; do
    if ! port_in_use "$candidate"; then
      warn "port $preferred is already in use, using $candidate" >&2
      echo "$candidate"
      return
    fi
  done
  die "no free HTTP port found (tried $preferred, 18000, 18080, 28000, 38000)"
}

# ─── Main flow ──────────────────────────────────────────────────────────────

banner
detect_platform
require_root_helper
info "Host: ${OS_NAME:-unknown} / package manager: ${PKG_MANAGER:-none}"

MISSING_PACKAGES=""
COMPOSE_AVAILABLE="false"

if detect_docker; then
  COMPOSE_AVAILABLE="true"
else
  case $? in
    2) MISSING_PACKAGES="$MISSING_PACKAGES docker-compose-plugin" ;;
    *) MISSING_PACKAGES="$MISSING_PACKAGES docker.io docker-compose-plugin" ;;
  esac
fi

ensure_command curl curl || true
ensure_command python3 python3 || true

# Optional: only needed for the smoke suite.
if [ "$SKIP_TESTS" = "false" ]; then
  ensure_command pip3 python3-pip || true
fi

if [ -n "${MISSING_PACKAGES// /}" ]; then
  info "Missing packages:${MISSING_PACKAGES}"
  if [ "$PKG_MANAGER" = "apt" ]; then
    MISSING_PACKAGES="${MISSING_PACKAGES/docker.io/docker.io}"
    install_packages $MISSING_PACKAGES
  else
    install_packages $MISSING_PACKAGES
  fi
  detect_platform
  require_root_helper
  if ! detect_docker; then
    die "docker is still unavailable after installation; start Docker manually and re-run"
  fi
  COMPOSE_AVAILABLE="true"
fi

[ "$COMPOSE_AVAILABLE" = "true" ] || die "docker compose is not available"
ok "docker $($DOCKER version --format '{{.Server.Version}}' 2>/dev/null || echo present) with compose plugin"

# .env
if [ ! -f .env ]; then
  if [ -f .env.example ]; then
    cp .env.example .env
    ok "created .env from .env.example"
  else
    warn ".env.example not found; using built-in defaults"
  fi
fi

HTTP_PORT="$(choose_port 8000)"
if [ -z "$HTTPS_PORT" ]; then
  if port_in_use 8443; then HTTPS_PORT=18443; else HTTPS_PORT=8443; fi
fi

export GATEWAY_HTTP_PORT="$HTTP_PORT"
export GATEWAY_HTTPS_PORT="$HTTPS_PORT"
export LAB_CONTROL_PORT="$LAB_CONTROL_PORT"
export COMPOSE_PROFILES="$PROFILE"

info "Starting profile '$PROFILE' (gateway on 127.0.0.1:$HTTP_PORT)"

compose() { $DOCKER compose --profile "$PROFILE" "$@"; }

if [ "$SKIP_BUILD" = "true" ]; then
  compose up -d
else
  info "Building images (first run downloads base images and may take a few minutes)"
  compose up -d --build
fi

info "Waiting for services to become healthy…"
HEALTHY="false"
for _attempt in $(seq 1 90); do
  if curl -fsS -m 3 "http://127.0.0.1:$LAB_CONTROL_PORT/__lab/mode" >/dev/null 2>&1 \
     && curl -fsS -m 3 "http://127.0.0.1:$HTTP_PORT/" >/dev/null 2>&1; then
    HEALTHY="true"
    break
  fi
  sleep 2
done

if [ "$HEALTHY" != "true" ]; then
  warn "services did not report healthy in time"
  $DOCKER compose --profile "$PROFILE" ps || true
  die "startup did not complete; inspect logs with: $DOCKER compose logs"
fi
ok "all services are healthy"

# Optional smoke suite
if [ "$SKIP_TESTS" = "false" ]; then
  if python3 -c "import requests" >/dev/null 2>&1; then
    info "Running the smoke suite (this exercises every vulnerability)"
    if python3 tests/run_tests.py --mode smoke \
        --base-url "http://127.0.0.1:$HTTP_PORT" \
        --lab-control "http://127.0.0.1:$LAB_CONTROL_PORT"; then
      ok "smoke suite passed"
    else
      warn "smoke suite reported failures; see the output above"
    fi
  else
    warn "python 'requests' is not installed; skipping the smoke suite"
    warn "install it with: pip3 install -r tests/requirements.txt"
  fi
fi

# ─── Access summary ─────────────────────────────────────────────────────────

GW="http://127.0.0.1:$HTTP_PORT"
cat <<EOF

${C_BOLD}VulnForge Lab is running${C_RESET}
────────────────────────────────────────────────────────────
Gateway (scanner target) : $GW
  PHP web                : $GW/php/sqli/products.php?id=1
  Node API               : $GW/api/v1/products
  Flask service          : $GW/py/ssti?name=World
  Java service           : $GW/java/template?name=World
  Go service             : $GW/go/proxy?url=http://example.invalid
  GraphQL                : $GW/graphql
  Crawl lab (SPA)        : $GW/spa/
  Legacy service         : $GW/legacy/
  Auth service           : $GW/auth/
  HTTPS (self-signed)    : https://127.0.0.1:$HTTPS_PORT

Lab control (out of scope for scanners)
  Health                 : http://127.0.0.1:$LAB_CONTROL_PORT/__lab/health
  Ground truth           : http://127.0.0.1:$LAB_CONTROL_PORT/__lab/vulns
  Reset                  : curl -X POST http://127.0.0.1:$LAB_CONTROL_PORT/__lab/reset
  Events                 : http://127.0.0.1:$LAB_CONTROL_PORT/__lab/events

Any additional host services for the selected profile:
EOF

$DOCKER compose --profile "$PROFILE" ps --format '  {{.Name}}  {{.Status}}' 2>/dev/null || true

cat <<EOF

Demo credentials (synthetic):
  PHP web     : alice / password1        admin / admin123
  Node API    : alice / password1
  Auth service: alice / password1
  Legacy      : admin / admin  (default credentials on purpose)

Useful commands:
  make down                 stop the stack
  make reset                reset databases and events
  make smoke                prove every vulnerability is exploitable
  make controls             prove every safe twin is not
  make score                render an example scorer report

${C_YELLOW}Reminder: this lab is intentionally insecure. Keep it on loopback and never
publish these ports.${C_RESET}
EOF
