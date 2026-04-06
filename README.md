#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/Twix16/homelabsec.git}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/homelabsec}"
BRANCH="${BRANCH:-main}"

log() {
  printf '\n[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Error: required command not found: $1" >&2
    exit 1
  }
}

detect_compose() {
  if docker compose version >/dev/null 2>&1; then
    echo "docker compose"
    return
  fi
  if command -v docker-compose >/dev/null 2>&1; then
    echo "docker-compose"
    return
  fi
  echo ""
}

log "Checking prerequisites"
need_cmd git
need_cmd curl

if ! command -v docker >/dev/null 2>&1; then
  echo "Error: Docker is not installed." >&2
  echo "Install Docker first, then re-run this script." >&2
  exit 1
fi

COMPOSE_CMD="$(detect_compose)"
if [[ -z "$COMPOSE_CMD" ]]; then
  echo "Error: Docker Compose is not available." >&2
  echo "Install Docker Compose plugin or docker-compose first." >&2
  exit 1
fi

log "Using compose command: $COMPOSE_CMD"

if [[ -d "$INSTALL_DIR/.git" ]]; then
  log "Existing repo found in $INSTALL_DIR, updating"
  git -C "$INSTALL_DIR" fetch origin
  git -C "$INSTALL_DIR" checkout "$BRANCH"
  git -C "$INSTALL_DIR" pull --ff-only origin "$BRANCH"
else
  log "Cloning repo into $INSTALL_DIR"
  git clone --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR"
fi

cd "$INSTALL_DIR"

if [[ ! -f .env && -f .env.example ]]; then
  log "Creating .env from .env.example"
  cp .env.example .env
fi

mkdir -p discovery/raw

if [[ ! -f compose/.env && -f .env ]]; then
  log "Copying .env into compose/.env for docker compose"
  cp .env compose/.env
fi

log "Starting containers"
cd compose
$COMPOSE_CMD up -d

log "Waiting briefly for services"
sleep 5

log "Health check"
curl -fsS http://localhost:8088/health || true

cat <<EOF

Install complete.

Repo location:
  $INSTALL_DIR

Useful commands:
  cd $INSTALL_DIR/compose
  $COMPOSE_CMD ps
  $COMPOSE_CMD logs -f brain
  curl http://localhost:8088/health

Next steps:
  1. Edit $INSTALL_DIR/.env if needed
  2. Re-run:
       cd $INSTALL_DIR/compose && $COMPOSE_CMD up -d
  3. Review README.md for scheduler and scanning setup

EOF