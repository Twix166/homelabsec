#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/Twix166/homelabsec.git}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/homelabsec}"
BRANCH="${BRANCH:-main}"
API_BASE_URL="${API_BASE_URL:-http://localhost:8088}"
WAIT_TIMEOUT_SECONDS="${WAIT_TIMEOUT_SECONDS:-180}"

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

sync_env_file() {
  if [[ -f .env ]]; then
    log "Syncing .env into compose/.env"
    cp .env compose/.env
  fi
}

wait_for_http() {
  local url="$1"
  local label="$2"
  local deadline=$((SECONDS + WAIT_TIMEOUT_SECONDS))

  while (( SECONDS < deadline )); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      log "$label is ready"
      return 0
    fi
    sleep 2
  done

  echo "Error: timed out waiting for $label at $url" >&2
  return 1
}

validate_api_schema() {
  local summary_url="${API_BASE_URL}/report/summary"
  local payload

  if ! payload="$(curl -fsS "$summary_url")"; then
    echo "Error: API schema validation failed at $summary_url" >&2
    return 1
  fi

  printf '%s\n' "$payload" | grep -q '"assets"' || {
    echo "Error: API schema validation returned an unexpected payload: $payload" >&2
    return 1
  }
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

sync_env_file

log "Starting containers"
cd compose
$COMPOSE_CMD up -d --build

log "Waiting for API health"
wait_for_http "${API_BASE_URL}/health" "API health endpoint"

log "Validating schema-dependent API endpoint"
validate_api_schema

cat <<EOF

Install complete.

Repo location:
  $INSTALL_DIR

Useful commands:
  cd $INSTALL_DIR/compose
  $COMPOSE_CMD ps
  $COMPOSE_CMD logs -f brain
  curl ${API_BASE_URL}/health

Next steps:
  1. Edit $INSTALL_DIR/.env if needed
  2. Re-run:
       cd $INSTALL_DIR/compose && $COMPOSE_CMD up -d --build
  3. Review README.md for scheduler and scanning setup

EOF
