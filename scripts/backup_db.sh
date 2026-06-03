#!/usr/bin/env bash
set -euo pipefail

SCRIPT_PATH="${BASH_SOURCE[0]}"
SCRIPT_DIR="${SCRIPT_PATH%/*}"
ROOT_DIR="${SCRIPT_DIR%/*}"
COMPOSE_FILE="${COMPOSE_FILE:-$ROOT_DIR/compose/compose.yaml}"
COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-homelabsec-backup}"
POSTGRES_SERVICE="${POSTGRES_SERVICE:-postgres}"
POSTGRES_DB="${POSTGRES_DB:-homelabsec}"
POSTGRES_USER="${POSTGRES_USER:-homelabsec}"
OUTPUT_PATH="${1:-$ROOT_DIR/backups/homelabsec_$(date -u +%Y%m%dT%H%M%SZ).sql}"

if [[ "${1:-}" == "--status" ]]; then
  docker_available=false
  if command -v docker >/dev/null 2>&1; then
    docker_available=true
  fi
  compose_file_exists=false
  if [[ -f "$COMPOSE_FILE" ]]; then
    compose_file_exists=true
  fi
  ready=false
  if [[ "$docker_available" == true && "$compose_file_exists" == true ]]; then
    ready=true
  fi
  printf '{"docker_available":%s,"compose_file_exists":%s,"ready":%s}\n' \
    "$docker_available" "$compose_file_exists" "$ready"
  exit 0
fi

mkdir -p "$(dirname "$OUTPUT_PATH")"

docker compose -p "$COMPOSE_PROJECT_NAME" -f "$COMPOSE_FILE" exec -T "$POSTGRES_SERVICE" \
  pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists --no-owner --no-privileges >"$OUTPUT_PATH"

printf 'Backup written to %s\n' "$OUTPUT_PATH"
