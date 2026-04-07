#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-$ROOT_DIR/compose/compose.yaml}"
COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-homelabsec-backup}"
POSTGRES_SERVICE="${POSTGRES_SERVICE:-postgres}"
POSTGRES_DB="${POSTGRES_DB:-homelabsec}"
POSTGRES_USER="${POSTGRES_USER:-homelabsec}"
OUTPUT_PATH="${1:-$ROOT_DIR/backups/homelabsec_$(date -u +%Y%m%dT%H%M%SZ).sql}"

mkdir -p "$(dirname "$OUTPUT_PATH")"

docker compose -p "$COMPOSE_PROJECT_NAME" -f "$COMPOSE_FILE" exec -T "$POSTGRES_SERVICE" \
  pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists --no-owner --no-privileges >"$OUTPUT_PATH"

printf 'Backup written to %s\n' "$OUTPUT_PATH"
