#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-$ROOT_DIR/compose/compose.yaml}"
COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-homelabsec-backup}"
POSTGRES_SERVICE="${POSTGRES_SERVICE:-postgres}"
POSTGRES_DB="${POSTGRES_DB:-homelabsec}"
POSTGRES_USER="${POSTGRES_USER:-homelabsec}"
INPUT_PATH="${1:-}"

if [[ -z "$INPUT_PATH" || ! -f "$INPUT_PATH" ]]; then
  echo "Usage: $0 /path/to/backup.sql" >&2
  exit 1
fi

docker compose -p "$COMPOSE_PROJECT_NAME" -f "$COMPOSE_FILE" exec -T "$POSTGRES_SERVICE" \
  psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" <"$INPUT_PATH"

printf 'Restore applied from %s\n' "$INPUT_PATH"
