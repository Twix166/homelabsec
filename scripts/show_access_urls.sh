#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ENV_FILE:-$ROOT_DIR/.env}"

if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

EDGE_HTTP_PORT="${EDGE_HTTP_PORT:-8081}"
EDGE_HTTPS_PORT="${EDGE_HTTPS_PORT:-8443}"
PROMETHEUS_HOST_PORT="${PROMETHEUS_HOST_PORT:-9090}"
ALERTMANAGER_HOST_PORT="${ALERTMANAGER_HOST_PORT:-9093}"
GRAFANA_HOST_PORT="${GRAFANA_HOST_PORT:-3001}"
API_HOST_PORT="${API_HOST_PORT:-8088}"
FRONTEND_HOST_PORT="${FRONTEND_HOST_PORT:-8080}"

cat <<EOF
HomelabSec access URLs
  Dashboard:     http://localhost:${FRONTEND_HOST_PORT}
  API:           http://localhost:${API_HOST_PORT}
  Prometheus:    http://127.0.0.1:${PROMETHEUS_HOST_PORT}
  Alertmanager:  http://127.0.0.1:${ALERTMANAGER_HOST_PORT}
  Grafana:       http://127.0.0.1:${GRAFANA_HOST_PORT}
  Secure edge:   http://localhost:${EDGE_HTTP_PORT}
  Secure edge:   https://localhost:${EDGE_HTTPS_PORT}
EOF
