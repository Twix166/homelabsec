#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_DIR="$ROOT_DIR/compose"
RUNTIME_ENV_FILE="$ROOT_DIR/.edge-runtime.env"

DEFAULT_HTTP_PORT=8081
DEFAULT_HTTPS_PORT=8443
FALLBACK_HTTP_PORT=18081
FALLBACK_HTTPS_PORT=18443
USE_OIDC=false

require_env() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "Missing required environment variable: ${name}" >&2
    exit 1
  fi
}

validate_oidc_env() {
  require_env "EDGE_OIDC_ISSUER_URL"
  require_env "EDGE_OIDC_CLIENT_ID"
  require_env "EDGE_OIDC_CLIENT_SECRET"
  require_env "EDGE_OIDC_COOKIE_SECRET"

  case "${EDGE_OIDC_ISSUER_URL}" in
    https://*|http://localhost*|http://127.0.0.1*)
      ;;
    *)
      echo "EDGE_OIDC_ISSUER_URL must use https, or localhost for local testing." >&2
      exit 1
      ;;
  esac

  if [ "${#EDGE_OIDC_COOKIE_SECRET}" -lt 16 ]; then
    echo "EDGE_OIDC_COOKIE_SECRET must be at least 16 characters." >&2
    exit 1
  fi
}

port_in_use() {
  local port="$1"
  ss -ltnH "sport = :${port}" 2>/dev/null | grep -q .
}

pair_available() {
  local http_port="$1"
  local https_port="$2"
  ! port_in_use "$http_port" && ! port_in_use "$https_port"
}

find_free_pair() {
  local candidate_http=20081
  local candidate_https=20443

  while [ "$candidate_http" -le 65535 ] && [ "$candidate_https" -le 65535 ]; do
    if pair_available "$candidate_http" "$candidate_https"; then
      printf '%s %s\n' "$candidate_http" "$candidate_https"
      return 0
    fi
    candidate_http=$((candidate_http + 1))
    candidate_https=$((candidate_https + 1))
  done

  return 1
}

choose_ports() {
  if pair_available "$DEFAULT_HTTP_PORT" "$DEFAULT_HTTPS_PORT"; then
    printf '%s %s\n' "$DEFAULT_HTTP_PORT" "$DEFAULT_HTTPS_PORT"
    return 0
  fi

  if pair_available "$FALLBACK_HTTP_PORT" "$FALLBACK_HTTPS_PORT"; then
    printf '%s %s\n' "$FALLBACK_HTTP_PORT" "$FALLBACK_HTTPS_PORT"
    return 0
  fi

  local discovered
  discovered="$(find_free_pair)" || {
    echo "Unable to find a free HTTP/HTTPS port pair for the secure edge overlay." >&2
    exit 1
  }

  local discovered_http discovered_https
  read -r discovered_http discovered_https <<<"$discovered"

  if [ ! -t 0 ]; then
    echo "Default secure edge ports are unavailable." >&2
    echo "Suggested free ports: HTTP ${discovered_http}, HTTPS ${discovered_https}." >&2
    echo "Re-run interactively or set EDGE_HTTP_PORT and EDGE_HTTPS_PORT explicitly." >&2
    exit 1
  fi

  printf 'Default secure edge ports are unavailable. Use HTTP %s and HTTPS %s instead? [y/N] ' \
    "$discovered_http" "$discovered_https"
  read -r reply
  case "${reply}" in
    y|Y|yes|YES)
      printf '%s %s\n' "$discovered_http" "$discovered_https"
      ;;
    *)
      echo "Secure edge startup cancelled." >&2
      exit 1
      ;;
  esac
}

main() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "docker is required." >&2
    exit 1
  fi

  if ! command -v ss >/dev/null 2>&1; then
    echo "ss is required for secure edge port detection." >&2
    exit 1
  fi

  while [ "$#" -gt 0 ]; do
    case "$1" in
      --oidc)
        USE_OIDC=true
        ;;
      *)
        echo "Unknown argument: $1" >&2
        echo "Usage: ./run_secure_edge.sh [--oidc]" >&2
        exit 1
        ;;
    esac
    shift
  done

  local selected
  selected="$(choose_ports)"

  local http_port https_port
  read -r http_port https_port <<<"$selected"

  echo "Starting secure edge overlay on HTTP ${http_port} and HTTPS ${https_port}."

  (
    cd "$COMPOSE_DIR"
    if [ "$USE_OIDC" = true ]; then
      validate_oidc_env
      EDGE_HTTP_PORT="$http_port" EDGE_HTTPS_PORT="$https_port" \
      EDGE_OIDC_REDIRECT_URL="${EDGE_OIDC_REDIRECT_URL:-https://localhost:${https_port}/oauth2/callback}" \
        docker compose -f compose.yaml -f compose.exposed.yaml -f compose.oidc.yaml up -d --build
    else
      EDGE_HTTP_PORT="$http_port" EDGE_HTTPS_PORT="$https_port" \
        docker compose -f compose.yaml -f compose.exposed.yaml up -d --build
    fi
  )

  cat >"$RUNTIME_ENV_FILE" <<EOF
EDGE_HTTP_PORT=${http_port}
EDGE_HTTPS_PORT=${https_port}
EDGE_AUTH_MODE=$([ "$USE_OIDC" = true ] && printf 'oidc' || printf 'basic')
EOF

  cat <<EOF
Secure edge available at:
  http://localhost:${http_port}
  https://localhost:${https_port}
EOF

  if [ "$USE_OIDC" = true ]; then
    echo "Auth mode: OIDC via oauth2-proxy"
  else
    echo "Auth mode: basic"
  fi
}

main "$@"
