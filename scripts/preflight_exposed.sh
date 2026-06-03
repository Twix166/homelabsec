#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'ERROR: %s\n' "$1" >&2
  exit 1
}

EDGE_AUTH_MODE="${EDGE_AUTH_MODE:-basic}"
EDGE_AUTH_USERNAME="${EDGE_AUTH_USERNAME:-admin}"
EDGE_AUTH_PASSWORD="${EDGE_AUTH_PASSWORD:-change-me-now}"
EDGE_TLS_MODE="${EDGE_TLS_MODE:-self_signed}"
EDGE_SERVER_NAME="${EDGE_SERVER_NAME:-localhost}"

if [[ "$EDGE_AUTH_MODE" == "basic" ]]; then
  [[ -n "$EDGE_AUTH_USERNAME" ]] || fail "EDGE_AUTH_USERNAME is required when EDGE_AUTH_MODE=basic"
  [[ -n "$EDGE_AUTH_PASSWORD" ]] || fail "EDGE_AUTH_PASSWORD is required when EDGE_AUTH_MODE=basic"
  if [[ "$EDGE_AUTH_PASSWORD" == "change-me-now" ]]; then
    fail "EDGE_AUTH_PASSWORD must be changed from the default value change-me-now before using the exposed edge"
  fi
elif [[ "$EDGE_AUTH_MODE" != "oauth2_proxy" && "$EDGE_AUTH_MODE" != "none" ]]; then
  fail "EDGE_AUTH_MODE must be one of: basic, oauth2_proxy, none"
fi

if [[ "$EDGE_TLS_MODE" != "self_signed" && "$EDGE_TLS_MODE" != "provided" ]]; then
  fail "EDGE_TLS_MODE must be one of: self_signed, provided"
fi

if [[ -z "$EDGE_SERVER_NAME" ]]; then
  fail "EDGE_SERVER_NAME must not be blank"
fi

printf 'Exposed edge preflight passed\n'
