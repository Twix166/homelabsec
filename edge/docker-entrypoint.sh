#!/bin/sh
set -eu

EDGE_AUTH_MODE="${EDGE_AUTH_MODE:-basic}"
EDGE_SERVER_NAME="${EDGE_SERVER_NAME:-localhost}"
EDGE_TLS_MODE="${EDGE_TLS_MODE:-self_signed}"
EDGE_CERT_PATH="${EDGE_CERT_PATH:-/etc/nginx/certs/tls.crt}"
EDGE_KEY_PATH="${EDGE_KEY_PATH:-/etc/nginx/certs/tls.key}"

mkdir -p "$(dirname "$EDGE_CERT_PATH")"

TEMPLATE_PATH="/etc/nginx/templates/default.conf.template"

if [ "$EDGE_AUTH_MODE" = "basic" ]; then
  : "${EDGE_AUTH_USERNAME:?EDGE_AUTH_USERNAME is required}"
  : "${EDGE_AUTH_PASSWORD:?EDGE_AUTH_PASSWORD is required}"
  htpasswd -bc /etc/nginx/.htpasswd "$EDGE_AUTH_USERNAME" "$EDGE_AUTH_PASSWORD"
elif [ "$EDGE_AUTH_MODE" = "oauth2_proxy" ]; then
  TEMPLATE_PATH="/etc/nginx/templates/oauth2_proxy.conf.template"
else
  echo "Error: unsupported EDGE_AUTH_MODE=$EDGE_AUTH_MODE" >&2
  exit 1
fi

if [ "$EDGE_TLS_MODE" = "self_signed" ]; then
  if [ ! -f "$EDGE_CERT_PATH" ] || [ ! -f "$EDGE_KEY_PATH" ]; then
    openssl req -x509 -nodes -days 365 \
      -newkey rsa:2048 \
      -keyout "$EDGE_KEY_PATH" \
      -out "$EDGE_CERT_PATH" \
      -subj "/CN=$EDGE_SERVER_NAME"
  fi
elif [ "$EDGE_TLS_MODE" = "provided" ]; then
  if [ ! -f "$EDGE_CERT_PATH" ] || [ ! -f "$EDGE_KEY_PATH" ]; then
    echo "Error: EDGE_TLS_MODE=provided requires $EDGE_CERT_PATH and $EDGE_KEY_PATH" >&2
    exit 1
  fi
else
  echo "Error: unsupported EDGE_TLS_MODE=$EDGE_TLS_MODE" >&2
  exit 1
fi

export EDGE_SERVER_NAME EDGE_CERT_PATH EDGE_KEY_PATH
envsubst '${EDGE_SERVER_NAME} ${EDGE_CERT_PATH} ${EDGE_KEY_PATH}' \
  < "$TEMPLATE_PATH" \
  > /etc/nginx/conf.d/default.conf

exec nginx -g 'daemon off;'
