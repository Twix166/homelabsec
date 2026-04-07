#!/bin/sh
set -eu

CONFIG_PATH="/etc/alertmanager/alertmanager.yml"
DEFAULT_RECEIVER="${ALERTMANAGER_DEFAULT_RECEIVER:-null}"

mkdir -p /etc/alertmanager

case "$DEFAULT_RECEIVER" in
  null)
    RECEIVER_BLOCKS='
  - name: "null"
'
    GLOBAL_BLOCK=''
    ;;
  webhook)
    : "${ALERTMANAGER_WEBHOOK_URL:?ALERTMANAGER_WEBHOOK_URL is required when ALERTMANAGER_DEFAULT_RECEIVER=webhook}"
    RECEIVER_BLOCKS="
  - name: \"webhook\"
    webhook_configs:
      - url: \"${ALERTMANAGER_WEBHOOK_URL}\"
        send_resolved: true
"
    GLOBAL_BLOCK=''
    ;;
  email)
    : "${ALERTMANAGER_EMAIL_TO:?ALERTMANAGER_EMAIL_TO is required when ALERTMANAGER_DEFAULT_RECEIVER=email}"
    : "${ALERTMANAGER_EMAIL_FROM:?ALERTMANAGER_EMAIL_FROM is required when ALERTMANAGER_DEFAULT_RECEIVER=email}"
    : "${ALERTMANAGER_SMARTHOST:?ALERTMANAGER_SMARTHOST is required when ALERTMANAGER_DEFAULT_RECEIVER=email}"
    GLOBAL_BLOCK="
global:
  smtp_from: \"${ALERTMANAGER_EMAIL_FROM}\"
  smtp_smarthost: \"${ALERTMANAGER_SMARTHOST}\"
  smtp_auth_username: \"${ALERTMANAGER_SMTP_AUTH_USERNAME:-}\"
  smtp_auth_password: \"${ALERTMANAGER_SMTP_AUTH_PASSWORD:-}\"
  smtp_require_tls: ${ALERTMANAGER_SMTP_REQUIRE_TLS:-true}
"
    RECEIVER_BLOCKS="
  - name: \"email\"
    email_configs:
      - to: \"${ALERTMANAGER_EMAIL_TO}\"
        send_resolved: true
"
    ;;
  *)
    echo "Unsupported ALERTMANAGER_DEFAULT_RECEIVER=$DEFAULT_RECEIVER" >&2
    exit 1
    ;;
esac

cat > "$CONFIG_PATH" <<EOF
${GLOBAL_BLOCK}
route:
  receiver: "${DEFAULT_RECEIVER}"
  group_by: ["alertname", "job"]
  group_wait: 10s
  group_interval: 30s
  repeat_interval: 4h

receivers:${RECEIVER_BLOCKS}

templates: []
EOF

exec /bin/alertmanager \
  --config.file="$CONFIG_PATH" \
  --storage.path=/alertmanager \
  --web.listen-address=:9093
