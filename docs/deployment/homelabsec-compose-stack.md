# HomelabSec reproducible Compose deployment

This document is the source-of-truth deployment recipe for the single-host HomelabSec stack. It captures the same infrastructure shape used by the live `pi4` deployment while keeping the instructions portable to any Linux Docker host.

## Deployment shape

HomelabSec is deployed as a Docker Compose project named `homelabsec`.

Core services:

- `homelabsec-postgres` — durable Postgres database; private to the Compose network in the UAT overlay.
- `homelabsec-brain` — API/backend; published to host loopback only by the UAT overlay.
- `homelabsec-scheduler` — discovery/report scheduler; runs with host networking for LAN discovery.
- `homelabsec-lynis-runner` — optional host-audit worker.
- `homelabsec-frontend` — web UI; published for LAN or reverse-proxy access.

Monitoring services when `compose.monitoring.yaml` is included:

- `homelabsec-prometheus`
- `homelabsec-grafana`
- `homelabsec-alertmanager`

The live pi4-style stack uses these Compose files together:

```bash
docker compose \
  --env-file ../.env \
  -f compose.yaml \
  -f compose.uat.yaml \
  -f compose.monitoring.yaml \
  up -d --build
```

## Prerequisites

Install on the target host:

- Linux with Docker Engine
- Docker Compose plugin that supports Compose file merge tags such as `!reset` and `!override`
- Git
- Curl
- Ollama reachable from the Docker host, unless `SKIP_OLLAMA_VALIDATION=true` is used for first boot
- The configured classifier model available in Ollama, for example `homelabsec-classifier`

For discovery, the host must be attached to the network you want to scan. The scheduler uses host networking, and `TARGET_SUBNET` controls the subnet it scans.

## Fresh install

Clone the repo:

```bash
git clone https://github.com/Twix166/homelabsec.git
cd homelabsec
```

Create the environment file:

```bash
cp .env.uat.example .env
```

Edit `.env` before first start:

```bash
$EDITOR .env
```

At minimum change:

- `POSTGRES_PASSWORD`
- `DEFAULT_ADMIN_PASSWORD`
- `GRAFANA_ADMIN_PASSWORD`
- `TARGET_SUBNET`
- `OLLAMA_HOST_URL` if Ollama is not on the same host
- `OLLAMA_URL` if containers need a non-default Ollama address

Start the stack:

```bash
cd compose
docker compose \
  --env-file ../.env \
  -f compose.yaml \
  -f compose.uat.yaml \
  -f compose.monitoring.yaml \
  up -d --build
```

## Port layout

The UAT example uses non-default host ports so the stack can coexist with other services.

Default UAT ports from `.env.uat.example`:

- Frontend: `http://<host>:18080`
- Brain API: `http://127.0.0.1:18088`
- Prometheus: `http://<host>:19090`
- Grafana: `http://<host>:13001`
- Alertmanager: `http://<host>:19093`
- Postgres: not published

Variables that control the layout:

```bash
BRAIN_HOST_PORT=18088
HOMELABSEC_UAT_FRONTEND_BIND=0.0.0.0
HOMELABSEC_UAT_FRONTEND_PORT=18080
MONITORING_HOST_BIND=0.0.0.0
PROMETHEUS_HOST_PORT=19090
GRAFANA_HOST_PORT=13001
ALERTMANAGER_HOST_PORT=19093
```

For a private local-only deployment, set `HOMELABSEC_UAT_FRONTEND_BIND=127.0.0.1` and `MONITORING_HOST_BIND=127.0.0.1`, then expose only through a local tunnel or a controlled reverse proxy.

## Reverse proxy / HTTPS

The Compose stack does not require a specific reverse proxy. In Robert's pi4 deployment, Nginx Proxy Manager runs on the same host and proxies HTTPS routes to the UAT host ports.

Equivalent proxy targets:

- HomelabSec frontend: `<docker-host>:18080`
- Prometheus: `<docker-host>:19090`
- Grafana: `<docker-host>:13001`
- Alertmanager: `<docker-host>:19093`

Keep the brain API on `127.0.0.1:18088`; do not expose it directly unless an authenticated edge layer is added.

If publishing the service beyond a trusted admin LAN, use the secure edge/OIDC overlays or an external reverse proxy with TLS and authentication.

## Update an existing deployment

From the deployment directory:

```bash
git pull --ff-only
cd compose
docker compose \
  --env-file ../.env \
  -f compose.yaml \
  -f compose.uat.yaml \
  -f compose.monitoring.yaml \
  up -d --build
```

The stack includes a one-shot `migrate` service. It runs before `brain` starts when the stack is brought up through Compose dependencies.

To run migrations explicitly:

```bash
cd compose
docker compose --env-file ../.env -f compose.yaml -f compose.uat.yaml run --rm migrate
```

## Verification

Check container state:

```bash
cd compose
docker compose \
  --env-file ../.env \
  -f compose.yaml \
  -f compose.uat.yaml \
  -f compose.monitoring.yaml \
  ps
```

Expected healthy services:

- `homelabsec-postgres`
- `homelabsec-brain`
- `homelabsec-scheduler`
- `homelabsec-lynis-runner`
- `homelabsec-frontend`
- `homelabsec-alertmanager`

Check application endpoints:

```bash
curl -fsS http://127.0.0.1:${BRAIN_HOST_PORT:-18088}/health
curl -fsS http://127.0.0.1:${BRAIN_HOST_PORT:-18088}/version
curl -fsS http://127.0.0.1:${BRAIN_HOST_PORT:-18088}/report/summary
curl -fsS http://127.0.0.1:${PROMETHEUS_HOST_PORT:-19090}/-/ready
curl -fsS http://127.0.0.1:${ALERTMANAGER_HOST_PORT:-19093}/-/ready
curl -fsS http://127.0.0.1:${GRAFANA_HOST_PORT:-13001}/api/health
```

Check monitoring status:

```bash
curl -fsS http://127.0.0.1:${PROMETHEUS_HOST_PORT:-19090}/api/v1/alertmanagers
curl -fsS http://127.0.0.1:${PROMETHEUS_HOST_PORT:-19090}/api/v1/alerts
curl -fsS http://127.0.0.1:${ALERTMANAGER_HOST_PORT:-19093}/api/v2/alerts
```

The `HomelabSecWatchdog` alert is intentionally present so alert routing can be validated. Treat unexpected critical/pending alerts as deployment failures.

## Backup and restore

Back up the Compose-managed Postgres database with:

```bash
./scripts/backup_db.sh
```

Restore with:

```bash
./scripts/restore_db.sh /path/to/backup.sql
```

Do not publish Postgres just to run backups. Use Compose exec/backup helpers.

## Reproducing the pi4 stack elsewhere

To reproduce the same shape on another host:

1. Install Docker, Compose, Git, Curl, and Ollama.
2. Clone this repository.
3. Copy `.env.uat.example` to `.env`.
4. Change secrets, `TARGET_SUBNET`, host ports, and Ollama values.
5. Start with `compose.yaml + compose.uat.yaml + compose.monitoring.yaml`.
6. Point any reverse proxy at the documented host ports.
7. Run the verification checks above.

No pi4-specific paths, IP addresses, hostnames, or credentials are required by the Compose files. The pi4 deployment is just one environment-specific checkout of this documented stack shape.
