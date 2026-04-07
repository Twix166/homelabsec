# HomelabSec

HomelabSec is a local homelab security inventory and monitoring system.

It currently supports:

- LAN discovery with Nmap
- ingest of Nmap XML into Postgres
- asset fingerprinting
- local AI classification via Ollama
- fingerprint history
- change persistence
- daily reporting

## Current status

This repo is at the stage where it can:

1. discover LAN assets
2. ingest network scan results
3. build per-asset fingerprints
4. classify assets using a custom Ollama model
5. persist changes into the `changes` table
6. generate a `/report/daily` summary

## Requirements

- Linux host
- Docker
- Docker Compose
- Git
- Curl
- Ollama running locally on the host
- An installed classifier model such as `homelabsec-classifier`

## Configuration

Copy `.env.example` to `.env` and change secrets before exposing the stack beyond a local trusted environment.

Important variables:

```bash
POSTGRES_DB=homelabsec
POSTGRES_USER=homelabsec
POSTGRES_PASSWORD=change-me
OLLAMA_URL=http://host.containers.internal:11434
OLLAMA_HOST_URL=http://localhost:11434
OLLAMA_MODEL=homelabsec-classifier
OLLAMA_TIMEOUT_SECONDS=120
CLASSIFICATION_FALLBACK_ROLE=unknown
CLASSIFICATION_FALLBACK_CONFIDENCE=0.10
OBSERVATIONS_LIST_LIMIT=200
FINGERPRINTS_LIST_LIMIT=200
NOTABLE_ASSET_LIMIT=20
ADMIN_STALE_SCAN_MINUTES=90
LOG_LEVEL=INFO
SCHEDULER_API_BASE=http://127.0.0.1:8088
SCHEDULER_METRICS_PORT=9100
```

`compose/compose.yaml` now reads Postgres credentials from env variables instead of embedding them directly in the file.

## Quick install

You can install directly from GitHub with:

```bash
curl -fsSL https://raw.githubusercontent.com/Twix166/homelabsec/main/install.sh | bash
```

The installer now:

- clones or updates the repository
- treats repo-root `.env` as the source of truth and resyncs `compose/.env`
- validates Ollama connectivity and model availability
- starts the stack with `--build`
- waits for `/health`
- validates schema readiness through `/report/summary`

If install exits successfully, Ollama was reachable, the configured model existed, and the API answered both a basic health check and a schema-dependent query.

Installer-related Ollama variables:

```bash
OLLAMA_HOST_URL=http://localhost:11434
OLLAMA_MODEL=homelabsec-classifier
SKIP_OLLAMA_VALIDATION=false
```

`OLLAMA_HOST_URL` is used by the installer on the host. `OLLAMA_URL` is used by the `brain` container and defaults to `http://host.containers.internal:11434`.

Installer env behavior:

- edit the repo-root `.env`
- the installer resyncs `compose/.env` only when needed
- installer-driven compose commands explicitly load `../.env`, so they do not depend on whichever env file happens to be in the current working directory

Installer guarantees on success:

- the repo is present at the requested branch
- `.env` exists
- `compose/.env` matches `.env`
- Ollama was reachable unless validation was explicitly skipped
- the configured model existed unless validation was explicitly skipped
- Postgres started
- migrations ran
- `brain`, `scheduler`, and `frontend` started
- `/health` responded
- `/report/summary` returned a schema-dependent payload

Still manual:

- choosing production-grade secrets
- deciding whether the deployment is LAN-only or exposed behind a proxy
- configuring TLS and authentication if you expose the stack beyond a trusted admin network
- setting host firewall policy
- creating and testing a recurring backup plan
- installing or updating custom Ollama models beyond the installer’s existence check

## Backup And Restore

HomelabSec now includes scripted Postgres backup and restore helpers for compose-based deployments.

Backup:

```bash
./scripts/backup_db.sh
```

Restore:

```bash
./scripts/restore_db.sh /path/to/backup.sql
```

Both scripts target the compose-managed `postgres` service by default and can be pointed at another compose file or project with environment variables:

```bash
COMPOSE_FILE=/path/to/compose.yaml
COMPOSE_PROJECT_NAME=homelabsec-test
POSTGRES_DB=homelabsec
POSTGRES_USER=homelabsec
```

The repo also includes automated integration coverage that performs a disposable backup and restore round trip, so this path is verified rather than only documented.

## Operator Helpers

To print the main local access URLs without manually inspecting compose files:

```bash
./scripts/show_access_urls.sh
```

## Web dashboard

A read-only web dashboard is available from the `frontend` service on port `8080`.

Start the stack from `compose/compose.yaml`:

```bash
cd compose
docker compose up -d --build
```

On a fresh Postgres volume, the database schema is initialized automatically from `brain/init.sql`.

For ongoing schema changes, HomelabSec now uses versioned SQL migrations from `brain/migrations/` executed by `brain/migrate.py`. The compose stack runs the one-shot `migrate` service before starting `brain`, so existing deployments can be upgraded without recreating the Postgres volume.

The `init.sql` bootstrap remains in place for brand-new Postgres volumes, but it is no longer the only schema path.

Migration authoring workflow:

1. add a new versioned SQL file in `brain/migrations/`
2. run `python3 brain/render_init_sql.py --write`
3. run tests
4. commit both the new migration and the regenerated `brain/init.sql`

If `brain/init.sql` drifts from the migration set, `python3 brain/render_init_sql.py --check` fails and the automated tests catch it.

Then open:

```text
http://localhost:8080
```

The frontend proxies API requests internally to the `brain` service, so no backend changes are required.

The summary cards on the dashboard are clickable. Selecting `Total assets`, `Observations`, `Fingerprints`, or `24h changes` opens a detail list for that category in the dashboard.

The dashboard also includes an `Admin status` panel. It shows API status, scheduler freshness, summary counts, and quick links to the main operator surfaces.

The compose stack now includes healthchecks for `postgres`, `brain`, `scheduler`, and `frontend`. `brain` waits for Postgres readiness, and the dependent services wait for the API health endpoint before starting.

The `brain` service is now built from `brain/Dockerfile` with pinned Python dependencies in `brain/requirements.txt` instead of installing packages dynamically at container startup.

## Trust Model

HomelabSec is currently designed for trusted local-network use.

Supported deployment assumptions:

- the stack runs on infrastructure you control
- the dashboard and API are reachable only from your LAN, VPN, or another trusted admin network
- Postgres is not exposed directly to untrusted clients
- Ollama is reachable only from the local host or a trusted internal network path

Current non-goals for the default compose deployment:

- multi-user access control
- internet exposure without an additional reverse proxy and auth layer
- direct public access to the API or dashboard

If you keep the default compose ports published on a host with broader network exposure, you should treat that as an unsupported deployment shape until you add the controls below.

## Exposed Deployments

HomelabSec now ships an optional edge-based basic-auth and TLS deployment path, but it still does not include application-level user management, SSO, or per-user authorization.

If you need access beyond a trusted LAN, put it behind a reverse proxy and add all of the following:

- TLS termination with a real certificate
- authentication in front of both the dashboard and the API
- IP allowlisting or VPN access if possible
- restricted exposure of Postgres so it is never reachable from the public internet

Practical deployment pattern:

- publish `frontend` and `brain` only to localhost or a private interface
- terminate TLS in Caddy, Nginx, Traefik, or another reverse proxy
- require SSO, basic auth, or forward-auth at the proxy layer
- avoid exposing `scheduler` or `postgres` at all

If the stack must remain LAN-only, the simplest safe option is to keep the current compose deployment and limit host-level firewall access to your admin subnet.

HomelabSec now includes an optional secure edge overlay for broader deployments.

Start it with:

```bash
./run_secure_edge.sh
```

For stronger auth instead of basic auth:

```bash
./run_secure_edge.sh --oidc
```

The launcher chooses ports in this order:

- `8081/8443`
- `18081/18443`
- the next free pair starting at `20081/20443`, after an interactive confirmation

If you prefer to choose ports yourself, you can still start the overlay directly:

```bash
cd compose
docker compose -f compose.yaml -f compose.exposed.yaml up -d --build
```

OIDC-authenticated edge:

```bash
cd compose
docker compose -f compose.yaml -f compose.exposed.yaml -f compose.oidc.yaml up -d --build
```

The secure overlay:

- removes direct host exposure of the dashboard container
- keeps `brain` bound to localhost on the host side
- publishes an authenticated TLS edge in front of both the dashboard and API
- supports either self-signed or operator-provided certificates

Relevant variables:

```bash
EDGE_AUTH_USERNAME=admin
EDGE_AUTH_PASSWORD=change-me-now
EDGE_AUTH_MODE=basic
EDGE_SERVER_NAME=localhost
EDGE_TLS_MODE=self_signed
EDGE_HTTP_PORT=8081
EDGE_HTTPS_PORT=8443
```

OIDC variables for the stronger-auth overlay:

```bash
EDGE_OIDC_PROVIDER=oidc
EDGE_OIDC_ISSUER_URL=https://your-idp.example.com/application/o/homelabsec/
EDGE_OIDC_CLIENT_ID=homelabsec
EDGE_OIDC_CLIENT_SECRET=replace-me
EDGE_OIDC_COOKIE_SECRET=replace-with-32-byte-base64-secret
EDGE_OIDC_REDIRECT_URL=https://localhost:8443/oauth2/callback
EDGE_OIDC_EMAIL_DOMAINS=*
EDGE_OIDC_SCOPE=openid email profile
EDGE_OIDC_WHITELIST_DOMAINS=
```

OIDC operator notes:

- `./run_secure_edge.sh --oidc` now validates the required OIDC variables before starting compose
- if `EDGE_OIDC_REDIRECT_URL` is unset, the launcher fills it automatically as `https://localhost:<chosen-https-port>/oauth2/callback`
- `EDGE_OIDC_ISSUER_URL` must use `https://` for real deployments, with `http://localhost` allowed only for local test IdPs
- `EDGE_OIDC_COOKIE_SECRET` must be set and at least 16 characters long

Reference provider setup pattern:

1. Create an OIDC client in your identity provider with redirect URI `https://localhost:8443/oauth2/callback`
2. Set `EDGE_OIDC_ISSUER_URL` to the provider issuer URL
3. Set `EDGE_OIDC_CLIENT_ID` and `EDGE_OIDC_CLIENT_SECRET` from that client
4. Set `EDGE_OIDC_COOKIE_SECRET` to a strong random secret
5. Start the edge with `./run_secure_edge.sh --oidc`

For local validation only, you can point the issuer at a localhost-hosted IdP and let the launcher fill the callback URL for the chosen HTTPS port.

TLS modes:

- `EDGE_TLS_MODE=self_signed` generates a self-signed certificate automatically on first start
- `EDGE_TLS_MODE=provided` expects certificate files at `edge/certs/tls.crt` and `edge/certs/tls.key`

The default secure overlay covers reverse proxying, basic auth, and TLS termination.

The OIDC overlay adds stronger proxy-layer auth with `oauth2-proxy`, while preserving the current app and API shape. It still does not provide in-app per-user roles or API token management.

## Ollama Configuration

Compose now accepts:

```bash
OLLAMA_URL=http://host.containers.internal:11434
OLLAMA_MODEL=homelabsec-classifier
OLLAMA_TIMEOUT_SECONDS=120
CLASSIFICATION_FALLBACK_ROLE=unknown
CLASSIFICATION_FALLBACK_CONFIDENCE=0.10
```

During install, HomelabSec validates host-side Ollama access through `OLLAMA_HOST_URL` and confirms the configured `OLLAMA_MODEL` exists via the Ollama tags API.

If Ollama is unreachable or returns an invalid transport response, the classification endpoints now fail with `502` instead of a generic `500`. If the model returns non-JSON content, the API keeps the existing soft-fallback behavior and stores an `unknown` classification with `raw_model_output` included in the response.

## Database Migrations

Migration files live in `brain/migrations/` and are applied in filename order.

To run migrations manually:

```bash
cd compose
docker compose run --rm migrate
```

The migration runner records applied versions in the `schema_migrations` table.

## Backups and Restore

The durable data for HomelabSec lives in Postgres. At minimum, back up:

- the Postgres database contents
- your `.env`
- any local model/runtime configuration needed to reach Ollama

Example logical backup:

```bash
docker compose -f compose/compose.yaml exec -T postgres \
  pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB" > homelabsec-$(date +%F).sql
```

Example restore into a fresh stack:

```bash
cat homelabsec-YYYY-MM-DD.sql | docker compose -f compose/compose.yaml exec -T postgres \
  psql -U "$POSTGRES_USER" "$POSTGRES_DB"
```

Operational notes:

- run restores only after the target schema is migrated to the expected version
- test restores periodically on a disposable instance instead of trusting backups blindly
- named Docker volumes are not a backup strategy by themselves

If you prefer volume-level backups instead of logical dumps, document and test that process separately for your host environment.

## Testing Plan

The test strategy is tracked in `TEST_PLAN.md`. It defines the unit, integration, regression, and pre-UAT checks needed to make changes safely as the product evolves.

## Running Unit Tests

The first automated test slice covers pure functions in `brain/app.py` and does not require a running database or Ollama instance.

Install the test dependency:

```bash
python3 -m pip install -r requirements-dev.txt
```

Run the unit tests:

```bash
python3 -m pytest
```

Run only the integration tests:

```bash
python3 -m pytest tests/integration
```

The integration suite starts an isolated Postgres test container on port `55432`, loads the schema from `brain/init.sql`, and runs the FastAPI app in-process. Ollama is mocked in the classification integration tests so the results stay deterministic.

Integration coverage also locks down:

- invalid and missing ingest XML paths
- missing-asset `404` behavior on classification and change detection
- `502` handling when Ollama is unreachable
- idempotent change persistence for the same fingerprint transition

Run the regression tests for the frontend-backed API contract:

```bash
python3 -m pytest tests/regression
```

Run the compose smoke test:

```bash
python3 -m pytest tests/smoke
```

The smoke suite starts the full compose stack with temporary remapped host ports chosen at runtime, waits for healthchecks to pass, verifies the API and frontend respond, and then tears the stack down.

## Scheduler Behavior

The scheduler now waits for API readiness at startup, retries API calls, logs per-job failures without crashing the loop, and supports optional immediate discovery with:

```bash
STARTUP_DISCOVERY=true
```

Startup discovery decision:

- default behavior remains `STARTUP_DISCOVERY=false`
- this avoids kicking off a network scan immediately on every container restart
- use `STARTUP_DISCOVERY=true` if you explicitly want boot-time discovery after maintenance windows or host reboots
- periodic discovery still starts on the configured interval either way

Additional scheduler tuning variables:

```bash
SCHEDULER_API_BASE=http://127.0.0.1:8088
SCHEDULER_METRICS_PORT=9100
API_RETRY_ATTEMPTS=5
API_RETRY_DELAY_SECONDS=5
STARTUP_API_TIMEOUT_SECONDS=120
```

## Scheduler Networking

`network_mode: "host"` is intentionally retained for the scheduler.

Current rationale:

- the scheduler runs `nmap -sS`, which relies on raw-socket scanning semantics tied closely to the network namespace it runs in
- the target is a LAN subnet, so scanning from the host namespace preserves the expected source address and routing behavior
- the scheduler currently reaches the API through host loopback via `SCHEDULER_API_BASE`, which defaults to `http://127.0.0.1:8088`

This means the scheduler is currently Linux-host oriented. If host networking is removed in the future, that change should be treated as a networking redesign, not a compose cleanup, because scan behavior and API reachability would both change.

Operational assumptions:

- `nmap -sS` requires raw-socket privileges inside the scheduler container
- the scheduler should run only on trusted local infrastructure
- host-network mode should be reviewed again only if the scan model changes, for example moving away from SYN scans or offloading discovery to the host

## Logs and Observability

Current observability is intentionally minimal. The stack relies on container logs plus compose healthchecks.

`brain`, `scheduler`, and `migrate` now emit structured JSON log lines to stdout so compose logs are easier to filter and ship elsewhere.

`brain` and `scheduler` now expose Prometheus-style metrics:

- `brain`: `http://brain:8088/metrics` from the compose network, or `http://127.0.0.1:8088/metrics` on the host
- `scheduler`: `http://host.containers.internal:9100/metrics` from other containers, or `http://127.0.0.1:9100/metrics` on the host

Start the monitoring overlay with:

```bash
cd compose
docker compose -f compose.yaml -f compose.monitoring.yaml up -d --build
```

This adds:

- Prometheus on `127.0.0.1:9090`
- Alertmanager on `127.0.0.1:9093`
- Grafana on `127.0.0.1:3001`

The monitoring overlay now also includes:

- a provisioned `HomelabSec Overview` Grafana dashboard
- Alertmanager for routed notifications
- Prometheus alert rules for brain target availability
- Prometheus alert rules for scheduler target availability
- Prometheus alert rules for elevated brain 5xx rate and sustained high average latency
- Prometheus alert rules for scheduler job failures and stale discovery runs
- a `HomelabSecWatchdog` alert that always fires so alert routing can be tested safely

Relevant variables:

```bash
PROMETHEUS_HOST_PORT=9090
ALERTMANAGER_HOST_PORT=9093
ALERTMANAGER_DEFAULT_RECEIVER=null
ALERTMANAGER_WEBHOOK_URL=
ALERTMANAGER_EMAIL_TO=
ALERTMANAGER_EMAIL_FROM=
ALERTMANAGER_SMARTHOST=
ALERTMANAGER_SMTP_AUTH_USERNAME=
ALERTMANAGER_SMTP_AUTH_PASSWORD=
ALERTMANAGER_SMTP_REQUIRE_TLS=true
GRAFANA_HOST_PORT=3001
GRAFANA_ADMIN_USER=admin
GRAFANA_ADMIN_PASSWORD=change-me-now
SCHEDULER_METRICS_PORT=9100
LOG_LEVEL=INFO
```

Grafana is provisioned with a default Prometheus datasource and the `HomelabSec Overview` dashboard.

Alert routing now runs through Alertmanager. The monitoring overlay supports three receiver modes:

- `ALERTMANAGER_DEFAULT_RECEIVER=null`
- `ALERTMANAGER_DEFAULT_RECEIVER=webhook`
- `ALERTMANAGER_DEFAULT_RECEIVER=email`

Webhook example:

```bash
ALERTMANAGER_DEFAULT_RECEIVER=webhook
ALERTMANAGER_WEBHOOK_URL=https://example.internal/alerts
```

Email example:

```bash
ALERTMANAGER_DEFAULT_RECEIVER=email
ALERTMANAGER_EMAIL_TO=ops@example.com
ALERTMANAGER_EMAIL_FROM=homelabsec@example.com
ALERTMANAGER_SMARTHOST=smtp.example.com:587
ALERTMANAGER_SMTP_AUTH_USERNAME=homelabsec@example.com
ALERTMANAGER_SMTP_AUTH_PASSWORD=replace-me
ALERTMANAGER_SMTP_REQUIRE_TLS=true
```

The default `null` receiver keeps the overlay safe to start even before notification settings are configured. The `HomelabSecWatchdog` alert exists so routing can be validated once a real receiver is configured.

Useful operational commands:

```bash
docker compose -f compose/compose.yaml ps
docker compose -f compose/compose.yaml logs -f brain
docker compose -f compose/compose.yaml logs -f scheduler
docker compose -f compose/compose.yaml logs -f frontend
docker compose -f compose/compose.yaml logs -f postgres
```

What to watch:

- `brain` for request failures, migration issues, and Ollama-related errors
- `scheduler` for discovery failures, API retry loops, and scan timing
- `postgres` for startup or readiness failures
- compose health status for service-level regressions

Recommended next-step observability if the project grows:

- centralized log retention outside Docker’s default local buffers
- dashboards and alerting on the exposed metrics
- alerting on repeated scheduler failures or unhealthy services

## API usage

The API is exposed by the `brain` service on port `8088`.

Classify a single asset:

```bash
curl -X POST http://localhost:8088/classify/<asset_id>
```

Example response:

```json
{
  "asset_id": "7d0d0a6f-4f7a-4a30-8b56-0f3b0aa9d9ab",
  "classification": {
    "role": "nas",
    "confidence": 0.97
  },
  "fingerprint": {},
  "fingerprint_store": {
    "changed": false
  },
  "raw_model_output": null
}
```

Classify all known assets:

```bash
curl -X POST http://localhost:8088/classify_all
```

Example response:

```json
{
  "total_assets": 12,
  "classified_ok": 12,
  "errors": 0,
  "failed": []
}
```
