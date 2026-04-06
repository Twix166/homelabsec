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
SCHEDULER_API_BASE=http://127.0.0.1:8088
```

`compose/compose.yaml` now reads Postgres credentials from env variables instead of embedding them directly in the file.

## Quick install

You can install directly from GitHub with:

```bash
curl -fsSL https://raw.githubusercontent.com/Twix166/homelabsec/main/install.sh | bash
```

The installer now:

- clones or updates the repository
- syncs `.env` into `compose/.env`
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

The installer copies `.env` into `compose/.env` so compose reads the same credentials and runtime settings.

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

Then open:

```text
http://localhost:8080
```

The frontend proxies API requests internally to the `brain` service, so no backend changes are required.

The summary cards on the dashboard are clickable. Selecting `Total assets`, `Observations`, `Fingerprints`, or `24h changes` opens a detail list for that category in the dashboard.

The compose stack now includes healthchecks for `postgres`, `brain`, `scheduler`, and `frontend`. `brain` waits for Postgres readiness, and the dependent services wait for the API health endpoint before starting.

The `brain` service is now built from `brain/Dockerfile` with pinned Python dependencies in `brain/requirements.txt` instead of installing packages dynamically at container startup.

## Ollama Configuration

Compose now accepts:

```bash
OLLAMA_URL=http://host.containers.internal:11434
OLLAMA_MODEL=homelabsec-classifier
```

During install, HomelabSec validates host-side Ollama access through `OLLAMA_HOST_URL` and confirms the configured `OLLAMA_MODEL` exists via the Ollama tags API.

## Database Migrations

Migration files live in `brain/migrations/` and are applied in filename order.

To run migrations manually:

```bash
cd compose
docker compose run --rm migrate
```

The migration runner records applied versions in the `schema_migrations` table.

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

Run the regression tests for the frontend-backed API contract:

```bash
python3 -m pytest tests/regression
```

Run the compose smoke test:

```bash
python3 -m pytest tests/smoke
```

The smoke suite starts the full compose stack with remapped ports on `18080`, `18088`, and `15432`, waits for healthchecks to pass, verifies the API and frontend respond, and then tears the stack down.

## Scheduler Behavior

The scheduler now waits for API readiness at startup, retries API calls, logs per-job failures without crashing the loop, and supports optional immediate discovery with:

```bash
STARTUP_DISCOVERY=true
```

Additional scheduler tuning variables:

```bash
SCHEDULER_API_BASE=http://127.0.0.1:8088
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
