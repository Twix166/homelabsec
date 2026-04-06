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

## Quick install

You can install directly from GitHub with:

```bash
curl -fsSL https://raw.githubusercontent.com/Twix166/homelabsec/main/install.sh | bash
```

The installer now:

- clones or updates the repository
- syncs `.env` into `compose/.env`
- starts the stack with `--build`
- waits for `/health`
- validates schema readiness through `/report/summary`

If install exits successfully, the API has answered both a basic health check and a schema-dependent query.

## Web dashboard

A read-only web dashboard is available from the `frontend` service on port `8080`.

Start the stack from `compose/compose.yaml`:

```bash
cd compose
docker compose up -d --build
```

On a fresh Postgres volume, the database schema is initialized automatically from `brain/init.sql`.

If you already have an existing `pgdata` volume from an older run, the init script will not be re-applied automatically. In that case, either load `brain/init.sql` manually into the existing database or recreate the volume if you do not need to preserve data.

Then open:

```text
http://localhost:8080
```

The frontend proxies API requests internally to the `brain` service, so no backend changes are required.

The compose stack now includes healthchecks for `postgres`, `brain`, `scheduler`, and `frontend`. `brain` waits for Postgres readiness, and the dependent services wait for the API health endpoint before starting.

The `brain` service is now built from `brain/Dockerfile` with pinned Python dependencies in `brain/requirements.txt` instead of installing packages dynamically at container startup.

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
API_RETRY_ATTEMPTS=5
API_RETRY_DELAY_SECONDS=5
STARTUP_API_TIMEOUT_SECONDS=120
```

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
