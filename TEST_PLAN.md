# Test Plan

This document defines the testing approach for HomelabSec so changes can land with a lower risk of breaking existing endpoints, Docker Compose behavior, or the dashboard before user acceptance testing.

## Goals

- Protect the existing API contract for ingest, classification, change detection, and reporting.
- Verify Docker Compose startup and service readiness.
- Catch regressions in the dashboard-backed endpoints.
- Establish enough automated coverage to reduce manual retesting before UAT.

## Test Layers

### 1. Unit Tests

Scope:

- XML parsing in `brain/app.py`
- Role normalization in `brain/app.py`
- Fingerprint hashing and change diff logic in `brain/app.py`
- Small scheduler helper functions that do not require network or `nmap`

Initial targets:

- `parse_nmap_xml()` with representative Nmap XML fixtures
- `normalize_role()` for supported aliases and fallback behavior
- `fingerprint_hash()` to confirm volatile fields do not cause false changes
- `diff_fingerprints()` for new asset, IP change, MAC change, port open, port close, and role change cases

Recommended tooling:

- `pytest`

### 2. Integration Tests

Scope:

- FastAPI endpoints against a real Postgres instance
- Schema bootstrap verification
- Ingest to fingerprint to classify to detect-changes flow
- Report endpoints used by the dashboard

Initial targets:

- `/health`
- `/ingest/nmap_xml`
- `/assets`
- `/fingerprint/{asset_id}`
- `/classify/{asset_id}`
- `/classify_all`
- `/detect_changes`
- `/report/daily`
- `/report/summary`

Recommended approach:

- Bring up Postgres and the API in Docker Compose for integration runs
- Use fixed XML fixtures from `discovery/raw` or dedicated test fixtures
- Mock Ollama responses where classification determinism is required

### 3. Regression Tests

Scope:

- Endpoint response shape stability for the frontend
- Daily report fields consumed by the dashboard
- Compose startup ordering and healthchecks

Initial targets:

- `/api/health`
- `/api/report/summary`
- `/api/report/daily`
- `/api/assets`

Recommended approach:

- Add response-shape assertions for dashboard fields
- Add smoke verification that `docker compose up -d --build` reaches healthy state
- Preserve existing response keys unless a documented versioned change is intentional

### 4. Pre-UAT Verification

Scope:

- End-to-end sanity checks before the user performs acceptance testing

Required checks:

1. Start the stack with Docker Compose from `compose/`.
2. Confirm all services report healthy.
3. Verify `/health` responds successfully.
4. Run ingest using a known XML fixture.
5. Confirm assets appear in `/assets`.
6. Run classification flow with a deterministic or mocked Ollama response.
7. Run `/detect_changes` and verify expected persistence behavior.
8. Verify `/report/daily` and `/report/summary` return valid payloads.
9. Load the frontend on port `8080` and confirm dashboard data renders.

## Fixtures and Test Data

- Add a dedicated `tests/fixtures/` directory for stable XML samples.
- Keep at least one fixture for a new asset and one for a changed asset.
- Avoid relying on live network scans in automated tests.
- Avoid relying on a live Ollama instance for default CI coverage.

## Execution Order

1. Add unit tests for pure functions first.
2. Add integration tests for core API flows with Postgres.
3. Add regression coverage for dashboard endpoints.
4. Add a compose smoke test for healthy startup.
5. Use the pre-UAT checklist before manual acceptance testing.

## Definition of Done for Test Readiness

- Core pure functions have unit coverage.
- The main endpoint flow has integration coverage.
- Dashboard-backed endpoints have regression checks.
- Compose startup can be validated with a repeatable smoke test.
- A documented pre-UAT checklist exists and is run before handoff.

## Immediate Next Steps

- Add `pytest`-based unit tests around parsing, fingerprinting, and diffing.
- Introduce a small integration harness for API plus Postgres.
- Add a simple smoke script or documented command sequence for compose health verification.
