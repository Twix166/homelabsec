# TODO

This file tracks the highest-value follow-up work for making HomelabSec more reliable in production without breaking existing endpoints or Docker Compose behavior.

## Priority 0: Keep Current System Stable

- Preserve existing API endpoints and response shapes while refactoring.
- Keep `compose/compose.yaml` working as the default local deployment path.
- Prefer small incremental patches with verification after each change.

## Priority 1: Deployment and Bootstrap Gaps

Status:
- Postgres init is now wired into compose for fresh volumes.
- Service healthchecks are in place.
- `brain` now builds from a Dockerfile with pinned dependencies.
- Versioned SQL migrations now run through the `migrate` service and `schema_migrations` table.

- Use the migration framework for future schema changes instead of editing only `init.sql`.

## Priority 2: Installer Reliability

Status:
- Installer repo URL mismatch is fixed.
- Installer now validates API health and schema readiness.
- Installer now validates Ollama connectivity and configured model availability.
- Installer now treats repo-root `.env` as the source of truth and explicitly runs compose with that env file.
- Installer guarantees and remaining manual setup are now documented.

- Add deeper validation only if the installer later takes on more host-level responsibilities than compose startup and API readiness.

## Priority 3: Scheduler Hardening

Status:
- Scheduler now waits for API readiness, retries API calls, and logs job failures without crashing the loop.
- `network_mode: "host"` has been reviewed and is intentionally retained for LAN `nmap -sS` semantics and host-loopback API access.
- Scan privilege and host-network assumptions are now documented.
- Startup discovery is now an explicit documented opt-in; default startup remains non-scanning unless `STARTUP_DISCOVERY=true`.
- Scheduler logging is now structured for easier compose-log consumption.
- Scheduler now exposes Prometheus-style metrics on a dedicated metrics port.

## Priority 4: Backend Maintainability

Status:
- `app.py` remains the stable FastAPI entrypoint, and core helper logic has been extracted into internal modules under `brain/brainlib`.
- Database lookup and common API error paths are now more centralized.
- Ingest input validation and external dependency failures now return explicit API errors instead of generic server failures.
- Change persistence now dedupes per fingerprint transition, so repeated detection runs stay idempotent while recurring changes can still be recorded after a later state change.
- Runtime tuning and fallback values are now routed through `brain/brainlib/config.py`.
- Reporting queries and serializers are now extracted from `app.py` into a dedicated internal module.
- Classification route logic is now extracted from `app.py` into a dedicated internal module.
- Ingest parsing and persistence logic is now extracted from `app.py` into a dedicated internal module.
- Change-detection route orchestration is now extracted from `app.py` into a dedicated internal module.

- Split the monolithic FastAPI app into smaller modules without changing endpoint behavior.
- Continue splitting the monolithic FastAPI app into smaller modules without changing endpoint behavior.

## Priority 5: Security and Operations

Status:
- Postgres secrets are now env-driven instead of being embedded directly in compose service definitions.
- The supported trust model is now documented as trusted-LAN/local-admin use by default.
- TLS/auth guidance for exposed deployments is now documented.
- Postgres backup and restore guidance is now documented.
- Basic log and observability guidance is now documented.
- `brain`, `scheduler`, and `migrate` now emit structured JSON logs to stdout.
- An optional auth/TLS edge overlay now exists for broader deployment scenarios.
- An optional monitoring overlay now exists for Prometheus and Grafana.
- `brain` now exposes Prometheus-style API metrics.
- The monitoring overlay now includes a provisioned Grafana dashboard and Prometheus alert rules for core API and scheduler health.

- An optional OIDC-based stronger-auth overlay now exists for exposed deployments.
- Add notification routing, such as Alertmanager, if alerts need to reach operators automatically.

## Priority 6: Testing and Verification

Status:
- Unit, integration, regression, and compose smoke coverage are now in place.
- CI now runs the test suite on push and pull request.

- Add API smoke tests for health, ingest, classification, change detection, and daily report flows.
- Add compose-level verification steps that confirm the stack boots cleanly.
- Add regression coverage for the dashboard endpoints used by the frontend.
- Add a lightweight CI path for linting and smoke tests.

## Suggested Execution Order

1. Wire database initialization and service healthchecks.
2. Replace the `brain` runtime install with a built image and pinned dependencies.
3. Harden the install script so failures are explicit.
4. Harden the scheduler around readiness, retries, and logging.
5. Add smoke tests to protect the current endpoints before larger refactors.
6. Refactor the backend incrementally once deployment is stable.
