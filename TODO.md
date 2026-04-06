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

- Make `.env` and `compose/.env` handling less error-prone.
- Document what the installer guarantees and what still requires manual setup.

## Priority 3: Scheduler Hardening

Status:
- Scheduler now waits for API readiness, retries API calls, and logs job failures without crashing the loop.
- `network_mode: "host"` has been reviewed and is intentionally retained for LAN `nmap -sS` semantics and host-loopback API access.
- Scan privilege and host-network assumptions are now documented.

- Decide whether startup should trigger an immediate discovery run.

## Priority 4: Backend Maintainability

Status:
- `app.py` remains the stable FastAPI entrypoint, and core helper logic has been extracted into internal modules under `brain/brainlib`.

- Split the monolithic FastAPI app into smaller modules without changing endpoint behavior.
- Centralize database connection handling and error paths.
- Add validation around ingest inputs and external dependency failures.
- Review classification and change-detection code for idempotency and duplicate persistence edge cases.
- Add a consistent configuration layer for environment variables.

## Priority 5: Security and Operations

Status:
- Postgres secrets are now env-driven instead of being embedded directly in compose service definitions.

- Define the supported trust model for LAN-only versus exposed deployments.
- Add guidance for TLS and authentication if the product is accessed beyond a trusted local network.
- Add Postgres backup and restore instructions.
- Add log collection and basic observability guidance.

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
