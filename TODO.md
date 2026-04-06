# TODO

This file tracks the highest-value follow-up work for making HomelabSec more reliable in production without breaking existing endpoints or Docker Compose behavior.

## Priority 0: Keep Current System Stable

- Preserve existing API endpoints and response shapes while refactoring.
- Keep `compose/compose.yaml` working as the default local deployment path.
- Prefer small incremental patches with verification after each change.

## Priority 1: Deployment and Bootstrap Gaps

- Wire Postgres schema initialization into Docker Compose.
- Add a safe database bootstrap path for `brain/init.sql`.
- Decide on a migration strategy for future schema changes.
- Replace the runtime `pip install` in the `brain` service with a proper Docker image build.
- Pin backend dependencies instead of installing floating latest versions at container start.
- Add service healthchecks for `postgres`, `brain`, `scheduler`, and `frontend`.
- Improve startup ordering so the scheduler does not run before the API is reachable.

## Priority 2: Installer Reliability

- Fix the repository URL mismatch between `README.md` and `install.sh`.
- Make install validation fail clearly when the stack is unhealthy.
- Verify schema readiness as part of install.
- Verify Ollama connectivity and model availability during install or first-run checks.
- Make `.env` and `compose/.env` handling less error-prone.
- Document what the installer guarantees and what still requires manual setup.

## Priority 3: Scheduler Hardening

- Add readiness checks and retries around API calls in the scheduler.
- Decide whether startup should trigger an immediate discovery run.
- Handle `nmap` failures without silently stalling the schedule loop.
- Revisit `network_mode: "host"` and confirm it is required.
- Document scan privilege and host-network assumptions for `nmap -sS`.
- Add clearer scheduler logs for discovery, ingest, classification, and report outcomes.

## Priority 4: Backend Maintainability

- Split the monolithic FastAPI app into smaller modules without changing endpoint behavior.
- Centralize database connection handling and error paths.
- Add validation around ingest inputs and external dependency failures.
- Review classification and change-detection code for idempotency and duplicate persistence edge cases.
- Add a consistent configuration layer for environment variables.

## Priority 5: Security and Operations

- Remove hardcoded secrets from compose defaults.
- Define the supported trust model for LAN-only versus exposed deployments.
- Add guidance for TLS and authentication if the product is accessed beyond a trusted local network.
- Add Postgres backup and restore instructions.
- Add log collection and basic observability guidance.

## Priority 6: Testing and Verification

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
