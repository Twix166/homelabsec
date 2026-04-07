# Backlog

This file is the active development backlog for HomelabSec.

Use it as the working queue. `TODO.md` remains the broader status and historical follow-up list, while this file should contain the next concrete slices of work we can ship safely.

## How To Use This Backlog

- Work from top to bottom unless a production issue forces reprioritization.
- Keep slices small enough to implement, verify, and deploy in one iteration.
- Do not break existing endpoints, response shapes, or default compose behavior.
- After each slice:
  - run the relevant tests
  - bring the app up for UAT
  - update this file to reflect progress

## Priority Model

- `P0`: production safety or operational blind spots
- `P1`: important product hardening and admin usability
- `P2`: maintainability and scale-up improvements
- `P3`: nice-to-have improvements after the core platform is stable

## Current Prioritized Queue

### Slice 1: Alert Routing
Priority: `P0`
Status: `done`

Goal:
- Make Prometheus alerts reach an operator instead of existing only inside Prometheus.

Delivered:
- Alertmanager is now part of the monitoring overlay
- Prometheus now forwards alerts to Alertmanager
- Notification settings are env-driven
- Webhook and SMTP email routing are documented
- A watchdog alert is present for routing validation

Follow-on:
- add automated validation against a disposable webhook receiver

### Slice 2: Monitoring Smoke Verification
Priority: `P0`
Status: `done`

Goal:
- Protect the monitoring and secure-edge overlays with repeatable verification.

Delivered:
- Added smoke checks for Prometheus availability
- Added smoke checks for Grafana availability
- Added smoke checks that the provisioned dashboard exists
- Added smoke checks that the secure edge still starts with the monitoring overlay present
- Isolated smoke compose overlays so they no longer collide with the real stack

Follow-on:
- add smoke assertions for Alertmanager receiver behavior using a disposable webhook target

### Slice 3: OIDC Overlay Validation
Priority: `P1`
Status: `done`

Goal:
- Reduce risk in the new stronger-auth path.

Delivered:
- Added launcher-side validation for required OIDC variables
- Added targeted compose validation coverage for the OIDC overlay
- Added a concrete reference setup section in the README
- Kept the basic-auth path unchanged

Follow-on:
- add an isolated smoke path for oauth2-proxy once a disposable test IdP is available

### Slice 4: API Smoke Coverage
Priority: `P1`
Status: `done`

Goal:
- Close the remaining gap between current tests and true end-to-end runtime checks.

Delivered:
- Added workflow smoke coverage for:
  - `/health`
  - ingest path
  - classification path
  - change detection path
  - daily report path
  - summary report path
- Added a deterministic fake-Ollama smoke overlay
- Kept the smoke path isolated from the real stack

Follow-on:
- expand smoke assertions to include frontend-driven workflow rendering, not only API responses

### Slice 5: Dashboard Contract Expansion
Priority: `P1`

Goal:
- Protect the dashboard as a user-facing surface rather than only protecting backend endpoints.

Scope:
- Add regression checks for:
  - clickable summary cards
  - summary detail list rendering
  - dashboard loading against expected API payloads
- Lock down the new list endpoints used by the frontend

Acceptance criteria:
- Frontend-facing regressions are caught before UAT
- Summary-card behavior is covered by automated regression checks

### Slice 6: Backend Entry Point Cleanup
Priority: `P2`

Goal:
- Finish the modularization pass so `brain/app.py` becomes a thin composition layer.

Scope:
- Remove any remaining business logic still embedded in `app.py`
- Standardize route wiring, dependencies, and error translation
- Keep route contracts unchanged

Acceptance criteria:
- `app.py` is primarily route registration and app setup
- Core workflow logic lives in focused internal modules
- Existing endpoint behavior stays unchanged

### Slice 7: Config Validation Layer
Priority: `P2`

Goal:
- Make startup failures more predictable and easier to diagnose.

Scope:
- Validate required env vars centrally
- Validate incompatible configuration combinations early
- Standardize defaults and config error messages

Acceptance criteria:
- Invalid runtime configuration fails fast with clear messages
- Shared configuration logic is used consistently by `brain`, `scheduler`, `migrate`, and helper scripts where practical

### Slice 8: DB Migration Discipline
Priority: `P2`

Goal:
- Reduce schema drift risk as the project evolves.

Scope:
- Add a documented migration authoring workflow
- Add verification that fresh bootstrap and migration-applied schemas stay aligned
- Add a test or validation path that fails if migration state is incomplete

Acceptance criteria:
- New schema changes have one obvious path
- Drift between `init.sql` and migrations becomes detectable

### Slice 9: Backup And Restore Drill
Priority: `P2`

Goal:
- Turn backup guidance into a verified operational capability.

Scope:
- Add a scripted backup flow
- Add a scripted restore flow against a disposable stack
- Document the validation procedure

Acceptance criteria:
- Backup and restore can be tested end to end
- Restore instructions are verified, not only described

### Slice 10: Admin UX Improvements
Priority: `P3`

Goal:
- Make the product easier to operate during UAT and early deployments.

Scope:
- Add a lightweight admin status view for service health and scheduler freshness
- Surface monitoring and edge URLs more clearly in docs or helper scripts
- Add small deployment helper scripts where they reduce operator error

Acceptance criteria:
- Common operator tasks require less manual compose and log inspection
- No existing endpoints are broken

## Suggested Execution Order

1. Slice 1: Alert Routing
2. Slice 2: Monitoring Smoke Verification
3. Slice 3: OIDC Overlay Validation
4. Slice 4: API Smoke Coverage
5. Slice 5: Dashboard Contract Expansion
6. Slice 6: Backend Entry Point Cleanup
7. Slice 7: Config Validation Layer
8. Slice 8: DB Migration Discipline
9. Slice 9: Backup And Restore Drill
10. Slice 10: Admin UX Improvements

## Parking Lot

These are valid ideas, but not current execution priorities:

- in-app user management
- API token issuance and revocation
- SSO role mapping into application behavior
- multi-node deployment support
- replacing host-network scheduler design
- major frontend redesign
