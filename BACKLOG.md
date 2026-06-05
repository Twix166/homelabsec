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
Status: `done`

Goal:
- Protect the dashboard as a user-facing surface rather than only protecting backend endpoints.

Delivered:
- Added regression checks for clickable summary cards and detail surfaces
- Locked down `/observations`, `/fingerprints`, and `/admin/status` contracts
- Added static frontend contract checks for the dashboard summary wiring

Follow-on:
- add browser-driven frontend rendering tests if the project adopts a JS test runner

### Slice 6: Backend Entry Point Cleanup
Priority: `P2`
Status: `done`

Goal:
- Finish the modularization pass so `brain/app.py` becomes a thin composition layer.

Delivered:
- Extracted inventory queries and fingerprint detail logic into `brainlib/inventory.py`
- Extracted system helpers into `brainlib/system.py`
- Added `brainlib/admin.py` for operator-facing status data
- Kept `app.py` focused on middleware, route wiring, and DB context boundaries

### Slice 7: Config Validation Layer
Priority: `P2`
Status: `done`

Goal:
- Make startup failures more predictable and easier to diagnose.

Delivered:
- Added validated `BrainConfig` loading for `brain` and `migrate`
- Added validated scheduler config loading in `scheduler/config.py`
- Added unit coverage for invalid configuration paths
- Added `ADMIN_STALE_SCAN_MINUTES` as a shared operator-facing runtime knob

### Slice 8: DB Migration Discipline
Priority: `P2`
Status: `done`

Goal:
- Reduce schema drift risk as the project evolves.

Delivered:
- Added `0000_schema_migrations.sql` so the bootstrap path is fully migration-backed
- Added `brain/render_init_sql.py` to render and check `init.sql` from versioned migrations
- Added automated drift detection for bootstrap schema sync

### Slice 9: Backup And Restore Drill
Priority: `P2`
Status: `done`

Goal:
- Turn backup guidance into a verified operational capability.

Delivered:
- Added `scripts/backup_db.sh`
- Added `scripts/restore_db.sh`
- Added integration coverage that backs up and restores a disposable Postgres stack

### Slice 10: Admin UX Improvements
Priority: `P3`
Status: `done`

Goal:
- Make the product easier to operate during UAT and early deployments.

Delivered:
- Added `/admin/status`
- Added a dashboard admin status panel with scheduler freshness and quick links
- Added `scripts/show_access_urls.sh` for operator-friendly endpoint discovery

Next priority:
- browser-level UI testing
- richer alert delivery validation
- backup retention policy and off-host storage

### Slice 11: Exposure Map Dashboard
Priority: `P0`
Status: `proposed`

Goal:
- Turn HomelabSec into an operator-facing exposure map by correlating Nmap observations with HCM targets/certificates, NPM routes, Heimdall launcher links, and DNS answers.

Reference:
- `docs/threat-exposure-map-and-dashboard-spec.md`

Deliver:
- add route, DNS, launcher-link, and exposure-finding data models
- add read-only exposure summary/routes/DNS/launcher/findings APIs
- add secret-safe HCM and NPM collectors
- add Heimdall hygiene checks for raw-IP or legacy links where a preferred HTTPS route exists
- add DNS alignment checks that distinguish candidate records from production failures
- add dashboard cards/tables for control-plane risk, raw service exposure, TLS status, unknown services, and accepted findings

Verification:
- unit tests for route classifiers and finding severity rules
- fixture-based integration test joining Nmap, HCM, NPM, Heimdall, and DNS payloads
- dashboard contract tests for the new exposure endpoints

### Slice 12: Sandfly Security Finding Integration
Priority: `P2`
Status: `parked`

Goal:
- Add Sandfly support as a future enrichment/source-of-findings integration for HomelabSec, after the core exposure map work is stable.

Context:
- Public Sandfly tooling and docs appear sufficient to build the integration if a licensed Sandfly server is available.
- Expected integration points include API authentication, Sandfly-managed host inventory, check listing, scan launch, ad-hoc IP range or SSH credential scans, result retrieval, and mapping Sandfly alerts/findings into HomelabSec findings/remediation surfaces.
- This is deliberately not a current implementation item.

Deliver later:
- document required Sandfly server/API configuration and secret handling
- add a read-only Sandfly collector for hosts, checks, scans, and findings
- map Sandfly severity/status/remediation into HomelabSec exposure findings without breaking existing finding shapes
- add opt-in scan launch controls with safe defaults and clear operator confirmation
- add fixture-backed tests using sanitized Sandfly API payloads

Verification later:
- unit tests for Sandfly payload parsing and severity/status mapping
- integration tests with mocked Sandfly API responses
- dashboard contract tests for Sandfly-origin findings

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
11. Slice 11: Exposure Map Dashboard
12. Slice 12: Sandfly Security Finding Integration, only after a Sandfly server/API path is selected

## Parking Lot

These are valid ideas, but not current execution priorities:

- in-app user management
- API token issuance and revocation
- SSO role mapping into application behavior
- multi-node deployment support
- replacing host-network scheduler design
- major frontend redesign
- Sandfly support until the core exposure map is stable and Robert decides to connect a licensed Sandfly server
