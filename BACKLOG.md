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

### Operational P0: Secret Management Programme
Priority: `P0`
Status: `in progress`

Goal:
- Bring API keys, SSH keys, tokens, certificates, recovery material, and service credentials under deliberate management before broad backup implementation.

Reference:
- `docs/operations/homelab-secret-management-strategy.md`
- `docs/operations/vaultwarden-openbao-secret-management.md`
- `docs/operations/vaultwarden-openbao-bootstrap-runbook.md`
- `docs/operations/secret-inventory-template.md`
- `secrets/README.md`

Delivered so far:
- started the migration away from Git-hosted SOPS payloads
- removed tracked SOPS config/encrypted payloads from the repo
- added a zero-secret Git validator and expanded ignore rules for Vaultwarden/OpenBao data, exports, snapshots, tokens, and runtime files
- added a Vaultwarden + OpenBao plan, bootstrap runbook, example compose stack, OpenBao config scaffold, and metadata-only inventory examples

Deliver:
- use Vaultwarden as the primary human/recovery vault
- use OpenBao as the automation/service vault
- enforce that GitHub contains no secrets, encrypted or otherwise
- inventory high-value secrets by metadata only: owner, consumer, storage, rotation, recovery test, blast radius, and revocation path
- migrate known high-value secrets out of ad-hoc `.env` files and loose key locations into Vaultwarden/OpenBao or documented local materialization steps
- create and test encrypted backups for Vaultwarden, OpenBao snapshots/recovery material, backup repository passwords, and break-glass runbook
- rotate old, broad, unclear-provenance, or previously Git-encrypted credentials in staged batches
- add HomelabSec posture checks later without collecting raw secret values

Safety rules:
- never put plaintext or encrypted private keys, tokens, passwords, seeds, macaroons, backup repository passwords, rendered `.env` files, vault exports, OpenBao snapshots, unseal/recovery keys, or vault tokens in GitHub, backlog files, dashboards, alerts, logs, or Telegram
- report inventory coverage, freshness, rotation due dates, and recovery-test status only

Next action:
- deploy the Vaultwarden/OpenBao foundations on the approved homelab workload host, then initialize/administer them with Robert present for bootstrap secrets.

### Operational P0: Self-Hosted Git Migration Programme
Priority: `P0`
Status: `planned`

Goal:
- Move selected repositories from GitHub-only hosting to a self-hosted Git service without losing mirrors, backups, recovery options, or public-discovery benefits where they matter.

Reference:
- `docs/operations/self-hosted-git-migration-strategy.md`

Deliver:
- choose the self-hosted Git platform, with Forgejo as the current recommended pilot
- deploy the platform behind the homelab HTTPS/DNS/certificate chain with SSH Git access
- implement backup and restore drills before moving operational repositories
- migrate low-risk pilot repositories first, then active personal repositories, then operational/private repositories
- keep GitHub mirrors or fallback remotes until restore and rollback are proven
- defer high-impact autonomous/financial repositories until explicit go/no-go after lower-risk migration success

Safety rules:
- do not delete or archive GitHub repositories during the pilot phase
- do not print or commit GitHub/Forgejo tokens, deploy keys, webhook secrets, Actions secrets, or private SSH keys
- do not make self-hosted Git the only copy of an important repository until backup and restore are verified

Next action:
- confirm Forgejo as the pilot platform or choose an alternative, then write/deploy the first LAN-only Forgejo runbook and test it with a Tier 0 repository.

### Operational P0: Thunderbluff 3-2-1 Backup Programme
Priority: `P0`
Status: `planned`

Goal:
- Make Thunderbluff the primary encrypted backup landing zone, then complete a 3-2-1 posture with an independent/offsite or offline third copy.

Reference:
- `docs/operations/homelab-backup-strategy.md`

Deliver:
- confirm Thunderbluff backup share/path, access, capacity, snapshot/immutability support, and restricted backup users/keys
- inventory all important homelab apps and classify by RPO/RTO/data criticality
- implement the first three monitored jobs: Faye/Hermes runtime, HomelabSec Postgres/manifests, and proxy/DNS/certificate control-plane state
- extend to Home Assistant, Trading Team, WordPress, media/document apps, monitoring, Proxmox guests, and Lightning/Umbrel critical state
- replicate encrypted backups to a separate/offsite/offline third copy and run quarterly restore drills

Safety rules:
- do not start implementation until Robert explicitly asks; this is currently a planning/backlog item
- application-aware database dumps before raw volume copies
- report presence, age, size, snapshot IDs, and restore-test status only; never expose backup contents or secrets

Next action:
- secret-management choice is made; next backup step, only after Robert explicitly asks to start backup implementation, is to obtain/verify Thunderbluff access and implement the first three jobs.

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
Status: `in progress`

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

Delivered so far:
- Added migration-backed exposure tables for routes, DNS records, launcher links, and exposure findings.
- Added authenticated read-only API skeletons for `/exposure/summary`, `/exposure/routes`, `/exposure/dns`, `/exposure/launcher-links`, and `/exposure/findings`.
- Added a dashboard exposure-map panel and frontend/API contract tests.

Remaining:
- Add unit tests for route classifiers and finding severity rules once collectors/classifiers are introduced.
- Add fixture-based integration tests joining Nmap, HCM, NPM, Heimdall, and DNS payloads.
- Add secret-safe HCM, NPM, Heimdall, and DNS collectors.
- Add dashboard tables/cards for correlated control-plane risk, raw service exposure, TLS status, unknown services, and accepted findings.

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
11. Operational P0: Secret Management Programme
12. Operational P0: Thunderbluff 3-2-1 Backup Programme
13. Slice 11: Exposure Map Dashboard
14. Slice 12: Sandfly Security Finding Integration, only after a Sandfly server/API path is selected

## Parking Lot

These are valid ideas, but not current execution priorities:

- in-app user management
- API token issuance and revocation
- SSO role mapping into application behavior
- multi-node deployment support
- replacing host-network scheduler design
- major frontend redesign
- Sandfly support until the core exposure map is stable and Robert decides to connect a licensed Sandfly server
