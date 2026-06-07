# Homelab Backup Strategy

Purpose: make Thunderbluff the primary homelab backup landing zone, then extend to a practical 3-2-1 backup posture for all important homelab applications.

Captured: 2026-06-07

## Target posture: 3-2-1

3-2-1 means:

1. **3 copies of important data**
   - Production copy on the app host.
   - Primary backup copy on Thunderbluff.
   - Secondary independent copy outside the production host + Thunderbluff failure domain.
2. **2 different media / storage systems**
   - App host local disk, VM volume, Docker volume, or appliance storage.
   - Thunderbluff backup share or encrypted backup repository.
   - Prefer the third copy on a separate NAS, removable disk, or encrypted cloud/object storage rather than another share on the same Thunderbluff pool.
3. **1 offsite or offline copy**
   - Best: encrypted cloud/object repository or periodically rotated USB disk stored away from the homelab.
   - Minimum viable interim: replicate Thunderbluff backups to a separate storage system plus a scheduled offline/removable-disk rotation until cloud/offsite is selected.

## Design principles

- Thunderbluff is the primary backup hub, not the only copy.
- Use application-aware dumps for databases first; raw volume snapshots are secondary.
- Encrypt backup repositories before anything leaves the app host or Thunderbluff.
- Keep secrets out of logs, dashboards, GitHub, and Telegram reports. Report backup presence, age, size, and restore-test status only.
- Prefer small, restorable units: app config, database dump, compose/env manifests, TLS/DNS/proxy config, and critical state.
- Do not treat GitHub as the backup for runtime secrets, databases, uploaded files, or Docker volumes.
- Do not treat named Docker volumes or RAID as backup by themselves.
- Every important backup class needs a restore test, not just a successful job log.

## Proposed repository layout on Thunderbluff

Use a dedicated backup area, with one encrypted repository per trust class if using restic or borg:

```text
/backups/homelab/
  faye/
  proxmox/
  proxy-edge/
  synology-apps/
  homelabsec/
  tradingteam/
  homeassistant/
  media-apps/
  documents/
  lightning/
  wordpress/
  restore-tests/
```

Minimum controls:

- Dedicated backup user/key per source host where practical.
- Append-only or restricted-write mode where the tool supports it.
- Snapshots immutable or protected on Thunderbluff if supported for the chosen share.
- Retention: daily for 14 days, weekly for 8 weeks, monthly for 12 months; tune per app.
- Monitoring: each job reports last success timestamp, bytes written, snapshot ID, and prune/check status.

## Backup classes

### Class A: identity, secrets, automation, control plane

Scope:

- Faye/Hermes config and skills/backlog, excluding volatile caches and logs.
- SSH public/private automation keys where required for recovery.
- DNS helper scripts and DNS zone exports.
- Proxy, certificate, and route configuration.
- Proxmox host access/IaC facts that are not already in Git.

Approach:

- Encrypted file backup from each host to Thunderbluff.
- Integrate with the secret-management programme rather than copying loose secrets into generic backups forever.
- Keep a separate emergency recovery bundle documented but not exposed in chat/logs.
- Verify by restoring to a disposable directory and checking file presence/permissions, not printing secret contents.

### Class B: databases and app state

Scope:

- HomelabSec Postgres.
- Trading Team state, reports, snapshots, and any local databases.
- Paperless, Mealie, Audiobookshelf, Heimdall, Portainer, proxy manager, Grafana/Prometheus/Alertmanager, Open WebUI, and similar Docker app data.
- WordPress database/uploads if hosted inside the homelab; otherwise treat remote WordPress export separately.

Approach:

- Prefer logical dumps: `pg_dump`, app export, SQLite copy under service stop/read-lock, or database-native dump.
- Also capture compose files, env templates/source manifests, and volume inventory.
- Back up uploaded documents/media metadata; large replaceable media libraries can have a lower-cost policy.
- Restore-test at least one representative Postgres app, one SQLite app, and one Docker-volume app.

### Class C: VMs/LXCs and host recovery

Scope:

- Proxmox VM/LXC configs and selected VM/LXC backups.
- Faye LXC, proxy/HCM host, HomelabSec UAT host, and appliance-like systems that are hard to recreate quickly.

Approach:

- Use Proxmox backup jobs where available, landing on Thunderbluff storage if it can be mounted safely.
- Keep IaC in Git as rebuild documentation, but still back up runtime state and secrets separately.
- Retain frequent backups for small/control-plane guests; less frequent for large/rebuildable guests.

### Class D: special high-risk services

Scope:

- Home Assistant configuration, add-ons, automations, and snapshots.
- Lightning/Umbrel/LND static channel backup and wallet-critical metadata.
- Bitcoin node config/wallet-critical data.

Approach:

- Home Assistant: use native full/partial backups plus config backup to Thunderbluff; test restore to a disposable HA instance where possible.
- Lightning/LND: monitor static channel backup file presence/age/size after channel changes; never print backup contents. Treat missing/stale backup as critical.
- Bitcoin blockchain: usually do not back up full chain data if it can be re-synced; back up node config/wallet-critical data only, unless storage allows a low-frequency snapshot.

### Class E: large media and replaceable data

Scope:

- Jellyfin media, ARR/download caches, audiobooks, books, photo/video libraries if present.

Approach:

- Separate irreplaceable libraries from replaceable downloads.
- Irreplaceable documents/photos/books: 3-2-1 with offsite encrypted copy.
- Replaceable media/download caches: metadata/config backup plus optional low-priority replication, not necessarily full 3-copy retention.

## Implementation phases

### Phase 0: discovery and access

- Confirm Thunderbluff backup share/path, filesystem/snapshot support, capacity, and credentials.
- Confirm whether Faye has SSH/API access to Thunderbluff or whether Robert needs to authorize a key.
- Inventory all active apps from launcher links, proxy/certificate routes, Docker/Portainer, Proxmox, appliance packages, and HomelabSec.
- Classify each app by RPO/RTO and data criticality.

### Phase 1: primary Thunderbluff landing zone

- Create the dedicated backup area and restricted backup users/keys.
- Pick the backup engine: restic is the default recommendation for encrypted, deduplicated, scriptable backups; borg is also acceptable if preferred.
- Implement and verify the first three jobs:
  1. Faye/Hermes runtime config/backlog/skills.
  2. HomelabSec Postgres dump + compose/runtime manifests.
  3. Proxy-edge config including route/cert/DNS state.

### Phase 2: app coverage

- Add Docker/app backups for launcher, Portainer, document, recipe, audiobook, media, ARR/download, Open WebUI/Ollama, and monitoring stacks.
- Add Home Assistant native backups once backend/access is healthy.
- Add Trading Team state backups with strict practice/live safety separation.
- Add Lightning/Umbrel backup checks and alerts for stale static channel backups.

### Phase 3: 3-2-1 completion

- Choose secondary independent destination: separate NAS, rotated USB, encrypted cloud/object storage, or a mix.
- Replicate encrypted Thunderbluff repositories to the secondary target.
- Make at least one copy offsite or offline.
- Add quarterly restore drills and alerting for missed backup windows.

## Success criteria

- Every important app has a documented backup source, method, destination, frequency, retention, and restore command.
- Thunderbluff has recent encrypted backup snapshots for all Class A/B/C/D items.
- At least one restored sample from each backup class has been verified.
- Backup status is visible through HomelabSec/HCM/Prometheus/Telegram without exposing secrets.
- A ransomware/admin-error scenario cannot delete all copies from a single compromised app host.

## Open decisions

- Which third-copy target should be used: separate NAS, rotated USB, encrypted cloud/object storage, or all of the above?
- Should Thunderbluff replicate backups onward, or should each source host write independently to both destinations?
- Which datasets are irreplaceable enough for full 3-2-1: documents/photos/books, Paperless, Home Assistant, Lightning, Trading Team, WordPress, media libraries?
- Preferred backup tool: restic default, borg alternative, or appliance-native tooling where app-aware dumps are not needed?
