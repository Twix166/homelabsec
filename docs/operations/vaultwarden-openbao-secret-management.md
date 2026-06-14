# Vaultwarden + OpenBao Secret Management Plan

Purpose: move HomelabSec away from Git-hosted SOPS secret payloads and toward a zero-secret GitHub boundary with Vaultwarden for human/recovery secrets and OpenBao for automation/runtime secrets.

Captured: 2026-06-14

## Decision

GitHub must not store secrets, encrypted or otherwise.

Allowed in GitHub:

- metadata-only inventory examples;
- service topology and deployment templates with placeholders;
- OpenBao policy templates without real paths/tokens where paths would disclose sensitive names;
- runbooks and validation scripts;
- `.env.example` files with placeholders only.

Forbidden in GitHub:

- plaintext secrets;
- SOPS encrypted payloads;
- Vaultwarden database files, exports, attachment blobs, admin tokens, session material, or backup archives;
- OpenBao raft data, snapshots, unseal/recovery keys, root tokens, app tokens, audit logs containing request bodies, or backup archives;
- rendered runtime `.env` files;
- SSH private keys, TLS private keys, API tokens, passwords, cookies, seeds, macaroons, and backup repository passwords.

## Target roles

### Vaultwarden

Vaultwarden is the human/recovery vault.

It should hold:

- human-used passwords and API keys;
- recovery copies of important SSH keys where appropriate;
- OpenBao unseal/recovery material and bootstrap records;
- backup repository passwords and restore notes;
- emergency break-glass notes;
- encrypted exports/backups managed outside GitHub.

Vaultwarden should not be required by ordinary services on every startup/request. It is for Robert-facing management, controlled deploys, and recovery.

### OpenBao

OpenBao is the automation/service vault.

It should hold:

- runtime application secrets;
- scoped deployment tokens;
- service credentials used by batch jobs and apps;
- short-lived/dynamic credentials where a backend supports them;
- audit evidence that secret access happened, without exposing values.

Services and deployment jobs should authenticate to OpenBao with the narrowest practical method and policy. Long-lived root/bootstrap tokens must be retired after setup.

## Bootstrap phases

### Phase 0 — stop Git secret distribution

Status: started in this branch.

- Remove tracked SOPS configuration and encrypted SOPS payloads from the repo.
- Replace the old SOPS validator with a zero-secret Git validator.
- Keep only metadata examples and docs in `secrets/`.
- Add ignore rules for local Vaultwarden/OpenBao working data, exports, snapshots, and tokens.

### Phase 1 — deploy foundations

Create the two services as internal HTTPS homelab applications:

- `vaultwarden.home.robertbalm.com` for Robert-facing vault access.
- `openbao.home.robertbalm.com` for automation vault/API access.

Initial posture:

- internal network only unless Robert explicitly approves exposure;
- TLS via the standard homelab reverse proxy/certificate workflow;
- HCM/Heimdall visibility for service status, not secret contents;
- app data volumes backed up encrypted outside Git;
- admin/bootstrap credentials handled interactively with Robert present.

### Phase 2 — initialize Vaultwarden

- Create/administer the Vaultwarden instance.
- Configure secure signup/admin policy.
- Record recovery ownership and emergency access.
- Define backup/export location outside GitHub.
- Run a restore drill into an isolated disposable instance before relying on it.

### Phase 3 — initialize OpenBao

- Initialize and unseal OpenBao with Robert present.
- Store unseal/recovery material in Vaultwarden and an offline break-glass copy, never GitHub.
- Enable audit logging with sensitive request/response handling reviewed.
- Create first policies and auth methods.
- Retire the root token after scoped admin paths exist.

### Phase 4 — migrate first secrets

Start with low-risk, clearly scoped non-production/runtime secrets.

For each migrated secret:

1. Create/update a metadata-only inventory row.
2. Put the real value in OpenBao or Vaultwarden, not Git.
3. Update the consuming deployment to fetch from OpenBao or controlled Vaultwarden CLI flow.
4. Render host-local runtime files with restrictive permissions if needed.
5. Verify the service works without printing the secret.
6. Document rotation and revocation.

### Phase 5 — rotate old material

Any secret that previously lived in plaintext, Telegram, logs, broad backups, or encrypted Git should be treated as rotation-needed. Prioritize:

- GitHub tokens;
- DNS/certificate tokens;
- Telegram/bot tokens;
- service admin passwords;
- database passwords;
- backup repository credentials;
- broad SSH automation keys.

## Operational rules

- Faye must not print secrets in Telegram or logs.
- Scripts must report counts, paths/classes, and status only.
- Any command that would reveal a secret should be run interactively with Robert present or redirected to a protected local file with `0600` permissions.
- Backups of Vaultwarden and OpenBao are themselves critical secrets and must be encrypted, tested, and copied off-box/offsite/offline according to the backup strategy.
- HomelabSec findings may report missing controls, stale rotations, invalid permissions, or failed backups, but not raw values.

## First implementation artifacts

This branch adds the initial repo-side controls:

- deletion of tracked SOPS encrypted payloads;
- `scripts/secrets/validate_no_git_secrets.py`;
- updated `secrets/README.md` and `secrets/inventory.example.json`;
- this migration plan.

The next step is service deployment design/implementation for Vaultwarden and OpenBao on the approved homelab app/workload host, with Robert present for bootstrap credentials.
