# Homelab Secret Management Strategy

Purpose: bring API keys, SSH keys, tokens, certificates, recovery material, and service credentials under deliberate management before they are broadly backed up.

Captured: 2026-06-07

## Executive priority

Secret management is **P0** and should be handled before broad backup implementation. Backups are only safe if the secrets inside them are encrypted, restorable, and revocable. Today, many homelab secrets are likely scattered across `.env` files, SSH directories, app databases, proxy/certificate stores, browser/operator machines, and ad-hoc notes. That creates two risks:

- **Loss risk:** a power event, disk failure, or host rebuild can permanently lose keys/tokens needed to recover services.
- **Exposure risk:** a naive backup can copy raw secrets into too many places, making compromise or accidental Git/Telegram/log exposure more likely.

The target is not “put every secret in Git.” The target is: every important secret is inventoried by name and owner, stored in a controlled encrypted system, backed up through a tested recovery path, rotated when needed, and never printed in normal operator output.

## Scope

Secret classes to manage:

- SSH keys for Faye, Proxmox, proxy, Synology/NAS, Home Assistant, app hosts, GitHub deploy/push, and future automation accounts.
- API tokens for GitHub, Cloudflare/DNS, certificate issuance, trading/data providers, WordPress, Telegram/bots, notification endpoints, monitoring, and app integrations.
- App/runtime credentials: `.env` secrets, database passwords, OIDC/basic-auth credentials, admin bootstrap passwords, Grafana/Prometheus/Alertmanager credentials, Portainer/proxy-manager credentials, and service-specific tokens.
- TLS/certificate material where private keys are not automatically recoverable from the certificate manager.
- Recovery material for Home Assistant, Lightning/Umbrel/LND, wallet/channel backups, password-manager emergency access, and encryption keys.
- Backup repository secrets: restic/borg repository passwords, storage keys, append-only credentials, and offsite replication credentials.

Do not store raw secret values in this repository, backlog files, issue bodies, dashboards, or Telegram reports.

## Recommended architecture

### Source of truth

Use a password-manager/vault as the human-friendly source of truth, plus an automation-friendly encrypted secret distribution path.

Decision:

1. **Primary human/recovery vault:** Robert's existing Bitwarden EU account for human-managed records, emergency access, API keys, SSH key recovery copies, backup repository passwords, and break-glass notes.
2. **Automation secrets:** SOPS + age encrypted files for machine-consumable secrets, decryptable only by designated host or operator keys.
3. **Runtime materialization:** deploy scripts render `.env` files or service config on target hosts from encrypted sources; generated plaintext stays local, permission-restricted, and is not committed.
4. **Break-glass recovery:** a small sealed/offline recovery bundle containing the minimum information needed to regain access to Bitwarden, SOPS/age recipients, backup repositories, and core hosts.

Vaultwarden is **not required for the initial strategy** because Robert already has Bitwarden EU. Add self-hosted Vaultwarden only if a later requirement justifies it, such as a local-only password-manager service, separate homelab vault tenancy, or avoiding hosted Bitwarden dependency. Until then, adding Vaultwarden would create another critical service to host, update, monitor, expose, and back up.

Alternatives that can be chosen later:

- Vaultwarden if a self-hosted Bitwarden-compatible vault becomes desirable.
- HashiCorp Vault or OpenBao if dynamic secrets and service-to-service leasing become valuable.
- KeePassXC if a simpler offline-first vault is preferred.
- Synology/C2 or cloud KMS only as an integration layer, not as the only recovery mechanism.

### Automated secret access model

Bitwarden EU can support automated secret lookup through the Bitwarden CLI/API, but it should not be the only automation layer and it should not become a runtime dependency for every service.

Recommended split:

1. **Bitwarden EU as human/recovery vault:** store high-value human-managed records, recovery copies, backup repository passwords, emergency notes, and source-of-truth metadata for API keys, SSH keys, service credentials, and break-glass material.
2. **SOPS + age as automation distribution:** store machine-consumable secrets in encrypted files that can live in Git only when encrypted, decryptable by approved operator/host keys.
3. **Local runtime materialization:** deployment scripts render `.env` files or service config on target hosts from encrypted sources; generated plaintext stays local, has restrictive permissions, and is excluded from Git/backups unless covered by the secret-backup policy.
4. **Bootstrap credentials as managed secrets:** any machine account, Bitwarden CLI API credential, Bitwarden session material, age identity, systemd credential, or local unlock file used by automation is itself a high-value secret with inventory, backup, rotation, and revocation requirements.

Allowed automation patterns:

- Faye or a deployment host may fetch a named secret from Bitwarden during a controlled deploy, then write a restricted local runtime file or update an encrypted SOPS file.
- Hosts may decrypt SOPS files with designated age identities during deployment or configuration rendering.
- HomelabSec may check whether secret references, encrypted files, inventories, and recovery backups exist and are fresh, but must not collect or display raw values.

Avoid as the default:

- Services directly querying Bitwarden on every startup or request, because a Bitwarden outage, expired CLI session, or bootstrap-credential failure could stop unrelated services from recovering after a power event.
- Giving every host broad Bitwarden access when a narrow SOPS recipient or rendered local config is enough.
- Logging `bw get`, decrypted SOPS output, rendered `.env` files, Authorization headers, private keys, cookies, session tokens, or seed/recovery material.

SSH-key handling:

- Day-to-day automation should use per-host/per-purpose local SSH keys with strict file permissions and narrow authorized-key or sudo/API scope.
- Bitwarden should store recovery copies or metadata for important keys, not necessarily serve private keys for every connection.
- Each SSH key should have inventory metadata for owner, target, allowed scope, backup/recovery path, rotation date, fingerprint, and revocation/removal path.

### Git boundary

GitHub should contain:

- Secret inventory metadata without values.
- Encrypted SOPS files if we explicitly decide to use GitOps for some secrets.
- `.env.example` files and deployment templates.
- Runbooks for rotation, restore, and verification.

GitHub should not contain:

- Plaintext private keys, tokens, passwords, cookies, session files, seed phrases, macaroons, or backup repository passwords.
- Full host paths that reveal sensitive local layout in public-facing docs where avoidable.
- Debug logs that may include Authorization headers or rendered env files.

## Inventory model

Create a secret inventory with one row per secret class, not the raw value.

Fields:

- `id`: stable non-secret identifier, for example `github-token-faye-push`.
- `owner`: human or service owner.
- `system`: host/app/service that consumes it.
- `type`: SSH key, API token, DB password, TLS key, recovery phrase, backup key, webhook URL, etc.
- `storage`: vault item, SOPS file, host-local generated file, hardware token, or offline envelope.
- `consumers`: hosts/services allowed to read it.
- `rotation`: planned rotation interval or event trigger.
- `backup`: whether it is included in encrypted backups and where the recovery copy lives.
- `recovery test`: how to prove the secret can be restored without revealing it.
- `blast radius`: what an attacker can do if it leaks.
- `revocation`: where/how to revoke it.

This inventory can live in the repo as `docs/operations/secret-inventory-template.md` or as a structured file later, but values stay elsewhere.

## Backup strategy for secrets

Secrets need a stricter backup plan than ordinary application data.

Minimum posture:

1. **Vault export backup:** encrypted password-manager export or vault database backup to Thunderbluff.
2. **SOPS/key backup:** age private keys or recipient recovery material stored in the vault and offline break-glass bundle.
3. **Host key backup:** only keys required for recovery are included; permissions and ownership are checked during restore tests.
4. **Backup repository passwords:** stored in the vault, included in break-glass, and never embedded in job logs.
5. **Offsite/offline copy:** encrypted copy of vault export and break-glass material, separate from Thunderbluff.

Never rely on a single running password-manager instance as the only copy of secrets. Never rely on Thunderbluff alone for vault recovery. Never include raw secrets in HomelabSec findings, dashboards, alerts, or routine Telegram output.

## Implementation phases

### Phase 0: freeze and protect

Implementation status: started in this repository. `.sops.yaml`, `secrets/`, and
`scripts/secrets/` now provide the initial SOPS/age workflow, validation guard,
encrypted sample bundle, and local env renderer.

- Stop adding new plaintext secrets to Git, chat, docs, or generic backups.
- Add or verify repo-level secret scanning before every commit/push.
- Review `.gitignore`, `.dockerignore`, and examples so generated `.env`, keys, vault exports, and backup files are excluded.
- Make a list of known high-value secret locations without printing values.

### Phase 1: inventory and choose tooling

- Pick the primary vault: Bitwarden/Vaultwarden, 1Password, KeePassXC, or another explicit choice.
- Pick automation encryption: SOPS with age is the default recommendation.
- Inventory current secrets by class and consumer, starting with:
  1. Faye/Hermes and Telegram/GitHub/Ollama/provider credentials.
  2. SSH automation keys for Proxmox, proxy, NAS, Home Assistant, app hosts, and GitHub.
  3. Proxy/DNS/certificate tokens and private keys.
  4. HomelabSec runtime credentials and monitoring/admin credentials.
  5. Backup repository passwords and storage credentials.
  6. Trading Team, WordPress, Home Assistant, and Lightning/Umbrel recovery material.
- Record owner, storage location class, rotation path, and recovery test for each secret. Do not record raw values.

### Phase 2: vault migration

- Create vault records for each high-value secret, tagged by system and recovery importance.
- Generate new credentials where current provenance is unclear.
- Move machine-readable deployment secrets into SOPS-encrypted files or documented local materialization steps.
- Replace ad-hoc shared credentials with per-service/per-host credentials where possible.
- Document break-glass access and store it offline.

### Phase 3: rotation and least privilege

- Rotate GitHub, DNS/certificate, Telegram/bot, service admin, and database credentials that are old, overbroad, or known to have lived in plaintext.
- Replace direct root/admin automation with locked-password automation accounts and narrow sudo/API scopes where practical.
- Use separate keys/tokens per host and per purpose; avoid one universal automation key.
- Remove stale authorized keys, unused tokens, old `.env` copies, and unneeded admin sessions.

### Phase 4: backup and restore tests

- Back up the vault/export, SOPS encrypted files, age recipient material, backup repository passwords, and emergency runbook to Thunderbluff.
- Replicate encrypted secret backups to the independent/offsite/offline third copy.
- Run quarterly secret recovery drills:
  - restore vault export to a disposable vault or offline test environment;
  - decrypt one non-production SOPS sample with the documented recovery key;
  - use a restored SSH key against a disposable/low-risk target or validate key fingerprint/permissions;
  - prove a backup repository can be unlocked without revealing the password.

### Phase 5: monitoring and governance

- HomelabSec should eventually report secret-management posture without collecting raw secrets:
  - stale key age;
  - missing inventory entries;
  - overly broad credentials;
  - committed secret detections;
  - missing encrypted backup freshness;
  - rotation due dates.
- Alerts should describe the control failure, not the secret value.
- Reports should include counts, ages, owners, and remediation links only.

## HomelabSec integration ideas

Future HomelabSec slices can help manage this safely:

- Add a secret inventory schema containing metadata only.
- Add collectors that look for risky file names and permissions without reading secret contents.
- Add Git secret-scan results as findings.
- Add SSH authorized-key inventory and stale-key checks.
- Add backup freshness checks for vault exports and encrypted secret bundles.
- Add dashboard cards for “secrets inventory coverage,” “rotation due,” and “secret backup freshness.”

## Success criteria

- Every high-value secret has a named inventory entry with owner, consumers, storage, rotation, backup, recovery test, and revocation path.
- No plaintext secrets are added to GitHub, docs, backlog, alerts, dashboards, or Telegram.
- Primary vault and automation-encrypted secrets are backed up to Thunderbluff and one independent/offsite/offline target.
- At least one recovery drill proves vault export restore, SOPS/age decryption, SSH-key recovery, and backup-repository unlock.
- Old broad credentials are replaced by purpose-specific credentials with limited blast radius.
- HomelabSec can monitor posture without becoming a secret store.

## Open decisions

- Primary vault: decided for initial rollout: Robert's existing Bitwarden EU account.
- Automation format: decided for initial rollout: SOPS + age.
- Vaultwarden: not needed initially; revisit only if a self-hosted Bitwarden-compatible vault becomes a deliberate requirement.
- Automated access: which hosts/users get Bitwarden CLI/API access, and which should use only SOPS/age or rendered local config?
- Bootstrap protection: where are Bitwarden machine credentials, CLI session material, age identities, and unlock files stored, backed up, rotated, and revoked?
- Emergency access: who/where holds the break-glass recovery material?
- Rotation policy: rotate all old/high-value secrets immediately after vault migration, or rotate in staged batches by system?
- Offsite/offline target: encrypted cloud/object storage, rotated USB, separate NAS, or a hybrid?
