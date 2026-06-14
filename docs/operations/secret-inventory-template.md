# Secret Inventory Template

Purpose: track secret metadata without storing raw secret values.

Do not put private keys, tokens, passwords, seed phrases, macaroons, cookies, session files, repository passwords, or rendered `.env` contents in this file.

## Template row

```yaml
id: example-service-api-token
owner: Robert / service owner
system: app-or-host-name
secret_type: api-token | ssh-key | db-password | tls-key | recovery-material | backup-key | webhook-url | other
storage: vault-item | sops-file | host-local-generated-file | hardware-token | offline-envelope
consumers:
  - host-or-service-allowed-to-use-it
rotation: quarterly | annual | on-staff-change | on-leak | manual
backup: encrypted-vault-export-and-offsite-copy
recovery_test: describe how to prove it works without exposing the value
blast_radius: what compromise enables
revocation: where and how to revoke or replace it
notes: non-secret notes only
```

## Initial inventory groups

- Faye/Hermes: Telegram bot token, GitHub token, provider credentials, SSH automation keys, local model endpoint credentials if any.
- Proxmox/Mac Pro: automation SSH keys, API tokens, sudoers scope.
- Proxy/DNS/certificates: DNS API credentials, certificate account keys, reverse-proxy admin credentials, TLS private-key storage.
- NAS/Thunderbluff/backups: backup user keys, repository passwords, storage credentials, snapshot/admin credentials.
- HomelabSec: Postgres password, admin credentials, OIDC/basic-auth secrets, monitoring/admin credentials, notification webhooks.
- Home Assistant: long-lived access tokens, add-on credentials, backup encryption/recovery material.
- Trading Team: practice/live API credentials, broker/data-provider keys, notification tokens, deployment keys.
- WordPress: API/application passwords, admin credentials, deployment tokens.
- Lightning/Umbrel: static channel backup location metadata, wallet/recovery material, macaroon/token classes.
