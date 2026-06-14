# HomelabSec secrets workflow

This repository now treats GitHub as a **zero-secret repository**:

- no plaintext secrets;
- no SOPS-encrypted secret payloads;
- no vault exports;
- no OpenBao snapshots, tokens, unseal keys, recovery keys, or session files;
- no Vaultwarden database/export files.

Git may contain only non-secret metadata, templates, policy examples, runbooks, and validation scripts.

## Target architecture

- **Vaultwarden**: Robert-facing human/recovery vault for passwords, API keys, SSH-key recovery copies, break-glass notes, OpenBao recovery material, and vault/export backups.
- **OpenBao**: automation/service secret broker for runtime secrets, narrowly scoped tokens, policies, short-lived credentials where practical, and audit logs.
- **Local runtime materialization**: deployment jobs fetch from OpenBao or Vaultwarden during controlled operations and write restrictive host-local files, normally `0600`, outside Git.

## Layout

- `inventory.example.json` — non-secret inventory metadata example.
- `runtime/` — local generated files; ignored and never committed.
- `openbao/`, `vaultwarden/`, `exports/`, `snapshots/`, and `backups/` — sensitive local-only working directories if created; ignored by Git.

## Rules

- Never commit `.env`, `*.env`, private keys, vault tokens, unseal/recovery keys, Bitwarden/Vaultwarden session files, vault exports, OpenBao snapshots, cookies, seeds, macaroons, or backup repository passwords.
- Never commit SOPS encrypted secret files. Encrypted-at-rest is not enough for this repo boundary.
- Store real values in Vaultwarden/OpenBao only, with backups and break-glass recovery outside GitHub.
- Validation must pass before commits/pushes:

```bash
python3 scripts/secrets/validate_no_git_secrets.py
```
