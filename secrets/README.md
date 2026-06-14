# HomelabSec secrets workflow

This directory implements the current secret-management strategy:

- **Bitwarden EU** is the human/recovery vault.
- **SOPS + age** is the automation secret distribution layer.
- **Rendered runtime files** are local-only and ignored by Git.

## Layout

- `inventory.example.json` — non-secret inventory metadata example.
- `sops/*.enc.json` — encrypted machine-consumable secret bundles.
- `runtime/` — local generated files; ignored and never committed.

## First-time operator setup

Faye now has local SOPS/age tooling installed and an age identity at the
standard SOPS path. The private identity is **not** in this repo. Store a
recovery copy in Bitwarden EU and the offline break-glass bundle before relying
on it for disaster recovery.

Useful commands:

```bash
# Confirm Bitwarden CLI points at Bitwarden EU.
bw config server

# Login/unlock interactively when Robert is present.
bw login
bw unlock

# Verify encrypted sample can decrypt on Faye.
python3 scripts/secrets/validate_secrets_management.py

# Render a local env file from an encrypted bundle.
python3 scripts/secrets/render_sops_env.py \
  secrets/sops/homelabsec.sample.enc.json \
  secrets/runtime/homelabsec.sample.env
```

## Rules

- Never commit `.env`, `*.env`, age private identities, Bitwarden session files,
  vault exports, private keys, API tokens, cookies, seeds, macaroons, or backup
  repository passwords.
- Commit only metadata or SOPS-encrypted files.
- Avoid logging decrypted SOPS output. Render to files with `0600` permissions.
- Store recovery copies and emergency notes in Bitwarden EU/offline break-glass,
  not in GitHub or Telegram.
