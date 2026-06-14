# Vaultwarden + OpenBao Bootstrap Runbook

This runbook deliberately excludes real credentials. Bootstrap steps that create or display secrets require Robert present.

## Preconditions

- Git working tree contains no secret payloads.
- `python3 scripts/secrets/validate_no_git_secrets.py` passes.
- Runtime env files are created outside Git under `secrets/runtime/` with `0600` permissions.
- Reverse proxy/DNS/TLS targets are prepared for:
  - `vaultwarden.home.robertbalm.com`
  - `openbao.home.robertbalm.com`

## Runtime files to create outside Git

`secrets/runtime/vaultwarden.env` should contain Vaultwarden runtime settings such as admin token, SMTP settings if used, database URL if moved off SQLite, and other service configuration. Do not commit it.

`secrets/runtime/openbao.env` should contain only non-persistent runtime environment required by the OpenBao container. Do not put unseal keys or root tokens here.

## Start services

```bash
docker compose -f compose/compose.secrets.example.yaml up -d
```

Verify without printing secrets:

```bash
docker compose -f compose/compose.secrets.example.yaml ps
curl -fsS http://127.0.0.1:8222/alive
BAO_ADDR=http://127.0.0.1:8200 bao status
```

## Vaultwarden bootstrap

With Robert present:

1. Open the Vaultwarden URL through the homelab HTTPS route.
2. Create/confirm the admin and owner account policy.
3. Disable open signups unless deliberately needed.
4. Store an offline recovery note outside Git.
5. Configure encrypted backup/export workflow and test restore into an isolated disposable instance.

## OpenBao bootstrap

With Robert present:

1. Initialize OpenBao.
2. Store unseal/recovery material in Vaultwarden and offline break-glass, never Git.
3. Unseal OpenBao.
4. Enable audit logging after confirming it will not store secret request bodies in unsafe locations.
5. Enable auth methods and create narrow policies.
6. Create scoped operator/admin tokens.
7. Revoke or retire the bootstrap/root token once scoped administration is working.

## First migration canary

Use a non-production canary secret first:

1. Create metadata-only inventory entry.
2. Write real value to OpenBao with a non-sensitive path name.
3. Fetch it from a deployment context without printing the value.
4. Render a host-local test file with `0600` permissions if needed.
5. Delete the canary or rotate it after the drill.

## Rollback

If bootstrap fails:

- stop containers;
- preserve logs only after checking they do not contain secrets;
- delete failed local runtime/token files if any were created;
- do not commit generated data, exports, snapshots, tokens, or keys.
