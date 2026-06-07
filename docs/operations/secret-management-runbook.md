# Secret management runbook

This runbook operationalizes the HomelabSec secret-management strategy: Bitwarden
EU for human/recovery records, SOPS + age for automation, and local rendered
runtime files for services.

## Bootstrap state

Faye has the following tooling installed:

- `age` / `age-keygen`
- `sops`
- Bitwarden CLI `bw`, configured to `https://vault.bitwarden.eu`

Faye's public SOPS recipient is recorded in `.sops.yaml`. The corresponding
private age identity is host-local and must be backed up into Bitwarden EU and
the offline break-glass bundle before this becomes the only recovery path.

## Create or update an automation secret bundle

1. Create or update the source item in Bitwarden EU.
2. On Faye, login/unlock Bitwarden interactively when Robert is present:

   ```bash
   bw config server https://vault.bitwarden.eu
   bw login
   bw unlock
   ```

3. Export/copy only the fields needed for a deployment into a temporary local
   JSON file under `/tmp` or another non-repo path.
4. Encrypt it into the repo:

   ```bash
   sops --encrypt --input-type json --output-type json \
     /tmp/homelabsec-runtime.json \
     > secrets/sops/homelabsec.runtime.enc.json
   ```

5. Remove the temporary plaintext immediately.
6. Validate without printing values:

   ```bash
   python3 scripts/secrets/validate_secrets_management.py
   ```

7. Commit only encrypted SOPS files, non-secret metadata, scripts, and docs.

## Render a runtime `.env` file

```bash
python3 scripts/secrets/render_sops_env.py \
  secrets/sops/homelabsec.runtime.enc.json \
  secrets/runtime/homelabsec.env
```

The renderer writes `0600` files and prints only the output path. It does not
print decrypted values.

## Recovery drill

Quarterly or after key changes:

1. Confirm Bitwarden EU can be unlocked by Robert.
2. Retrieve the recovery copy of the age identity into a disposable or controlled
   host path with `0600` permissions.
3. Decrypt `secrets/sops/homelabsec.sample.enc.json` without displaying values:

   ```bash
   python3 scripts/secrets/validate_secrets_management.py
   ```

4. Render the sample to a temporary env file and confirm the file exists with
   `0600` permissions.
5. Delete temporary plaintext artifacts.

## Rotation / revocation

When an age identity may be exposed or a host should lose access:

1. Generate a replacement identity on the trusted host.
2. Add the new public recipient to `.sops.yaml`.
3. Re-encrypt each SOPS file with `sops updatekeys` or decrypt/re-encrypt in a
   controlled local path.
4. Remove the old recipient from `.sops.yaml`.
5. Delete the old private identity from hosts that no longer need access.
6. Update Bitwarden EU, inventory metadata, and the break-glass bundle.
7. Run validation and commit the encrypted-file changes.

## Operator safety rules

- Never paste decrypted secrets into GitHub, docs, backlog files, dashboards, or
  Telegram.
- Never attach Bitwarden exports or age private identities to issues or chats.
- Do not log `bw get`, `sops --decrypt`, rendered env files, Authorization
  headers, cookies, seeds, macaroons, or private keys.
- Treat Bitwarden CLI session material and age identities as high-value secrets.
