# Umbrel / LND Recovery Runbook

Purpose: safely recover the Umbrel Bitcoin + Lightning stack after a host restart, container restart, or noisy monitoring alert without mistaking normal LND startup for a real fault.

## Scope

This runbook covers the monitored Umbrel stack:

- Umbrel OS/auth containers
- Bitcoin Core container
- LND / Lightning app containers
- Bitcoin and Lightning Tor containers
- The external Umbrel stack monitor, Prometheus, and Alertmanager on the monitoring host

Do not put wallet seeds, private keys, macaroon contents, TLS keys, API tokens, or exact secret paths into tickets or chat updates.

## First triage

1. Check whether this is immediately after a reboot or container restart.
2. Run the monitor health probe from the monitoring host:

```bash
cd /home/ubuntu/umbrel-stack-monitor
./scripts/post-restart-healthcheck.sh
```

3. Read the state fields in the output:

- `lnd_state=rpc_starting` / `startup_wait=1`: LND RPC is not ready yet. Wait and re-probe before diagnosing deeper.
- `rpc_ready=1 wallet_unlocked=0` or `wallet_locked=1`: wallet readiness is the problem; treat as high priority.
- `wallet_unlocked=1 synced_to_chain=0`: LND is up but not caught up to the chain yet.
- `bitcoin_ok=False` or low Bitcoin peer count: diagnose Bitcoin Core before LND.

## Normal restart expectations

After Umbrel or host restart, LND can lag behind the containers being marked `running`. Short-lived `lncli` RPC errors are expected while LND starts and connects to Bitcoin Core.

The monitor classifies this as `startup_wait`. The Prometheus rules intentionally wait longer before alerting:

- Overall stack unhealthy: alerts only if not merely `startup_wait` and sustained.
- LND startup wait: warning only after a prolonged startup window.
- LND wallet locked: critical once RPC is reachable but wallet readiness fails.

## Recovery checklist

### 1. Confirm required containers are running

Use the monitor `/status` or Portainer UI. Required containers include Umbrel OS/auth, Bitcoin Core/app/proxy/Tor, Lightning LND/app/proxy/Tor, and the shared Tor proxy.

If a required container is missing or exited, restart it from Portainer/Umbrel and re-run the post-restart healthcheck.

### 2. Confirm Bitcoin Core health

Bitcoin must be synced and network active before LND can be considered healthy.

Expected monitor fields:

- `bitcoin_ok=True`
- `initialblockdownload=False`
- `networkactive=True`
- Peer count is not persistently below the alert threshold

If Bitcoin is still syncing, wait. If it is not network active or has no peers for a sustained period, troubleshoot Bitcoin/Tor/networking first.

### 3. Classify LND readiness

The monitor distinguishes four common LND states:

- `rpc_starting`: transient during startup; wait and re-probe.
- `wallet_locked`: LND RPC path is reachable but the wallet is not unlocked; unlock through the normal Umbrel UI/operator process.
- `chain_backend_unavailable`: LND cannot reach Bitcoin Core; fix Bitcoin/backend first.
- `auth_error`: monitor/CLI macaroon or TLS access problem; fix monitor access, not the Lightning node itself.

Only escalate as a real LND fault once the same classifier persists beyond the Prometheus `for:` window or the wallet is locked.

### 4. Check Tor last

Tor bootstrap/heartbeat warnings can appear during restart. Re-probe after Bitcoin and LND settle. If Tor remains unhealthy, inspect the Bitcoin and Lightning Tor container logs through Portainer.

### 5. Verify alerts cleared

After recovery:

```bash
curl -fsS http://127.0.0.1:9090/api/v1/alerts
curl -fsS http://127.0.0.1:9093/api/v2/alerts
```

Expected: no active/firing Umbrel stack alerts, or only alerts that are still within a justified startup window.

## Backup / static channel backup checks

LND channel backups are critical. A backup check should prove that the current static channel backup file exists, is non-empty, and has a recent modification timestamp. The monitor/backup checker should never print the backup contents.

Minimum evidence to report:

- backup path label only, not secret contents
- size in bytes
- modification timestamp
- age in seconds/minutes
- pass/fail status

If the backup file is missing, empty, or stale after channel changes, treat as critical and update the backup job before making Lightning changes.

## Reporting format

For Telegram/status reports, include:

- Overall: healthy / degraded / critical
- Bitcoin: synced, peers, block height
- LND: classifier state, wallet unlocked, chain synced, active/pending channels
- Tor: bootstrap/heartbeat status
- Alerts: firing/cleared
- Backup: SCB present, non-empty, recent

Avoid raw internal secrets, tokens, keys, or wallet seed material.
