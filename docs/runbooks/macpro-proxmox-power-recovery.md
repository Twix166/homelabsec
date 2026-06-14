# Mac Pro / Proxmox power recovery runbook

Purpose: verify and preserve the Mac Pro Proxmox host's recovery behaviour after a mains power outage.

This runbook separates two different layers that are easy to confuse:

1. **Mac Pro host AC restore**: whether the physical Mac Pro powers itself back on when mains power returns.
2. **Proxmox guest autostart**: whether VMs and LXCs start after the Proxmox host has booted.

Both layers are required for unattended recovery after a real power outage.

## Known host

- Proxmox / Mac Pro host: `10.0.0.84`
- Proxmox node name: `pve`
- Important route: `https://macpro.home.robertbalm.com:8006/`

## Current known-good state

After the June 2026 power outage, the Mac Pro powered back on by itself and Proxmox started its configured guests.

The host-level AC restore check returned:

```text
setpci -s 00:1f.0 0xa4.b
08
```

For this Mac Pro / C600-X79 chipset setup, bit `0` clear means auto power-on after AC return is enabled. Therefore value `08` is treated as the current known-good state.

No persistent systemd startup item was found at that time. Because the setting was already on and the operator instruction was to leave it alone if on, no change was made.

## Access requirements

The Proxmox API can verify VM/LXC autostart settings and recent startup tasks, but it cannot verify the Mac Pro hardware-level AC restore register. Host shell access is required for the `setpci` checks below.

Use the dedicated `fayebot` automation account with passwordless sudo. This account and the removal of the former temporary direct-root Faye key are managed by `infra/proxmox/proxmox-host-access.yml`.

Examples below are host-local commands. When running remotely as `fayebot`, prefix privileged commands with `sudo -n`.

## Verify host-level AC restore

Run on the Proxmox host:

```bash
setpci -s 00:1f.0 0xa4.b
```

Interpretation used for this host:

```bash
v=$(setpci -s 00:1f.0 0xa4.b)
printf 'register_00_1f_0_0xa4_b=%s\n' "$v"
if (( 0x$v & 1 )); then
  echo 'auto_power_after_ac_return=OFF_OR_DISABLED'
else
  echo 'auto_power_after_ac_return=ON_OR_ENABLED'
fi
```

Known-good output:

```text
register_00_1f_0_0xa4_b=08
auto_power_after_ac_return=ON_OR_ENABLED
```

## Check for an existing persistent startup item

Run on the Proxmox host:

```bash
grep -Rsl 'setpci.*00:1f.0.*0xa4' \
  /etc/systemd/system \
  /usr/local/sbin \
  /usr/local/bin \
  2>/dev/null
```

If this prints no paths, there is no obvious startup item re-applying the setting.

## Set host-level AC restore if it is off

Only do this if the check says `OFF_OR_DISABLED`, or if the operator explicitly asks for the setting to be re-applied.

Run on the Proxmox host:

```bash
setpci -v -s 00:1f.0 0xa4.b=0:1
setpci -s 00:1f.0 0xa4.b
```

Re-run the interpretation command above and confirm it reports:

```text
auto_power_after_ac_return=ON_OR_ENABLED
```

## Optional: create a persistent boot-time reapply service

Only create this service if the setting is off, does not survive host boot, or the operator explicitly requests persistence. Do not create it merely because no service exists when the live hardware setting is already on and the instruction is to leave it alone.

Create the helper:

```bash
cat >/usr/local/sbin/macpro-ac-restore-enable <<'EOF'
#!/bin/sh
set -eu
setpci -v -s 00:1f.0 0xa4.b=0:1
v=$(setpci -s 00:1f.0 0xa4.b)
if [ $((0x$v & 1)) -ne 0 ]; then
  echo "Mac Pro AC restore still appears disabled: 0xa4.b=$v" >&2
  exit 1
fi
echo "Mac Pro AC restore enabled: 0xa4.b=$v"
EOF
chmod 0755 /usr/local/sbin/macpro-ac-restore-enable
```

Create the systemd unit:

```bash
cat >/etc/systemd/system/macpro-ac-restore.service <<'EOF'
[Unit]
Description=Enable Mac Pro auto power-on after AC returns
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/macpro-ac-restore-enable
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
```

Enable and run it:

```bash
systemctl daemon-reload
systemctl enable --now macpro-ac-restore.service
systemctl status --no-pager macpro-ac-restore.service
```

Verify again:

```bash
v=$(setpci -s 00:1f.0 0xa4.b)
printf 'register_00_1f_0_0xa4_b=%s\n' "$v"
if (( 0x$v & 1 )); then
  echo 'auto_power_after_ac_return=OFF_OR_DISABLED'
else
  echo 'auto_power_after_ac_return=ON_OR_ENABLED'
fi
```

## Verify Proxmox guest autostart

Host AC restore only gets the Mac Pro powered on. Proxmox guest autostart is separate.

From the Proxmox host:

```bash
qm list
pct list
for id in $(qm list | awk 'NR>1 {print $1}'); do
  printf 'QEMU %s ' "$id"
  qm config "$id" | grep -E '^(name|onboot|startup):' || true
done
for id in $(pct list | awk 'NR>1 {print $1}'); do
  printf 'LXC %s ' "$id"
  pct config "$id" | grep -E '^(hostname|onboot|startup):' || true
done
```

Expected result for critical guests: `onboot: 1`.

The Proxmox API can also verify this without host shell access by reading each VM/LXC config and checking `onboot=1`.

## Post-outage verification checklist

After a real outage:

1. Confirm the Mac Pro host is reachable.
2. Confirm Proxmox node uptime is recent and node status is online.
3. Confirm recent `startall`, `qmstart`, and `vzstart` tasks completed successfully.
4. Confirm critical VMs/LXCs are running.
5. Confirm critical routes are healthy from the normal LAN path, not only from backend checks.
6. If the host did not auto-power-on, use this runbook to inspect and re-apply the AC restore setting.

## Do not over-interpret

- VM/LXC `onboot=1` proves only guest autostart after the host boots.
- Proxmox `startall` success proves only that Proxmox started guests after the host was already on.
- The `setpci` register check is the host-level evidence for Mac Pro auto power-on after AC returns.
- A successful real outage recovery is useful evidence, but still record the live register value when verifying the configuration.
