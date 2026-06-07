# Proxmox host IaC

This directory captures host-level Proxmox/Mac Pro configuration that sits outside the HomelabSec Docker Compose application stack.

## Managed state

`proxmox-host-access.yml` enforces the Faye/Hermes automation access model on the Proxmox host:

- install `sudo` if missing
- create the dedicated `fayebot` automation account
- lock the `fayebot` password so password login is unavailable
- install the dedicated `fayebot` SSH public key
- grant `fayebot` passwordless sudo through `/etc/sudoers.d/90-fayebot`
- write an operator note at `/etc/fayebot-proxmox-access.README`
- remove the former temporary direct-root Faye SSH public key from root's `authorized_keys`
- validate sudoers syntax and prove `fayebot` can run non-interactive sudo

The matching private SSH keys and Proxmox API token secrets are intentionally not stored in this repo.

## Apply

From this directory, with root SSH still available for initial bootstrap or with another privileged account:

```bash
ansible-playbook -i inventory.example.yml proxmox-host-access.yml
```

After the first successful run, update your private inventory to connect as `fayebot` instead of `root` if desired:

```yaml
ansible_user: fayebot
ansible_ssh_private_key_file: ~/.ssh/id_ed25519_proxmox_fayebot
```

## Verify manually

```bash
ssh -i ~/.ssh/id_ed25519_proxmox_fayebot fayebot@10.0.0.84 'id && sudo -n true && sudo -n visudo -cf /etc/sudoers.d/90-fayebot'
ssh -i ~/.ssh/id_ed25519_proxmox_faye root@10.0.0.84 'true'
```

Expected result: the `fayebot` command succeeds and the old direct-root key is denied.
