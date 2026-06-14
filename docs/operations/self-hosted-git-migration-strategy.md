# Self-Hosted Git Migration Strategy

## Purpose

Move selected repositories from GitHub-only hosting to a self-hosted Git service without losing GitHub's strengths for public discovery, pull requests, or offsite redundancy.

This is a planning document. It does **not** move repositories by itself. The goal is to define a safe path for choosing the platform, deploying it in the homelab, migrating low-risk repositories first, and keeping recovery options clear.

## Current Starting Point

A non-secret GitHub inventory taken from the account currently shows 18 owned repositories: a mix of public utility repositories, private application repositories, homelab operations repositories, writing/content repositories, and high-impact automation repositories.

Because this repository may be public, this strategy intentionally does **not** list private repository names. Keep exact private repo names in an operator-only tracker or the self-hosted Git migration issue queue, not in this public planning document.

Treat the inventory as a snapshot, not the source of truth. Refresh it before migration.

## Recommended Direction

Use **Forgejo** as the first self-hosted Git platform unless a future requirement clearly needs GitLab's heavier project-management and CI features.

Why Forgejo first:

- light enough for homelab infrastructure
- compatible with normal Git workflows
- has web UI, issues, pull requests, releases, SSH/HTTPS Git, and package features
- simpler to back up and restore than a full GitLab stack
- easier to keep private/LAN-first while still mirroring selected repos to GitHub

Avoid self-hosting as a single point of failure. For important repositories, keep at least one independent remote outside the Git host:

- self-hosted Forgejo as the primary working remote for selected repos
- GitHub as a read-only or backup mirror where appropriate
- encrypted backup of the Forgejo application database, Git repositories, attachments, LFS objects, and configuration

## Hosting Model

Target shape:

- `git.home.robertbalm.com` or equivalent home HTTPS route for browser/API access
- SSH Git access on a deliberate port, preferably via a fixed LAN route or VPN-only path
- service behind the existing homelab reverse-proxy/certificate/DNS chain
- persistent volumes for Git repositories, database, attachments, LFS, avatars, and actions data
- SOPS/age-managed runtime secrets, following `docs/operations/secret-management-runbook.md`
- monitored health, disk, backup freshness, and certificate expiry

Keep the first deployment LAN-only unless Robert explicitly wants external access.

## Migration Principles

1. **Mirror before cutover.** Create bidirectional or one-way mirrors before changing developer remotes.
2. **Low-risk repos first.** Start with dormant or personal public repos before active private operational repos.
3. **Keep GitHub as fallback.** Do not delete GitHub repos during the first phase. Archive or mark read-only only after restore drills and mirror checks are proven.
4. **No secrets in migration artifacts.** Migration scripts and logs must not print tokens, deploy keys, private SSH keys, webhook secrets, or Actions secrets.
5. **One repo at a time.** Migrate, verify, and record each repository before starting the next.
6. **Restore is part of done.** The self-hosted platform is not production-ready until a backup restore drill proves the service and repositories can be recovered.

## Repository Tiers

### Tier 0: Pilot / Low-Risk

Use these to prove platform operations, backup, SSH/HTTPS Git, mirrors, and restore:

- small public shell/config repositories
- small public utility repositories
- dormant or disposable repositories with no production automation
- one newly-created test repository used only for migration drills

Acceptance criteria:

- repo imported into Forgejo
- clone via HTTPS works
- clone via SSH works
- push to a test branch works
- GitHub mirror remains updated or intentionally unchanged
- backup includes the repo and restore drill can recover it

### Tier 1: Active Personal / Non-Critical

Move after Tier 0 proves the platform:

- public application or utility repositories that benefit from GitHub mirroring
- private personal repositories without production deployment hooks
- content/model/config repositories that can tolerate a short rollback window

Acceptance criteria:

- issues and releases are imported or intentionally left on GitHub
- repository default branch is protected in Forgejo
- GitHub remote is retained as `github` or configured as a mirror
- developer machines and Faye have working SSH deploy/user access

### Tier 2: Operational / Sensitive

Move only after backup, restore, monitoring, and access controls are proven:

- homelab security and operations repositories
- assistant/runtime infrastructure repositories
- website/content deployment repositories
- finance or analysis repositories that are not autonomous trading systems
- any repository containing deployment workflows, private infrastructure metadata, or automation credentials

Acceptance criteria:

- private visibility and access control verified
- repository secrets reviewed and moved to Bitwarden/SOPS where applicable
- deploy keys and automation tokens rotated or re-scoped
- CI/deployment paths updated and tested
- GitHub mirror policy chosen per repo
- rollback path tested by pushing back to GitHub from a fresh clone

### Tier 3: High-Impact Autonomous/Financial Work

Move last, and only with explicit go/no-go:

- autonomous trading or financial-control repositories
- any repository where an agent can execute real-world actions, change deployments, or affect money/assets

Acceptance criteria:

- all Tier 2 criteria met
- separate disaster recovery notes exist
- automated agents can authenticate without broad tokens
- CI/deploy/paper-trading workflows have been tested after remote changes
- GitHub remains available as an emergency mirror until the self-hosted platform has survived multiple backup/restore drills

## Platform Implementation Plan

### Phase 1: Decide and Prepare

1. Confirm Forgejo vs Gitea vs GitLab.
2. Choose deployment host and storage location.
3. Choose database mode: Postgres preferred for operational consistency; SQLite acceptable only for a small pilot.
4. Decide network exposure: LAN-only, VPN-only, or externally reachable with strong auth.
5. Define initial admin users and groups.
6. Decide whether Forgejo Actions will be enabled immediately or deferred.

### Phase 2: Deploy Self-Hosted Git

1. Add a compose or Ansible deployment under HomelabSec infrastructure docs/IaC.
2. Store secrets through the SOPS/age workflow, not plaintext committed files.
3. Create reverse-proxy route and certificate.
4. Add DNS entry and verify normal resolver path.
5. Verify HTTPS route with browser/API health.
6. Verify SSH Git access.
7. Add dashboard/catalog link only after live checks pass.
8. Add monitoring checks for service health, certificate expiry, disk usage, and backup age.

### Phase 3: Backup and Restore Baseline

Back up at minimum:

- Forgejo configuration
- database
- Git repositories
- LFS data
- attachments and avatars
- Actions artifacts if enabled
- SSH host keys and app secrets, via secret-management workflow

Run a restore drill before migrating important repositories:

1. Stop the service or restore into a disposable test instance.
2. Restore database and data volumes.
3. Start Forgejo.
4. Clone an imported test repo.
5. Push a test branch.
6. Verify web UI, issues, and releases if used.

### Phase 4: Pilot Migration

For each Tier 0 repo:

1. Create/import repository in Forgejo.
2. Add GitHub as a mirror or backup remote.
3. Clone from Forgejo into a temporary directory.
4. Compare branch and tag counts with GitHub.
5. Push a test branch to Forgejo.
6. Delete the test branch.
7. Confirm backup captures the imported repo.
8. Record migration status in this document or a follow-up tracker.

### Phase 5: Active Repo Migration

For each Tier 1 or Tier 2 repo:

1. Freeze direct GitHub writes for the repo during the cutover window.
2. Import repo, branches, tags, issues, releases, and wiki where required.
3. Configure branch protection.
4. Configure deploy keys, webhooks, and CI variables using least privilege.
5. Update local remotes:

   ```bash
   git remote rename origin github
   git remote add origin <self-hosted-git-url>
   git fetch origin
   git push origin --all
   git push origin --tags
   ```

6. Run the repo's tests or deployment smoke checks.
7. Confirm GitHub mirror/fallback state.
8. Record the result and rollback notes.

### Phase 6: GitHub Cleanup

Only after multiple successful migrations and restore drills:

- keep public repos mirrored to GitHub if public discoverability matters
- archive GitHub repos only after all automation points to Forgejo
- update repository descriptions to point to the canonical self-hosted remote if desired
- remove stale broad GitHub tokens and replace with scoped mirrors/deploy keys
- keep at least one off-host backup independent of Forgejo

## Security Controls

- Require 2FA for human users where supported.
- Use SSH keys per human/agent; avoid shared keys.
- Use deploy keys per repository for automation where possible.
- Keep personal access tokens narrow, named, and rotated.
- Disable public registration unless explicitly needed.
- Keep private repos private by default.
- Do not store plaintext GitHub or Forgejo tokens in committed files.
- Put runtime secrets in SOPS/age bundles and recovery copies in Bitwarden EU.
- Monitor failed login attempts, disk usage, queue/worker failures, and backup freshness.

## CI and Automation

Initial recommendation:

- defer self-hosted CI runners until Git hosting, backups, and mirrors are stable
- keep existing GitHub Actions for repos that still need CI during transition
- later evaluate Forgejo Actions or a separate runner stack

Before moving CI for any repo:

- inventory current GitHub Actions secrets by name only
- move required runtime secrets to Bitwarden/SOPS or scoped Forgejo secrets
- test runners with a non-sensitive pilot repo
- avoid giving runners broad host Docker/socket access unless isolated

## Rollback Plan

For every migrated repo, keep a working GitHub fallback until the migration is proven.

Rollback steps:

1. Set GitHub remote as canonical again:

   ```bash
   git remote set-url origin https://github.com/<owner>/<repo>.git
   ```

2. Push current branches/tags back to GitHub if needed:

   ```bash
   git push origin --all
   git push origin --tags
   ```

3. Disable Forgejo webhooks/deploy keys for that repo.
4. Restore old CI/deploy settings.
5. Record the rollback reason.

## Open Decisions

- Confirm platform: Forgejo, Gitea, or GitLab.
- Confirm canonical URL and SSH access pattern.
- Choose host and storage backend.
- Decide whether public repos stay public on GitHub as mirrors.
- Decide whether private repos get GitHub private mirrors or self-hosted-only remotes.
- Decide whether to import GitHub issues/releases/wiki or keep history on GitHub.
- Decide when, if ever, to run self-hosted CI runners.

## Next Concrete Slice

1. Approve Forgejo as the pilot platform or choose an alternative.
2. Add a Forgejo deployment design/runbook to HomelabSec.
3. Deploy LAN-only Forgejo behind the homelab HTTPS route.
4. Prove backup/restore with one Tier 0 repo.
5. Migrate two Tier 0 repos and document results.
6. Review before moving any private or operational repos.
