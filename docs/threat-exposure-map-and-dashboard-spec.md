# HomelabSec Threat Exposure Map And Dashboard Spec

Generated: 2026-06-04T10:12:38+00:00

## Purpose

This document turns the current live homelab inventory into a product direction for HomelabSec. It is both:

1. a grounded snapshot of current LAN exposure, routing, DNS, dashboard, and certificate posture; and
2. a dashboard specification for turning HomelabSec from a scanner/classifier into an operator-facing security map.

The goal is not to shame normal homelab complexity. The goal is to make the security boundary visible:
what exists, what is routed, what still uses raw IP/port links, what terminates TLS directly,
what is unknown, and what should be prioritized first.

## Evidence Sources

Live sources checked from the homelab control paths:

- Homelab Certificate Manager API on the HCM host:
  - target inventory
  - certificate inventory
  - live certificate status fields
- Nginx Proxy Manager database on the proxy/dashboard host:
  - active proxy hosts
  - upstream host/port/scheme
  - SSL, force-SSL, HTTP/2, block-exploit, and websocket flags
  - selected only non-secret columns; no certificate metadata or DNS-provider secrets were read
- Heimdall database copied from the running Heimdall container:
  - active launcher items and URLs
- LAN DNS checks:
  - default resolver answer
  - authoritative Synology DNS answer at `10.0.0.14`
- LAN discovery from the proxy/dashboard host:
  - ping discovery across `10.0.0.0/24`
  - TCP connect scan for likely admin, proxy, media, monitoring, and app ports
- HomelabSec repository state:
  - README, TODO, BACKLOG, TEST_PLAN
  - current code/config/test surface
  - security-significant code/config grep
  - LOC summary with dependency/build directories excluded

## Repository Baseline

Current repository posture is strong enough to support this next product slice.

Observed repo state:

- Branch: `main`
- Recent work includes alert delivery validation, hardening regression coverage, Fingerbank integration, release `v0.2.0`, and dashboard confidence/guidance work.
- Current release in README: `0.2.0`
- Approximate code surface, excluding `.git`, `.venv`, caches, and build/dependency folders:
  - 127 files
  - 9,162 code lines
  - 777 comment/documentation lines counted by `pygount`
  - major surfaces: Python backend/scheduler/collectors/runner, FastAPI API, frontend assets, Docker Compose overlays, tests, SQL migrations, monitoring config

Current product capabilities from README/backlog:

- LAN discovery with Nmap
- Nmap XML ingest into Postgres
- asset fingerprinting
- local Ollama classification
- fingerprint history and change persistence
- daily reporting
- admin status dashboard
- optional auth/TLS edge overlay
- optional Prometheus/Grafana/Alertmanager monitoring overlay
- backup/restore scripts and integration coverage
- OIDC overlay validation
- alert delivery validation path

Security-sensitive implementation areas already present:

- Auth/session configuration with `DEFAULT_ADMIN_*`, `AUTH_SESSION_DAYS`, and `AUTH_SECURE_COOKIES`.
- Optional stronger auth/OIDC overlay.
- Scheduler host-network design retained intentionally for LAN scan semantics.
- Lynis remote runner stores SSH target configuration and supports sudo use.
- Lynis runner redacts sudo password material from captured output/error paths.
- Config validation exists for brain and scheduler startup.

This means the next useful step is not just more scanning. It is correlating multiple live control planes and turning them into an exposure graph.

## Live Inventory Snapshot

### LAN Discovery

Ping discovery observed 56 live hosts on `10.0.0.0/24`.

Named examples from reverse DNS / host discovery:

- `10.0.0.1`: gateway
- `10.0.0.14`: ElwynnForest Synology / DNS
- `10.0.0.17`: proxy/dashboard host
- `10.0.0.60`: Thunderbluff Synology / media and app services
- `10.0.0.82`: Umbrel
- `10.0.0.84`: Proxmox Mac Pro
- `10.0.0.86`: Brother printer

High-signal live hosts with open scanned ports:

- `10.0.0.1`: SSH, DNS, HTTP, HTTPS
- `10.0.0.14`: SSH, DNS, HTTP, HTTPS, SMB, DSM 5000/5001
- `10.0.0.17`: SSH, HTTP, NPM admin 81, HTTPS, Webmin 9090, Mealie 9925, Audiobookshelf 13378
- `10.0.0.25`: HTTP, HTTPS, 8000, 9000
- `10.0.0.36`: SSH, HTTPS
- `10.0.0.41`: HTTPS
- `10.0.0.60`: SSH, DNS, HTTP, HTTPS, SMB, DSM 5000/5001, 8000, qBittorrent-like 8090, Jellyfin 8096, Portainer 9000, Prowlarr 9696
- `10.0.0.84`: SSH, Proxmox 8006
- `10.0.0.86`: HTTP, HTTPS
- `10.0.0.106`: SSH, Paperless 8000
- `10.0.0.110`: SSH, HTTP, HTTPS, Ollama Fleet 8090, HCM 8097, Prometheus 9090, Alertmanager 9093
- `10.0.0.153`: SSH, HTTP, HTTPS
- `10.0.0.179`: SSH, HTTPS
- `10.0.0.182`: SSH, HTTP, HTTPS
- `10.0.0.222`: 8000, 9000

Interpretation:

- The LAN has a normal homelab density of direct admin surfaces.
- The highest-value exposure clusters are the proxy/dashboard host, the Synology media/app host, HCM/monitoring host, NAS/DNS host, Proxmox host, AI services, camera/device services, and torrent/ARR surfaces.
- HomelabSec should track raw service exposure separately from friendly routed URLs; both matter.

### HCM Targets And TLS Status

HCM tracks a mature set of named HTTPS services. Most live targets are valid and have 69-89 days remaining at time of check.

Valid managed or tracked named services include:

- `hcm.home.robertbalm.com` -> proxy to HCM backend
- `tradingteam.home.robertbalm.com` -> direct service-local HTTPS
- `faye.home.robertbalm.com` -> direct service-local HTTPS
- `ollamafleet.home.robertbalm.com` -> HCM/monitoring host
- `portainer.home.robertbalm.com` -> proxy host to Synology backend
- `ollama.home.robertbalm.com` -> proxy to Ollama API
- `webui.home.robertbalm.com` -> proxy to Open WebUI
- `heimdall.home.robertbalm.com` -> proxy/dashboard host
- `macpro.home.robertbalm.com` -> direct Proxmox UI certificate
- `jellyfin.home.robertbalm.com` -> proxy to media host
- `proxy.home.robertbalm.com` -> NPM admin route
- `paperless.home.robertbalm.com` -> proxy to Paperless
- `recipes.home.robertbalm.com` -> proxy to Mealie
- `books.home.robertbalm.com` -> proxy to Audiobookshelf
- `thunderbluff.home.robertbalm.com` -> Synology DSM direct cert
- `elwynnforest.home.robertbalm.com` -> Synology DSM direct cert
- `radarr.home.robertbalm.com`, `sonarr.home.robertbalm.com`, `prowlarr.home.robertbalm.com`, `qbittorrent.home.robertbalm.com` -> shared ARR proxy certificate
- `familieboten.home.robertbalm.com` -> externally managed Caddy cert, tracked by HCM live probe
- `paperclip.home.robertbalm.com` -> valid certificate but app route currently returns 502 because the VM root filesystem is full
- `alertmanager.home.robertbalm.com` -> proxy route with valid HCM-issued certificate
- `reolink.home.robertbalm.com` -> proxy route with valid HCM-issued certificate

Candidate or unresolved HCM entries:

- `unifi.home.robertbalm.com`: candidate, unresolved in LAN DNS
- `printer.home.robertbalm.com`: candidate, unresolved in LAN DNS
- `reolink-25.home.robertbalm.com`: candidate, unresolved in LAN DNS
- `reolink-172.home.robertbalm.com`: candidate, unresolved in LAN DNS

Unknown/unidentified raw services tracked by HCM for investigation:

- `10.0.0.20:3000`
- `10.0.0.41:443`
- `10.0.0.98:80`
- `10.0.0.122:80`
- `10.0.0.178:80`
- `10.0.0.211:80`
- `10.0.0.221:80`
- `10.0.0.222:8000`
- `10.0.0.244:3000`

Interpretation:

- TLS coverage for named services is good.
- The remaining meaningful security work is classification, exposure explanation, raw-IP cleanup, auth posture, and exception management.
- HCM already contains valuable context that HomelabSec should ingest rather than rediscover.

### Nginx Proxy Manager Routes

NPM contains two generations of route posture:

1. legacy `stormwind.local` routes without SSL forcing or custom cert binding; and
2. newer `home.robertbalm.com` routes with custom certs, force-SSL, and mostly `block_exploits` enabled.

Examples of newer routes with better posture:

- `heimdall.home.robertbalm.com`
- `portainer.home.robertbalm.com`
- `jellyfin.home.robertbalm.com`
- `hcm.home.robertbalm.com`
- `paperless.home.robertbalm.com`
- `radarr.home.robertbalm.com`
- `sonarr.home.robertbalm.com`
- `prowlarr.home.robertbalm.com`
- `qbittorrent.home.robertbalm.com`
- `ollama.home.robertbalm.com`
- `webui.home.robertbalm.com`
- `reolink.home.robertbalm.com`
- `proxy.home.robertbalm.com`
- `recipes.home.robertbalm.com`
- `books.home.robertbalm.com`
- `grist.home.robertbalm.com`
- `alertmanager.home.robertbalm.com`

Examples of older/local routes with weaker posture:

- `recipes.stormwind.local`
- `portainer.stormwind.local`
- `books.stormwind.local`
- `home.stormwind.local`
- `proxy.stormwind.local`
- `pdfs.stormwind.local`
- `rancher.stormwind.local`
- `heimdall.stormwind.local`
- `ollama.stormwind.local`
- `grist.stormwind.local`
- `paperless.stormwind.local`

Interpretation:

- HomelabSec should show route-generation drift: old local routes may still be useful internally, but they bypass the certificate policy and can confuse users about the supported access path.
- Route risk should be computed per domain, not per backend only. One backend can have both a hardened named route and a raw/legacy route.

### Heimdall Dashboard Links

Heimdall currently mixes preferred named HTTPS routes with raw IP and legacy local links.

Good named HTTPS links:

- Alertmanager
- Audiobookshelf
- Hermes Agent / Faye
- HCM
- Jellyfin
- Mealie
- Nginx Proxy Manager
- Open WebUI
- Paperclip
- Paperless
- Portainer
- Reolink
- Synology DSM entries
- Trading Team

Raw IP or legacy links that should be tracked as dashboard hygiene issues:

- AMP: `10.0.0.154:8080`
- AlbyHub: `thunderbluff.stormwind.local:59000`
- Bitcoin Node: `thunderbluff.stormwind.local:2100`
- Grafana: `10.0.0.60:3340`
- HomeAssistant: `10.0.0.60:8123`
- Lightning node: `thunderbluff.stormwind.local:2101`
- NetVisor: `10.0.0.124:60072`
- Ollama Fleet Monitor: raw `10.0.0.110:8090` even though HCM has a named route
- Prowlarr: raw `10.0.0.60:9696` even though HCM/NPM has a named route
- Proxmox: raw `10.0.0.84:8006` even though HCM has a named route
- Radarr: raw `10.0.0.60:7878` even though HCM/NPM has a named route
- Sonarr: raw `10.0.0.60:8989` even though HCM/NPM has a named route
- Stirling-PDF: `pdfs.stormwind.local`
- Umbrel: `thunderbluff.stormwind.local:3253`
- Wazuh: `10.0.0.35`
- Webmin entries: raw host/IP admin ports
- qBittorrent: raw `10.0.0.60:8090` even though HCM/NPM has a named route

Interpretation:

- Heimdall is a strong source of operator intent. If a link exists there, the service matters.
- HomelabSec should detect when Heimdall points to a raw IP/legacy hostname while a preferred HCM/NPM route exists.
- This is a low-risk, high-clarity dashboard feature: “launcher link does not match preferred secure route.”

### DNS Alignment

For checked HCM domains, default resolver and Synology resolver matched.

Expected proxy-fronted names resolve to `10.0.0.17`, including:

- HCM
- Portainer
- Ollama API
- Open WebUI
- Heimdall
- Jellyfin
- proxy/NPM
- Paperless
- recipes
- books
- ARR apps
- Alertmanager
- Reolink

Expected direct/service-local names resolve to their service hosts, including:

- Trading Team -> `10.0.0.153`
- Faye/Hermes -> `10.0.0.182`
- Ollama Fleet -> `10.0.0.110`
- Proxmox Mac Pro -> `10.0.0.84`
- Thunderbluff DSM -> `10.0.0.60`
- ElwynnForest DSM -> `10.0.0.14`
- Familieboten -> `10.0.0.179`
- Paperclip -> `10.0.0.36`

Unresolved candidate names:

- UniFi gateway
- printer
- per-device Reolink candidate names

Interpretation:

- DNS is currently aligned for active managed routes.
- Candidate HCM records should be treated as planned/incomplete, not failures.
- HomelabSec should differentiate “tracked candidate with no DNS” from “production route missing DNS.”

## Threat / Exposure Map

### Tier 0: Boundary And Control Plane

Assets:

- Gateway / router
- Synology DNS/NAS
- proxy/dashboard host running NPM and Heimdall
- HCM/monitoring host
- Proxmox host

Risks:

- DNS and proxy misalignment can silently bypass intended TLS/auth paths.
- NPM admin route exists as a named service; useful but high-value.
- Webmin and admin surfaces exist on raw IP/port links.
- NAS/DNS hosts expose multiple admin and storage protocols.

Recommended dashboard treatment:

- “Control plane” label.
- Flag every open admin port.
- Show whether access is raw-only, named HTTPS, or both.
- Require a documented owner/purpose for each control-plane service.

### Tier 1: Identity, Auth, And Remote Execution

Assets:

- HomelabSec auth/session system
- optional secure edge / OIDC overlay
- Lynis remote runner
- SSH targets across many hosts

Risks:

- Default admin credentials must never survive beyond local UAT.
- `AUTH_SECURE_COOKIES=false` is acceptable only for trusted local/basic deployments, not exposed deployments.
- Remote runner needs tight trust boundaries: credentials, sudo, command construction, timeout, and redaction.

Recommended dashboard treatment:

- Deployment mode card: trusted LAN, basic-auth edge, OIDC edge.
- Cookie security card: secure cookie expected when HTTPS edge is enabled.
- Remote runner card: count enabled targets, sudo targets, password-backed targets, and last audit result.
- Never display secret values.

### Tier 2: App And Media Surfaces

Assets:

- Jellyfin
- ARR stack
- qBittorrent
- Paperless
- Mealie
- Audiobookshelf
- HomeAssistant
- Grafana
- Umbrel/Lightning/Bitcoin services

Risks:

- Mixed raw and named links create accidental bypasses.
- qBittorrent and ARR apps deserve stronger access review because they often touch external content sources.
- Media/app host `10.0.0.60` has a dense port surface.

Recommended dashboard treatment:

- Service group heatmap by host.
- Raw-link hygiene warnings.
- External-content/service class tag for torrent/indexer/media automation tools.
- “Preferred URL” recommendation based on HCM/NPM/Heimdall correlation.

### Tier 3: AI And Automation Surfaces

Assets:

- Ollama API
- Open WebUI
- Ollama Fleet Monitor
- Faye/Hermes dashboard
- Trading Team dashboard

Risks:

- LLM/automation services can become high-impact if reachable beyond intended users.
- Raw API surfaces need special treatment even if LAN-only.
- Dashboard routes should advertise mode, access path, and auth posture.

Recommended dashboard treatment:

- AI/automation category.
- Flag unauthenticated API-style services separately from web apps.
- Show whether route is proxied through NPM, direct Caddy/service-local TLS, or raw.

### Tier 4: Devices And Unknowns

Assets:

- Reolink devices
- Brother printer
- unknown HTTP/HTTPS/gSOAP services
- devices exposing 8000/9000-style web/API ports

Risks:

- Unknown web services are impossible to reason about.
- Device web UIs often have weak TLS/auth/update posture.
- Camera and printer routes should be intentional and documented.

Recommended dashboard treatment:

- Unknown service queue.
- Device class with confidence, evidence, and “needs owner confirmation.”
- Candidate DNS/cert state distinct from production failure.

## Product Dashboard Spec

### New Dashboard Page: Exposure Map

Add a first-class dashboard view called `Exposure Map`.

Core cards:

1. `Live hosts`
   - count of hosts seen in latest scan
   - new/lost hosts since previous scan
   - confidence: observed by ping, ARP, TCP, DNS, HCM, NPM, Heimdall

2. `Open services`
   - count of open TCP services
   - high-risk admin/service ports by category
   - services newly opened/closed since previous scan

3. `Preferred route coverage`
   - services with named HTTPS route
   - services with raw-only access
   - services with both raw and named access
   - services with launcher link not matching preferred route

4. `TLS health`
   - valid certificates
   - expiring certificates
   - unresolved candidates
   - externally managed certificates tracked by live probe

5. `Unknown queue`
   - unknown services discovered by scan/HCM
   - confidence and evidence fields
   - recommended next action: identify, ignore, route, block, document

6. `Control-plane risk`
   - gateway, DNS/NAS, proxy, Proxmox, monitoring, admin tools
   - raw admin ports
   - named admin routes
   - missing or stale documentation

### Data Model Additions

Add normalized source tables or equivalent records for:

#### `route_inventory`

Fields:

- `source`: `npm`, `hcm`, `heimdall`, `dns`, `manual`
- `service_name`
- `domain`
- `url`
- `scheme`
- `frontdoor_host`
- `backend_host`
- `backend_port`
- `certificate_status`
- `certificate_days_left`
- `proxy_flags`: force SSL, HTTP/2, websocket, block exploits
- `route_status`: active, candidate, unresolved, legacy, stale
- `last_seen_at`

#### `dns_observations`

Fields:

- `domain`
- `resolver`
- `answers`
- `expected_answer`
- `status`: aligned, mismatch, missing, candidate_missing
- `last_checked_at`

#### `launcher_links`

Fields:

- `source`: `heimdall`
- `title`
- `url`
- `resolved_host`
- `route_match_status`: preferred, raw_ip, legacy_host, stale, category_folder
- `preferred_url`
- `last_seen_at`

#### `exposure_findings`

Fields:

- `finding_id`
- `severity`: info, low, medium, high, critical
- `asset_id`
- `service_key`
- `category`
- `title`
- `evidence`
- `recommended_action`
- `status`: open, accepted, resolved, ignored
- `first_seen_at`
- `last_seen_at`

### Correlation Rules

Implement these rules first because they are directly supported by the current live inventory.

#### Rule: Heimdall raw link when preferred route exists

If Heimdall URL is raw IP or legacy local hostname, and HCM/NPM has a valid named route for the same known app, create a medium finding.

Examples from current inventory:

- Ollama Fleet Monitor should prefer `https://ollamafleet.home.robertbalm.com/`
- Proxmox should prefer `https://macpro.home.robertbalm.com:8006/`
- Radarr should prefer `https://radarr.home.robertbalm.com/`
- Sonarr should prefer `https://sonarr.home.robertbalm.com/`
- Prowlarr should prefer `https://prowlarr.home.robertbalm.com/`
- qBittorrent should prefer `https://qbittorrent.home.robertbalm.com/`

#### Rule: Legacy NPM route active

If NPM contains an active `stormwind.local` route with no cert/force-SSL while a newer `home.robertbalm.com` route exists for the same service class, create a low/medium hygiene finding.

Severity should be medium for admin surfaces, low for benign internal-only app redirects.

#### Rule: Dense host exposure

If a host has more than a threshold of open services, create an informational or medium finding depending on service classes.

Current high-density examples:

- `10.0.0.60`: NAS/media/app surface
- `10.0.0.17`: proxy/dashboard/admin surface
- `10.0.0.110`: HCM/monitoring surface
- `10.0.0.14`: NAS/DNS surface

#### Rule: Unknown web service

If scan/HCM discovers HTTP/HTTPS/gSOAP service with unknown identity, create a medium finding until identified.

Examples include the HCM unknown queue and scan observations on device-style ports 8000/9000.

#### Rule: Candidate DNS missing

If HCM marks a target as candidate and DNS is missing, create an info finding, not a failure.

If a target is marked done/managed/routed and DNS is missing or mismatched, create a high finding.

#### Rule: Valid cert but bad backend

If certificate is valid but app route fails, create a medium/high application availability finding.

Current example:

- Paperclip has a valid live certificate but returns 502 because the VM root filesystem is full.

### UX Requirements

The dashboard should make the operator answer these questions in one screen:

- What changed since yesterday?
- Which hosts have the most exposed services?
- Which services are exposed by raw IP/legacy hostnames instead of preferred HTTPS routes?
- Which TLS routes are valid, expiring, missing, or externally managed?
- Which unknown services need identification?
- Which findings are accepted risk vs unresolved work?

Recommended layout:

1. Top summary cards.
2. Host/service heatmap.
3. Route coverage table.
4. TLS/DNS health table.
5. Heimdall hygiene table.
6. Unknown services queue.
7. Finding detail drawer with evidence and recommended action.

### API Requirements

Add read-only endpoints first:

- `GET /exposure/summary`
- `GET /exposure/hosts`
- `GET /exposure/routes`
- `GET /exposure/dns`
- `GET /exposure/launcher-links`
- `GET /exposure/findings`

Later mutation endpoints:

- `POST /exposure/findings/{id}/accept`
- `POST /exposure/findings/{id}/resolve`
- `POST /exposure/findings/{id}/ignore`
- `POST /exposure/services/{id}/preferred-url`

### Collector Requirements

Add collectors in small slices:

1. NPM collector:
   - read active non-secret route fields from NPM API or database export
   - never ingest cert `meta` secrets
   - store proxy flags and backend mapping

2. HCM collector:
   - ingest target/cert public status from HCM API
   - store plan status, live status, days left, route/backend URL

3. Heimdall collector:
   - ingest active launcher titles and URLs
   - classify raw IP, legacy local hostname, category folder, named HTTPS

4. DNS collector:
   - resolve HCM/NPM domains through configured resolvers
   - compare default resolver and authoritative resolver where configured

5. Exposure correlator:
   - join Nmap observations, DNS, routes, launcher links, and TLS status
   - write durable findings with first/last seen timestamps

### Security Requirements For Collectors

- Collectors must default to read-only.
- NPM collector must explicitly avoid secret-bearing columns/fields such as certificate metadata and provider tokens.
- Heimdall collector should avoid scraping credentials or session tables; only launcher item titles/URLs are needed.
- DNS collector should not require write access.
- SSH-based collectors should support least-privilege commands and clear failure states.
- Findings must redact secrets and avoid printing private keys, passwords, cookies, tokens, or full secret-bearing environment values.

## Recommended Next Work

### P0: Build Exposure Map Data Model And Read-Only API

Why:

- The repo already discovers hosts and stores fingerprints.
- The missing layer is cross-source route/security context.

Deliver:

- migration for route/DNS/launcher/finding tables
- read-only API endpoints
- unit tests for serializers and correlation rules

### P1: Add NPM + HCM Collectors

Why:

- These two sources give the strongest immediate insight into TLS and route posture.

Deliver:

- read-only NPM collector with secret-safe field allowlist
- HCM collector from public/internal API
- correlation rule for route posture and TLS status

### P1: Add Heimdall Hygiene Collector

Why:

- Heimdall captures what the operator actually clicks.
- Raw/legacy links are a concrete, fixable risk.

Deliver:

- launcher link ingest
- preferred route matching
- findings for raw links when a named route exists

### P2: Add DNS Alignment Collector

Why:

- Split-horizon DNS mistakes are a repeated homelab risk and can silently bypass the proxy.

Deliver:

- configured resolver checks
- candidate vs production route distinction
- mismatch findings

### P2: Add Exposure Map UI

Why:

- The value of the product is operational clarity.

Deliver:

- summary cards
- host/service heatmap
- route/TLS/DNS/launcher tables
- findings queue

### P3: Add Guided Remediation

Why:

- Once findings are reliable, the dashboard can recommend safe changes.

Deliver:

- “update Heimdall link” playbook text
- “retire legacy NPM route” checklist
- “identify unknown service” workflow
- “accept risk” status tracking

## Definition Of Done For This Product Slice

- Unit tests cover route and finding classifiers.
- Integration test ingests fixture Nmap XML plus fixture HCM/NPM/Heimdall/DNS payloads.
- Dashboard contract tests verify new exposure endpoints.
- No collector reads known secret-bearing fields.
- README documents source setup and security boundaries.
- A sample exposure report can be generated from fixtures without live homelab access.
- Live collector failures are shown as source health warnings, not whole-dashboard failures.

## Immediate Manual Findings From This Run

Open findings to track or convert into HomelabSec fixtures:

1. Heimdall raw links exist for services that already have named HTTPS routes.
2. Legacy `stormwind.local` NPM routes remain active alongside newer `home.robertbalm.com` routes.
3. Multiple unknown HTTP/HTTPS/gSOAP services remain unidentified.
4. Paperclip has valid TLS but an unhealthy backend route due to a full root filesystem.
5. Dense service exposure exists on the NAS/media/app host, proxy/dashboard host, HCM/monitoring host, and DNS/NAS host.
6. Candidate DNS entries for UniFi/printer/per-device Reolink are intentionally unresolved and should be represented as planned candidates, not production failures.

## Verification Notes

Commands used during this assessment included:

- `git status --short`
- `git branch --show-current`
- `git log --oneline -5`
- `pygount --format=summary --folders-to-skip='.git,.venv,__pycache__,.pytest_cache,dist,build,node_modules' .`
- HCM API reads from `/api/targets` and `/api/certs`
- NPM active route read with a non-secret SQL column allowlist
- Heimdall active item read from copied SQLite DB
- `dig +short` through default resolver and Synology DNS resolver
- `nmap -sn 10.0.0.0/24`
- `nmap -T3 --open -sT` for selected admin/app/media/monitoring ports
