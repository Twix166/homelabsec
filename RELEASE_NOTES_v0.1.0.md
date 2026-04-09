# HomelabSec v0.1.0 Release Notes

Release date: 2026-04-09

Version: `0.1.0`

Git tag: `v0.1.0`

## Overview

`v0.1.0` is the first tagged HomelabSec release. It establishes the project as a working homelab security inventory and monitoring platform with:

- Nmap-based asset discovery and ingest
- asset fingerprinting and change detection
- local AI-assisted classification through Ollama
- daily and summary reporting
- a read-only operator dashboard
- Docker Compose deployment paths for local, exposed, and monitored operation

## Included Capabilities

### Core asset workflow

- ingest of Nmap XML into Postgres
- asset normalization and identifier tracking
- fingerprint storage and fingerprint history
- per-asset and bulk classification
- change persistence with idempotent duplicate protection
- daily report and summary report endpoints

### API surface

Available primary endpoints in this release include:

- `/health`
- `/version`
- `/ingest/nmap_xml`
- `/assets`
- `/observations`
- `/fingerprints`
- `/fingerprint/{asset_id}`
- `/classify/{asset_id}`
- `/classify_all`
- `/detect_changes`
- `/detect_changes/{asset_id}`
- `/report/daily`
- `/report/summary`
- `/admin/status`
- `/metrics`

### Dashboard and operator UX

- read-only frontend dashboard
- clickable summary cards with detail listings
- admin status panel with API version, scheduler freshness, and quick links
- helper scripts for secure edge startup and access URL discovery

### Deployment and operations

- Compose project name standardized to `homelabsec`
- Dockerized `brain`, `scheduler`, `frontend`, monitoring, and edge services
- Postgres bootstrap plus versioned SQL migration workflow
- installer with health and Ollama validation
- optional secure edge overlay with TLS and proxy auth
- optional OIDC overlay for stronger auth
- Prometheus, Grafana, and Alertmanager overlays
- provisioned dashboards and alert rules
- backup and restore helper scripts

## Quality and verification

This release includes:

- unit tests
- integration tests
- regression tests
- compose smoke tests
- monitoring smoke coverage
- workflow smoke coverage
- backup and restore round-trip verification

Latest verification status at tag creation:

- `47 passed`

## Versioning

This release introduces semantic versioning for HomelabSec.

Version source of truth:

- `brain/VERSION`

Runtime version visibility:

- `GET /version`
- `/admin/status`

## Notes

- This release is suitable for trusted homelab and admin-network use.
- Exposed deployments should use the secure edge path rather than publishing the default stack directly.
- On systems where default edge ports are unavailable, `run_secure_edge.sh` selects fallback ports automatically.
