# HomelabSec v0.2.0 Release Notes

Release date: `2026-04-09`

Version: `0.2.0`

Git tag: `v0.2.0`

## Overview

`v0.2.0` builds on the initial HomelabSec release by improving classification speed, dashboard usability, and operator workflows.

This release adds:

- learned lookup-first classification with LLM fallback
- visibility into learned lookup entries and confidence
- a significantly improved dashboard inventory experience
- asset detail views with exposed-service and learned-lookup context
- queued focused rescans for individual assets

## Major Features

### Lookup-first classification

Classification now checks a learned lookup table before calling Ollama.

- repeated scans can classify faster
- similar hosts can reuse learned roles
- learned entries retain confidence, source, and sample count
- low-confidence entries remain visible for operator review

Relevant additions:

- `brain/migrations/0002_classification_lookup.sql`
- `GET /classification_lookup`

### Asset inventory improvements

The asset inventory is now a stronger operator view instead of a passive table.

- unified inventory table with notable-asset tagging
- `shown/total` counter
- confidence pills with guidance
- confidence-color filters
- sortable columns
- clearer visual hierarchy and improved admin panel readability

### Asset detail pages

Each asset can now be opened in a dedicated detail screen.

The detail page includes:

- core asset metadata
- identifiers
- exposed services
- latest fingerprint context
- matching learned lookup entry
- latest queued rescan status

### Focused rescans

Operators can now queue a targeted rescan for one asset.

This flow:

1. queues a rescan request in Postgres
2. lets the scheduler claim the request
3. runs a focused Nmap scan against the asset’s latest known IP
4. re-ingests results
5. reclassifies the asset
6. reruns change detection for that asset

Relevant additions:

- `brain/migrations/0003_rescan_requests.sql`
- `POST /rescan/{asset_id}`
- `GET /assets/{asset_id}`

## API Additions

New endpoints introduced since `v0.1.0`:

- `GET /classification_lookup`
- `GET /assets/{asset_id}`
- `POST /rescan/{asset_id}`

Internal scheduler queue endpoints:

- `POST /rescan_requests/claim`
- `POST /rescan_requests/{request_id}/complete`

Existing endpoints remain in place.

## UX And Operations

This release also improves the operator-facing experience:

- more readable dashboard styling
- clearer admin status presentation
- improved inventory filtering and sorting
- hover guidance for classification confidence

## Testing

The release is covered by:

- unit tests
- integration tests
- regression tests
- compose smoke tests

Verification status during release prep:

- `python3 -m pytest`
- result: `54 passed`

## Versioning

The release version source of truth remains:

- `brain/VERSION`

This release updates the current version from `0.1.0` to `0.2.0`.
