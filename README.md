# HomelabSec

HomelabSec is a local homelab security inventory and monitoring system.

It currently supports:

- LAN discovery with Nmap
- ingest of Nmap XML into Postgres
- asset fingerprinting
- local AI classification via Ollama
- fingerprint history
- change persistence
- daily reporting

## Current status

This repo is at the stage where it can:

1. discover LAN assets
2. ingest network scan results
3. build per-asset fingerprints
4. classify assets using a custom Ollama model
5. persist changes into the `changes` table
6. generate a `/report/daily` summary

## Requirements

- Linux host
- Docker
- Docker Compose
- Git
- Curl
- Ollama running locally on the host
- An installed classifier model such as `homelabsec-classifier`

## Quick install

You can install directly from GitHub with:

```bash
curl -fsSL https://raw.githubusercontent.com/Twix166/homelabsec/main/install.sh | bash
```

## Web dashboard

A read-only web dashboard is available from the `frontend` service on port `8080`.

Start the stack from [compose/compose.yaml](/home/rbalm/homelabsec/compose/compose.yaml):

```bash
cd compose
docker compose up -d --build
```

Then open:

```text
http://localhost:8080
```

The frontend proxies API requests internally to the `brain` service, so no backend changes are required.

## API usage

The API is exposed by the `brain` service on port `8088`.

Classify a single asset:

```bash
curl -X POST http://localhost:8088/classify/<asset_id>
```

Example response:

```json
{
  "asset_id": "7d0d0a6f-4f7a-4a30-8b56-0f3b0aa9d9ab",
  "classification": {
    "role": "nas",
    "confidence": 0.97
  },
  "fingerprint": {},
  "fingerprint_store": {
    "changed": false
  },
  "raw_model_output": null
}
```

Classify all known assets:

```bash
curl -X POST http://localhost:8088/classify_all
```

Example response:

```json
{
  "total_assets": 12,
  "classified_ok": 12,
  "errors": 0,
  "failed": []
}
```
