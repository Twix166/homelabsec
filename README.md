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