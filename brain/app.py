import os
import json
import hashlib
from datetime import datetime, timezone
from typing import Any

import psycopg
import requests
from fastapi import FastAPI

DATABASE_URL = os.environ["DATABASE_URL"]
OLLAMA_URL = os.environ["OLLAMA_URL"].rstrip("/")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen3:8b-q4_K_M")

app = FastAPI(title="HomelabSec Brain")


def db():
    return psycopg.connect(DATABASE_URL)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/ingest/sample")
def ingest_sample() -> dict[str, Any]:
    return {"accepted": True, "message": "brain is alive"}


@app.post("/ollama/test")
def ollama_test() -> dict[str, Any]:
    payload = {
        "model": OLLAMA_MODEL,
        "format": "json",
        "stream": False,
        "messages": [
            {
                "role": "system",
                "content": (
                    "Return strict JSON only with keys role and confidence. "
                    "Do not add any other text."
                ),
            },
            {
                "role": "user",
                "content": (
                    "Classify a host with ports 22, 80, 443 and nginx detected."
                ),
            },
        ],
    }
    r = requests.post(f"{OLLAMA_URL}/api/chat", json=payload, timeout=120)
    r.raise_for_status()
    return r.json()


@app.get("/report/summary")
def report_summary() -> dict[str, Any]:
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM assets")
            assets = cur.fetchone()[0]
            cur.execute("SELECT count(*) FROM findings")
            findings = cur.fetchone()[0]
            cur.execute("SELECT count(*) FROM changes")
            changes = cur.fetchone()[0]
    return {"assets": assets, "findings": findings, "changes": changes}
