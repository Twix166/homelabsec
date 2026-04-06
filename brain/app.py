import json
import time
import sys
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi import Request
from pydantic import BaseModel

APP_DIR = Path(__file__).resolve().parent
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

from brainlib.assets import NmapXmlError, get_or_create_asset, normalize_role, parse_nmap_xml
from brainlib.changes import detect_changes_all as detect_changes_all_records
from brainlib.changes import detect_changes_for_asset as detect_changes_for_asset_record
from brainlib.classification import classify_all_assets, classify_asset as classify_asset_record
from brainlib.config import FINGERPRINTS_LIST_LIMIT, OBSERVATIONS_LIST_LIMIT
from brainlib.database import db
from brainlib.errors import bad_gateway, bad_request, not_found
from brainlib.fingerprints import (
    detect_and_persist_changes_for_asset,
    diff_fingerprints,
    fingerprint_hash,
    get_latest_fingerprint,
    get_previous_fingerprint,
    persist_changes,
)
from brainlib.ingest import ingest_nmap_xml as ingest_nmap_xml_record
from brainlib.logging_utils import configure_logging, log_event
from brainlib.ollama import OllamaError, chat_json
from brainlib.reports import daily_report, summary_report

app = FastAPI(title="HomelabSec Brain")
logger = configure_logging("homelabsec.brain")


class NmapXmlIngestRequest(BaseModel):
    xml_path: str


@app.middleware("http")
async def log_requests(request: Request, call_next):
    started = time.perf_counter()
    response = await call_next(request)
    duration_ms = round((time.perf_counter() - started) * 1000, 2)
    log_event(
        logger,
        "info",
        "http_request",
        "Request completed",
        method=request.method,
        path=request.url.path,
        status_code=response.status_code,
        duration_ms=duration_ms,
    )
    return response



@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/ollama/test")
def ollama_test() -> dict[str, Any]:
    try:
        data = chat_json(
            [
                {
                    "role": "system",
                    "content": "Return strict JSON only with keys role and confidence.",
                },
                {
                    "role": "user",
                    "content": "Classify a host with ports 22, 80, 443 and nginx detected.",
                },
            ]
        )
    except OllamaError as exc:
        raise bad_gateway(str(exc)) from exc

    content = data["message"]["content"]
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError:
        parsed = {"raw_content": content}
    return {"model": data.get("model"), "result": parsed}


@app.post("/ingest/nmap_xml")
def ingest_nmap_xml(req: NmapXmlIngestRequest):
    try:
        with db() as conn:
            return ingest_nmap_xml_record(conn, req.xml_path)
    except FileNotFoundError as exc:
        raise not_found("XML file not found") from exc
    except NmapXmlError as exc:
        raise bad_request(str(exc)) from exc


@app.get("/assets")
def list_assets():
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT asset_id, preferred_name, role, role_confidence, first_seen, last_seen
                FROM assets
                ORDER BY last_seen DESC
                """
            )
            rows = cur.fetchall()

    return {
        "assets": [
            {
                "asset_id": str(r[0]),
                "preferred_name": r[1],
                "role": r[2],
                "role_confidence": float(r[3]) if r[3] is not None else None,
                "first_seen": r[4].isoformat(),
                "last_seen": r[5].isoformat(),
            }
            for r in rows
        ]
    }


@app.get("/observations")
def list_observations():
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    o.observation_id,
                    o.asset_id,
                    a.preferred_name,
                    o.ip_address,
                    o.mac_address,
                    o.port,
                    o.protocol,
                    o.service_name,
                    o.service_product,
                    o.service_version,
                    o.os_guess,
                    o.observed_at
                FROM network_observations o
                LEFT JOIN assets a ON a.asset_id = o.asset_id
                ORDER BY o.observed_at DESC, o.observation_id DESC
                LIMIT %s
                """,
                (OBSERVATIONS_LIST_LIMIT,),
            )
            rows = cur.fetchall()

    return {
        "observations": [
            {
                "observation_id": str(r[0]),
                "asset_id": str(r[1]) if r[1] is not None else None,
                "preferred_name": r[2],
                "ip_address": str(r[3]) if r[3] is not None else None,
                "mac_address": str(r[4]) if r[4] is not None else None,
                "port": r[5],
                "protocol": r[6],
                "service_name": r[7],
                "service_product": r[8],
                "service_version": r[9],
                "os_guess": r[10],
                "observed_at": r[11].isoformat(),
            }
            for r in rows
        ]
    }


@app.get("/fingerprints")
def list_fingerprints():
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    f.fingerprint_id,
                    f.asset_id,
                    a.preferred_name,
                    a.role,
                    f.fingerprint_hash,
                    f.created_at
                FROM fingerprints f
                JOIN assets a ON a.asset_id = f.asset_id
                ORDER BY f.created_at DESC, f.fingerprint_id DESC
                LIMIT %s
                """,
                (FINGERPRINTS_LIST_LIMIT,),
            )
            rows = cur.fetchall()

    return {
        "fingerprints": [
            {
                "fingerprint_id": str(r[0]),
                "asset_id": str(r[1]),
                "preferred_name": r[2],
                "role": r[3],
                "fingerprint_hash": r[4],
                "created_at": r[5].isoformat(),
            }
            for r in rows
        ]
    }


@app.post("/classify/{asset_id}")
def classify_asset(asset_id: str):
    with db() as conn:
        try:
            return classify_asset_record(conn, asset_id)
        except OllamaError as exc:
            raise bad_gateway(str(exc)) from exc

@app.get("/fingerprint/{asset_id}")
def get_fingerprint(asset_id: str):
    with db() as conn:
        latest = get_latest_fingerprint(conn, asset_id)

        if latest is None:
            raise not_found("No fingerprint found for asset")

        return {
            "asset_id": asset_id,
            "fingerprint_hash": latest["fingerprint_hash"],
            "created_at": latest["created_at"],
            "fingerprint": latest["fingerprint"],
        }
    
@app.get("/detect_changes/{asset_id}")
def detect_changes_for_asset(asset_id: str):
    with db() as conn:
        return detect_changes_for_asset_record(conn, asset_id)

@app.get("/detect_changes")
def detect_changes_all():
    with db() as conn:
        return detect_changes_all_records(conn)

@app.get("/report/daily")
def report_daily():
    with db() as conn:
        return daily_report(conn)

@app.get("/report/summary")
def report_summary():
    with db() as conn:
        return summary_report(conn)

@app.post("/classify_all")
def classify_all():
    with db() as conn:
        return classify_all_assets(conn, lambda asset_id: classify_asset_record(conn, asset_id))
