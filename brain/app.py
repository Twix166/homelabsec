import time
import sys
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi import Request, Response
from pydantic import BaseModel

APP_DIR = Path(__file__).resolve().parent
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

from brainlib.admin import admin_status
from brainlib.assets import NmapXmlError, normalize_role, parse_nmap_xml
from brainlib.changes import detect_changes_all as detect_changes_all_records
from brainlib.changes import detect_changes_for_asset as detect_changes_for_asset_record
from brainlib.classification import classify_all_assets, classify_asset as classify_asset_record
from brainlib.classification import list_classification_lookup_entries
from brainlib.database import db
from brainlib.errors import bad_gateway, bad_request, not_found
from brainlib.fingerprints import (
    classification_lookup_signature,
    classification_lookup_signature_hash,
    diff_fingerprints,
    fingerprint_hash,
)
from brainlib.ingest import ingest_nmap_xml as ingest_nmap_xml_record
from brainlib.inventory import fingerprint_detail, list_assets as list_assets_records
from brainlib.inventory import list_fingerprints as list_fingerprints_records
from brainlib.inventory import list_observations as list_observations_records
from brainlib.logging_utils import configure_logging, log_event
from brainlib.metrics import record_http_request
from brainlib.ollama import OllamaError
from brainlib.reports import daily_report, summary_report
from brainlib.system import health_status, metrics_payload, ollama_test_payload, version_status

app = FastAPI(title="HomelabSec Brain")
logger = configure_logging("homelabsec.brain")


class NmapXmlIngestRequest(BaseModel):
    xml_path: str


@app.middleware("http")
async def log_requests(request: Request, call_next):
    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        duration_seconds = time.perf_counter() - started
        duration_ms = round(duration_seconds * 1000, 2)
        record_http_request(request.method, request.url.path, 500, duration_seconds)
        log_event(
            logger,
            "error",
            "http_request",
            "Request failed",
            method=request.method,
            path=request.url.path,
            status_code=500,
            duration_ms=duration_ms,
        )
        raise

    duration_seconds = time.perf_counter() - started
    duration_ms = round(duration_seconds * 1000, 2)
    record_http_request(request.method, request.url.path, response.status_code, duration_seconds)
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
    return health_status()


@app.get("/metrics")
def metrics():
    return Response(metrics_payload(), media_type="text/plain; version=0.0.4; charset=utf-8")


@app.get("/version")
def version():
    return version_status()


@app.post("/ollama/test")
def ollama_test() -> dict[str, Any]:
    try:
        return ollama_test_payload()
    except OllamaError as exc:
        raise bad_gateway(str(exc)) from exc


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
        return list_assets_records(conn)


@app.get("/observations")
def list_observations():
    with db() as conn:
        return list_observations_records(conn)


@app.get("/fingerprints")
def list_fingerprints():
    with db() as conn:
        return list_fingerprints_records(conn)


@app.get("/classification_lookup")
def list_classification_lookup():
    with db() as conn:
        return list_classification_lookup_entries(conn)


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
        return fingerprint_detail(conn, asset_id)


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


@app.get("/admin/status")
def admin_status_view():
    with db() as conn:
        return admin_status(conn)


@app.post("/classify_all")
def classify_all():
    with db() as conn:
        return classify_all_assets(conn, lambda asset_id: classify_asset_record(conn, asset_id))
