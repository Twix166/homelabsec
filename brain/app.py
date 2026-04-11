import time
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi import Request, Response
from pydantic import BaseModel

APP_DIR = Path(__file__).resolve().parent
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

from brainlib.admin import admin_status
from brainlib.admin_console import (
    is_raw_data_source_enabled,
    list_enrichment_modules,
    list_raw_data_sources,
    update_enrichment_module,
    update_raw_data_source,
)
from brainlib.assets import NmapXmlError, normalize_role, parse_nmap_xml
from brainlib.auth import (
    auth_me,
    create_user,
    login,
    logout,
    require_admin,
    update_profile,
    update_user,
    list_users,
)
from brainlib.changes import detect_changes_all as detect_changes_all_records
from brainlib.changes import detect_changes_for_asset as detect_changes_for_asset_record
from brainlib.classification import classify_all_assets, classify_asset as classify_asset_record
from brainlib.classification import list_classification_lookup_entries
from brainlib.config import COLLECTORS_ENABLED
from brainlib.database import db
from brainlib.errors import bad_gateway, bad_request, conflict, not_found
from brainlib.fingerprints import (
    classification_lookup_signature,
    classification_lookup_signature_hash,
    diff_fingerprints,
    fingerprint_hash,
)
from brainlib.ingest import ingest_nmap_xml as ingest_nmap_xml_record
from brainlib.inventory import asset_detail, fingerprint_detail, list_assets as list_assets_records
from brainlib.inventory import list_fingerprints as list_fingerprints_records
from brainlib.inventory import list_observations as list_observations_records
from brainlib.lynis import (
    claim_lynis_run,
    complete_lynis_run,
    configure_lynis_target,
    enqueue_lynis_run,
    lynis_status_for_asset,
)
from brainlib.logging_utils import configure_logging, log_event
from brainlib.metrics import record_http_request
from brainlib.ollama import OllamaError
from brainlib.reports import daily_report, summary_report
from brainlib.rescan import claim_rescan_request, complete_rescan_request, enqueue_rescan_request
from brainlib.system import health_status, metrics_payload, ollama_test_payload, version_status
from collectors.supervisor import start_collectors_once

logger = configure_logging("homelabsec.brain")


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not COLLECTORS_ENABLED:
        yield
        return
    start_collectors_once()
    yield


app = FastAPI(title="HomelabSec Brain", lifespan=lifespan)


class NmapXmlIngestRequest(BaseModel):
    xml_path: str


class LoginRequest(BaseModel):
    username: str
    password: str


class RescanCompleteRequest(BaseModel):
    status: str
    result: dict[str, Any] | None = None


class UpdateProfileRequest(BaseModel):
    display_name: str | None = None
    email: str | None = None
    current_password: str | None = None
    new_password: str | None = None


class ToggleEnabledRequest(BaseModel):
    enabled: bool


class CreateUserRequest(BaseModel):
    username: str
    password: str
    display_name: str
    email: str | None = None
    role: str = "operator"


class UpdateUserRequest(BaseModel):
    display_name: str | None = None
    email: str | None = None
    role: str | None = None
    is_active: bool | None = None
    password: str | None = None


class ConfigureLynisTargetRequest(BaseModel):
    ssh_host: str
    ssh_port: int = 22
    ssh_username: str
    ssh_password: str | None = None
    use_sudo: bool = False
    enabled: bool = True
    notes: str | None = None


class CompleteLynisRunRequest(BaseModel):
    status: str
    summary: dict[str, Any] | None = None
    report_text: str | None = None
    log_text: str | None = None
    error_text: str | None = None


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


@app.post("/auth/login")
def auth_login(payload: LoginRequest, response: Response):
    with db() as conn:
        return login(conn, response, payload.username, payload.password)


@app.post("/auth/logout")
def auth_logout(request: Request, response: Response):
    with db() as conn:
        return logout(conn, request, response)


@app.get("/auth/me")
def auth_me_view(request: Request):
    with db() as conn:
        return auth_me(conn, request)


@app.patch("/auth/me")
def auth_update_profile(payload: UpdateProfileRequest, request: Request):
    with db() as conn:
        return update_profile(
            conn,
            request,
            display_name=payload.display_name,
            email=payload.email,
            current_password=payload.current_password,
            new_password=payload.new_password,
        )


@app.post("/ingest/nmap_xml")
def ingest_nmap_xml(req: NmapXmlIngestRequest):
    try:
        with db() as conn:
            if not is_raw_data_source_enabled(conn, "nmap_xml_ingest"):
                raise conflict("Nmap XML ingest is disabled in the admin console")
            return ingest_nmap_xml_record(conn, req.xml_path)
    except FileNotFoundError as exc:
        raise not_found("XML file not found") from exc
    except NmapXmlError as exc:
        raise bad_request(str(exc)) from exc


@app.get("/assets")
def list_assets():
    with db() as conn:
        return list_assets_records(conn)


@app.get("/assets/{asset_id}")
def get_asset_detail(asset_id: str):
    with db() as conn:
        return asset_detail(conn, asset_id)


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


@app.post("/rescan/{asset_id}")
def request_asset_rescan(asset_id: str):
    with db() as conn:
        return enqueue_rescan_request(conn, asset_id)


@app.get("/assets/{asset_id}/lynis")
def get_asset_lynis_status(asset_id: str, request: Request):
    with db() as conn:
        from brainlib.auth import require_user

        require_user(conn, request)
        return lynis_status_for_asset(conn, asset_id)


@app.put("/assets/{asset_id}/lynis_target")
def configure_asset_lynis_target(asset_id: str, payload: ConfigureLynisTargetRequest, request: Request):
    with db() as conn:
        require_admin(conn, request)
        return {
            "target": configure_lynis_target(
                conn,
                asset_id,
                ssh_host=payload.ssh_host,
                ssh_port=payload.ssh_port,
                ssh_username=payload.ssh_username,
                ssh_password=payload.ssh_password,
                use_sudo=payload.use_sudo,
                enabled=payload.enabled,
                notes=payload.notes,
            )
        }


@app.post("/assets/{asset_id}/lynis/run")
def run_asset_lynis(asset_id: str, request: Request):
    with db() as conn:
        user = auth_me(conn, request)["user"]
        return enqueue_lynis_run(conn, asset_id, user["user_id"])


@app.post("/lynis_runs/claim")
def claim_next_lynis_run():
    with db() as conn:
        return claim_lynis_run(conn)


@app.post("/lynis_runs/{run_id}/complete")
def complete_asset_lynis(run_id: str, payload: CompleteLynisRunRequest):
    with db() as conn:
        return complete_lynis_run(
            conn,
            run_id,
            status=payload.status,
            summary=payload.summary,
            report_text=payload.report_text,
            log_text=payload.log_text,
            error_text=payload.error_text,
        )


@app.post("/rescan_requests/claim")
def claim_next_rescan_request():
    with db() as conn:
        return claim_rescan_request(conn)


@app.post("/rescan_requests/{request_id}/complete")
def complete_asset_rescan(request_id: str, payload: RescanCompleteRequest):
    with db() as conn:
        return complete_rescan_request(conn, request_id, status=payload.status, result=payload.result)


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
def admin_status_view(request: Request):
    with db() as conn:
        from brainlib.auth import require_user

        require_user(conn, request)
        return admin_status(conn)


@app.get("/admin/modules")
def admin_modules_view(request: Request):
    with db() as conn:
        require_admin(conn, request)
        return list_enrichment_modules(conn)


@app.patch("/admin/modules/{module_key}")
def admin_update_module(module_key: str, payload: ToggleEnabledRequest, request: Request):
    with db() as conn:
        require_admin(conn, request)
        try:
            return update_enrichment_module(conn, module_key, payload.enabled)
        except KeyError as exc:
            raise not_found("Module not found") from exc


@app.get("/admin/data_sources")
def admin_data_sources_view(request: Request):
    with db() as conn:
        require_admin(conn, request)
        return list_raw_data_sources(conn)


@app.patch("/admin/data_sources/{source_key}")
def admin_update_data_source(source_key: str, payload: ToggleEnabledRequest, request: Request):
    with db() as conn:
        require_admin(conn, request)
        try:
            return update_raw_data_source(conn, source_key, payload.enabled)
        except KeyError as exc:
            raise not_found("Raw data source not found") from exc


@app.get("/admin/users")
def admin_users_view(request: Request):
    with db() as conn:
        require_admin(conn, request)
        return list_users(conn)


@app.post("/admin/users")
def admin_create_user(payload: CreateUserRequest, request: Request):
    with db() as conn:
        require_admin(conn, request)
        return {"user": create_user(
            conn,
            username=payload.username,
            password=payload.password,
            display_name=payload.display_name,
            email=payload.email,
            role=payload.role,
        )}


@app.patch("/admin/users/{user_id}")
def admin_update_user(user_id: str, payload: UpdateUserRequest, request: Request):
    with db() as conn:
        require_admin(conn, request)
        try:
            return {"user": update_user(
                conn,
                user_id,
                display_name=payload.display_name,
                email=payload.email,
                role=payload.role,
                is_active=payload.is_active,
                password=payload.password,
            )}
        except KeyError as exc:
            raise not_found("User not found") from exc


@app.post("/classify_all")
def classify_all():
    with db() as conn:
        return classify_all_assets(conn, lambda asset_id: classify_asset_record(conn, asset_id))
