import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
import schedule

from config import CONFIG
from logging_utils import configure_logging, log_event
from metrics import (
    record_api_request,
    record_api_request_failure,
    record_job_completed,
    record_job_failed,
    record_job_started,
    start_metrics_server,
)

API_BASE = CONFIG.api_base
TARGET_SUBNET = CONFIG.target_subnet
DISCOVERY_INTERVAL_MINUTES = CONFIG.discovery_interval_minutes
REPORT_HOUR_UTC = CONFIG.report_hour_utc
DISCOVERY_DIR = Path(CONFIG.discovery_dir)
TOP_PORTS = CONFIG.top_ports
API_RETRY_ATTEMPTS = CONFIG.api_retry_attempts
API_RETRY_DELAY_SECONDS = CONFIG.api_retry_delay_seconds
STARTUP_API_TIMEOUT_SECONDS = CONFIG.startup_api_timeout_seconds
STARTUP_DISCOVERY = CONFIG.startup_discovery
SCHEDULER_METRICS_PORT = CONFIG.scheduler_metrics_port
logger = configure_logging("homelabsec.scheduler", CONFIG.log_level)


def log(message: str, event: str = "scheduler_log", level: str = "info", **fields) -> None:
    log_event(logger, level, event, message, **fields)


def run_cmd(cmd: list[str]) -> None:
    log("Running command", event="command_start", command=cmd)
    subprocess.run(cmd, check=True)


def latest_scan_path() -> Path:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    DISCOVERY_DIR.mkdir(parents=True, exist_ok=True)
    return DISCOVERY_DIR / f"scan_{ts}.xml"


def wait_for_api_ready(timeout_seconds: int) -> None:
    deadline = time.time() + timeout_seconds
    last_error = "API did not become ready"

    while time.time() < deadline:
        try:
            response = requests.get(f"{API_BASE}/health", timeout=5)
            response.raise_for_status()
            log("API health check succeeded", event="api_ready", api_base=API_BASE)
            return
        except Exception as exc:
            last_error = str(exc)
            log("Waiting for API readiness", event="api_wait", api_base=API_BASE, error=str(exc))
            time.sleep(5)

    raise RuntimeError(f"Timed out waiting for API readiness: {last_error}")


def request_with_retries(method: str, path: str, **kwargs) -> requests.Response:
    last_error: Exception | None = None

    for attempt in range(1, API_RETRY_ATTEMPTS + 1):
        try:
            response = requests.request(method, f"{API_BASE}{path}", **kwargs)
            response.raise_for_status()
            record_api_request(method, path, response.status_code)
            return response
        except Exception as exc:
            last_error = exc
            record_api_request_failure(method, path)
            if attempt == API_RETRY_ATTEMPTS:
                break
            log(
                "Request failed and will retry",
                event="request_retry",
                method=method,
                path=path,
                attempt=attempt,
                max_attempts=API_RETRY_ATTEMPTS,
                error=str(exc),
            )
            time.sleep(API_RETRY_DELAY_SECONDS)

    raise RuntimeError(f"Request failed for {method} {path}: {last_error}")


def safe_job(name: str, fn) -> None:
    started = time.perf_counter()
    record_job_started(name)
    log("Starting job", event="job_start", job=name)
    try:
        fn()
        record_job_completed(name, time.perf_counter() - started)
        log("Completed job", event="job_complete", job=name)
    except Exception as exc:
        record_job_failed(name, time.perf_counter() - started)
        log("Job failed", event="job_failed", level="error", job=name, error=str(exc))


def run_discovery() -> None:
    out = latest_scan_path()
    run_cmd(
        [
            "nmap",
            "-sS",
            "-sV",
            "--top-ports",
            TOP_PORTS,
            "-T4",
            "-oX",
            str(out),
            TARGET_SUBNET,
        ]
    )
    log("Discovery finished", event="discovery_complete", output_path=str(out))

    ingest_latest(str(out))
    classify_all()
    detect_changes()


def ingest_latest(xml_path: str) -> None:
    log("Ingesting XML", event="ingest_start", xml_path=xml_path)
    r = request_with_retries(
        "POST",
        "/ingest/nmap_xml",
        json={"xml_path": xml_path},
        timeout=300,
    )
    log("Ingest response received", event="ingest_complete", response=r.json())


def classify_all() -> None:
    log("Running classify_all", event="classify_all_start")
    request_with_retries("POST", "/classify_all", timeout=600)
    log("classify_all complete", event="classify_all_complete")


def detect_changes() -> None:
    log("Running detect_changes", event="detect_changes_start")
    r = request_with_retries("GET", "/detect_changes", timeout=600)
    log(
        "detect_changes complete",
        event="detect_changes_complete",
        assets_with_changes=r.json().get("assets_with_changes"),
    )


def daily_report() -> None:
    log("Generating daily report", event="daily_report_start")
    r = request_with_retries("GET", "/report/daily", timeout=300)
    report = r.json()
    log(
        "Daily report generated",
        event="daily_report_complete",
        recent_change_count=report.get("recent_change_count"),
        recent_asset_count=report.get("recent_asset_count"),
        notable_asset_count=report.get("notable_asset_count"),
    )


def main() -> None:
    log(
        "Scheduler starting",
        event="scheduler_start",
        api_base=API_BASE,
        target_subnet=TARGET_SUBNET,
        discovery_interval_minutes=DISCOVERY_INTERVAL_MINUTES,
        report_hour_utc=REPORT_HOUR_UTC,
        api_retry_attempts=API_RETRY_ATTEMPTS,
        api_retry_delay_seconds=API_RETRY_DELAY_SECONDS,
        startup_api_timeout_seconds=STARTUP_API_TIMEOUT_SECONDS,
        startup_discovery=STARTUP_DISCOVERY,
        scheduler_metrics_port=SCHEDULER_METRICS_PORT,
    )
    start_metrics_server(SCHEDULER_METRICS_PORT)

    wait_for_api_ready(STARTUP_API_TIMEOUT_SECONDS)

    schedule.every(DISCOVERY_INTERVAL_MINUTES).minutes.do(safe_job, "run_discovery", run_discovery)
    schedule.every().day.at(f"{REPORT_HOUR_UTC:02d}:00").do(safe_job, "daily_report", daily_report)

    safe_job("startup_daily_report", daily_report)
    if STARTUP_DISCOVERY:
        safe_job("startup_discovery", run_discovery)

    while True:
        schedule.run_pending()
        time.sleep(5)


if __name__ == "__main__":
    main()
