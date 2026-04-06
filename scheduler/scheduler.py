import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
import schedule

API_BASE = os.environ.get("API_BASE", "http://brain:8088")
TARGET_SUBNET = os.environ.get("TARGET_SUBNET", "10.0.0.0/24")
DISCOVERY_INTERVAL_MINUTES = int(os.environ.get("DISCOVERY_INTERVAL_MINUTES", "30"))
REPORT_HOUR_UTC = int(os.environ.get("REPORT_HOUR_UTC", "8"))
DISCOVERY_DIR = Path(os.environ.get("DISCOVERY_DIR", "/data/discovery/raw"))
TOP_PORTS = os.environ.get("TOP_PORTS", "100")
API_RETRY_ATTEMPTS = int(os.environ.get("API_RETRY_ATTEMPTS", "5"))
API_RETRY_DELAY_SECONDS = int(os.environ.get("API_RETRY_DELAY_SECONDS", "5"))
STARTUP_API_TIMEOUT_SECONDS = int(os.environ.get("STARTUP_API_TIMEOUT_SECONDS", "120"))
STARTUP_DISCOVERY = os.environ.get("STARTUP_DISCOVERY", "false").strip().lower() in {"1", "true", "yes", "on"}


def log(msg: str) -> None:
    print(f"[{datetime.now(timezone.utc).isoformat()}] {msg}", flush=True)


def run_cmd(cmd: list[str]) -> None:
    log(f"Running: {' '.join(cmd)}")
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
            log("API health check succeeded")
            return
        except Exception as exc:
            last_error = str(exc)
            log(f"Waiting for API readiness: {exc}")
            time.sleep(5)

    raise RuntimeError(f"Timed out waiting for API readiness: {last_error}")


def request_with_retries(method: str, path: str, **kwargs) -> requests.Response:
    last_error: Exception | None = None

    for attempt in range(1, API_RETRY_ATTEMPTS + 1):
        try:
            response = requests.request(method, f"{API_BASE}{path}", **kwargs)
            response.raise_for_status()
            return response
        except Exception as exc:
            last_error = exc
            if attempt == API_RETRY_ATTEMPTS:
                break
            log(
                f"Request failed for {method} {path} "
                f"(attempt {attempt}/{API_RETRY_ATTEMPTS}): {exc}"
            )
            time.sleep(API_RETRY_DELAY_SECONDS)

    raise RuntimeError(f"Request failed for {method} {path}: {last_error}")


def safe_job(name: str, fn) -> None:
    log(f"Starting job: {name}")
    try:
        fn()
        log(f"Completed job: {name}")
    except Exception as exc:
        log(f"Job failed: {name}: {exc}")


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
    log(f"Discovery finished: {out}")

    ingest_latest(str(out))
    classify_all()
    detect_changes()


def ingest_latest(xml_path: str) -> None:
    log(f"Ingesting XML: {xml_path}")
    r = request_with_retries(
        "POST",
        "/ingest/nmap_xml",
        json={"xml_path": xml_path},
        timeout=300,
    )
    log(f"Ingest response: {r.json()}")


def classify_all() -> None:
    log("Running classify_all")
    request_with_retries("POST", "/classify_all", timeout=600)
    log("classify_all complete")


def detect_changes() -> None:
    log("Running detect_changes")
    r = request_with_retries("GET", "/detect_changes", timeout=600)
    log(f"detect_changes summary: {r.json().get('assets_with_changes')}")


def daily_report() -> None:
    log("Generating daily report")
    r = request_with_retries("GET", "/report/daily", timeout=300)
    report = r.json()
    log(
        f"Daily report: recent_change_count={report.get('recent_change_count')}, "
        f"recent_asset_count={report.get('recent_asset_count')}, "
        f"notable_asset_count={report.get('notable_asset_count')}"
    )


def main() -> None:
    log("Scheduler starting")
    log(f"API_BASE={API_BASE}")
    log(f"TARGET_SUBNET={TARGET_SUBNET}")
    log(f"DISCOVERY_INTERVAL_MINUTES={DISCOVERY_INTERVAL_MINUTES}")
    log(f"REPORT_HOUR_UTC={REPORT_HOUR_UTC}")
    log(f"API_RETRY_ATTEMPTS={API_RETRY_ATTEMPTS}")
    log(f"API_RETRY_DELAY_SECONDS={API_RETRY_DELAY_SECONDS}")
    log(f"STARTUP_API_TIMEOUT_SECONDS={STARTUP_API_TIMEOUT_SECONDS}")
    log(f"STARTUP_DISCOVERY={STARTUP_DISCOVERY}")

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
