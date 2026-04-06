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


def log(msg: str) -> None:
    print(f"[{datetime.now(timezone.utc).isoformat()}] {msg}", flush=True)


def run_cmd(cmd: list[str]) -> None:
    log(f"Running: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)


def latest_scan_path() -> Path:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    DISCOVERY_DIR.mkdir(parents=True, exist_ok=True)
    return DISCOVERY_DIR / f"scan_{ts}.xml"


def run_discovery() -> None:
    out = latest_scan_path()
    run_cmd([
        "nmap",
        "-sS",
        "-sV",
        "--top-ports",
        TOP_PORTS,
        "-T4",
        "-oX",
        str(out),
        TARGET_SUBNET,
    ])
    log(f"Discovery finished: {out}")

    ingest_latest(str(out))
    classify_all()
    detect_changes()


def ingest_latest(xml_path: str) -> None:
    log(f"Ingesting XML: {xml_path}")
    r = requests.post(
        f"{API_BASE}/ingest/nmap_xml",
        json={"xml_path": xml_path},
        timeout=300,
    )
    r.raise_for_status()
    log(f"Ingest response: {r.json()}")


def classify_all() -> None:
    log("Running classify_all")
    r = requests.post(f"{API_BASE}/classify_all", timeout=600)
    r.raise_for_status()
    log("classify_all complete")


def detect_changes() -> None:
    log("Running detect_changes")
    r = requests.get(f"{API_BASE}/detect_changes", timeout=600)
    r.raise_for_status()
    log(f"detect_changes summary: {r.json().get('assets_with_changes')}")


def daily_report() -> None:
    log("Generating daily report")
    r = requests.get(f"{API_BASE}/report/daily", timeout=300)
    r.raise_for_status()
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

    schedule.every(DISCOVERY_INTERVAL_MINUTES).minutes.do(run_discovery)
    schedule.every().day.at(f"{REPORT_HOUR_UTC:02d}:00").do(daily_report)

    # Optional immediate startup report
    try:
        daily_report()
    except Exception as exc:
        log(f"Initial report failed: {exc}")

    while True:
        schedule.run_pending()
        time.sleep(5)


if __name__ == "__main__":
    main()