from __future__ import annotations

from typing import Any

import psycopg

from brainlib.config import ADMIN_STALE_SCAN_MINUTES, utcnow_iso
from brainlib.reports import summary_report
from brainlib.versioning import current_version


def admin_status(conn: psycopg.Connection) -> dict[str, Any]:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT scan_run_id, scan_type, started_at, completed_at, status
            FROM scan_runs
            ORDER BY COALESCE(completed_at, started_at) DESC
            LIMIT 1
            """
        )
        latest_scan_row = cur.fetchone()

    summary = summary_report(conn)
    latest_scan = None
    freshness = {
        "status": "unknown",
        "stale_after_minutes": ADMIN_STALE_SCAN_MINUTES,
        "age_minutes": None,
    }

    if latest_scan_row is not None:
        latest_scan = {
            "scan_run_id": str(latest_scan_row[0]),
            "scan_type": latest_scan_row[1],
            "started_at": latest_scan_row[2].isoformat() if latest_scan_row[2] else None,
            "completed_at": latest_scan_row[3].isoformat() if latest_scan_row[3] else None,
            "status": latest_scan_row[4],
        }
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT EXTRACT(EPOCH FROM (now() - COALESCE(completed_at, started_at))) / 60.0
                FROM scan_runs
                WHERE scan_run_id = %s
                """,
                (latest_scan_row[0],),
            )
            age_minutes = float(cur.fetchone()[0])

        freshness["age_minutes"] = round(age_minutes, 2)
        freshness["status"] = "stale" if age_minutes > ADMIN_STALE_SCAN_MINUTES else "fresh"

    return {
        "generated_at": utcnow_iso(),
        "api_status": "ok",
        "version": current_version(),
        "summary": summary,
        "latest_scan_run": latest_scan,
        "scheduler_freshness": freshness,
    }
