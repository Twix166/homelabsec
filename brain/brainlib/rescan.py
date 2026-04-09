from __future__ import annotations

import json
from typing import Any

import psycopg

from brainlib.database import asset_exists
from brainlib.errors import not_found


def latest_asset_ip(conn: psycopg.Connection, asset_id: str) -> str | None:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT ip_address
            FROM network_observations
            WHERE asset_id = %s
              AND ip_address IS NOT NULL
            ORDER BY observed_at DESC, observation_id DESC
            LIMIT 1
            """,
            (asset_id,),
        )
        row = cur.fetchone()

    return str(row[0]) if row and row[0] is not None else None


def latest_rescan_request(conn: psycopg.Connection, asset_id: str) -> dict[str, Any] | None:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT request_id,
                   asset_id,
                   target_ip,
                   status,
                   requested_by,
                   requested_at,
                   started_at,
                   completed_at,
                   result_json
            FROM rescan_requests
            WHERE asset_id = %s
            ORDER BY requested_at DESC, request_id DESC
            LIMIT 1
            """,
            (asset_id,),
        )
        row = cur.fetchone()

    if not row:
        return None

    return {
        "request_id": str(row[0]),
        "asset_id": str(row[1]),
        "target_ip": str(row[2]) if row[2] is not None else None,
        "status": row[3],
        "requested_by": row[4],
        "requested_at": row[5].isoformat(),
        "started_at": row[6].isoformat() if row[6] is not None else None,
        "completed_at": row[7].isoformat() if row[7] is not None else None,
        "result": row[8],
    }


def enqueue_rescan_request(conn: psycopg.Connection, asset_id: str) -> dict[str, Any]:
    if not asset_exists(conn, asset_id):
        raise not_found("Asset not found")

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT request_id,
                   asset_id,
                   target_ip,
                   status,
                   requested_by,
                   requested_at,
                   started_at,
                   completed_at,
                   result_json
            FROM rescan_requests
            WHERE asset_id = %s
              AND status IN ('pending', 'running')
            ORDER BY requested_at DESC, request_id DESC
            LIMIT 1
            """,
            (asset_id,),
        )
        existing = cur.fetchone()
        if existing:
            return {
                "queued": False,
                "request": {
                    "request_id": str(existing[0]),
                    "asset_id": str(existing[1]),
                    "target_ip": str(existing[2]) if existing[2] is not None else None,
                    "status": existing[3],
                    "requested_by": existing[4],
                    "requested_at": existing[5].isoformat(),
                    "started_at": existing[6].isoformat() if existing[6] is not None else None,
                    "completed_at": existing[7].isoformat() if existing[7] is not None else None,
                    "result": existing[8],
                },
            }

        target_ip = latest_asset_ip(conn, asset_id)
        cur.execute(
            """
            INSERT INTO rescan_requests (asset_id, target_ip, status, requested_by)
            VALUES (%s, %s, 'pending', 'ui')
            RETURNING request_id, requested_at
            """,
            (asset_id, target_ip),
        )
        inserted = cur.fetchone()
        conn.commit()

    return {
        "queued": True,
        "request": {
            "request_id": str(inserted[0]),
            "asset_id": asset_id,
            "target_ip": target_ip,
            "status": "pending",
            "requested_by": "ui",
            "requested_at": inserted[1].isoformat(),
            "started_at": None,
            "completed_at": None,
            "result": {},
        },
    }


def claim_rescan_request(conn: psycopg.Connection) -> dict[str, Any]:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT request_id, asset_id, target_ip
            FROM rescan_requests
            WHERE status = 'pending'
            ORDER BY requested_at ASC, request_id ASC
            LIMIT 1
            FOR UPDATE SKIP LOCKED
            """
        )
        row = cur.fetchone()

        if not row:
            conn.commit()
            return {"claimed": False}

        cur.execute(
            """
            UPDATE rescan_requests
            SET status = 'running',
                started_at = now()
            WHERE request_id = %s
            """,
            (row[0],),
        )
        conn.commit()

    return {
        "claimed": True,
        "request": {
            "request_id": str(row[0]),
            "asset_id": str(row[1]),
            "target_ip": str(row[2]) if row[2] is not None else None,
        },
    }


def complete_rescan_request(
    conn: psycopg.Connection,
    request_id: str,
    *,
    status: str,
    result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE rescan_requests
            SET status = %s,
                completed_at = now(),
                result_json = %s::jsonb
            WHERE request_id = %s
            RETURNING request_id, asset_id, target_ip, requested_by, requested_at, started_at, completed_at, result_json
            """,
            (status, json.dumps(result or {}), request_id),
        )
        row = cur.fetchone()
        conn.commit()

    if not row:
        raise not_found("Rescan request not found")

    return {
        "request_id": str(row[0]),
        "asset_id": str(row[1]),
        "target_ip": str(row[2]) if row[2] is not None else None,
        "status": status,
        "requested_by": row[3],
        "requested_at": row[4].isoformat(),
        "started_at": row[5].isoformat() if row[5] is not None else None,
        "completed_at": row[6].isoformat() if row[6] is not None else None,
        "result": row[7],
    }
