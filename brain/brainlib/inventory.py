from __future__ import annotations

from typing import Any

import psycopg

from brainlib.config import FINGERPRINTS_LIST_LIMIT, OBSERVATIONS_LIST_LIMIT
from brainlib.errors import not_found
from brainlib.fingerprints import get_latest_fingerprint


def list_assets(conn: psycopg.Connection) -> dict[str, list[dict[str, Any]]]:
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


def list_observations(conn: psycopg.Connection) -> dict[str, list[dict[str, Any]]]:
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


def list_fingerprints(conn: psycopg.Connection) -> dict[str, list[dict[str, Any]]]:
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


def fingerprint_detail(conn: psycopg.Connection, asset_id: str) -> dict[str, Any]:
    latest = get_latest_fingerprint(conn, asset_id)
    if latest is None:
        raise not_found("No fingerprint found for asset")

    return {
        "asset_id": asset_id,
        "fingerprint_hash": latest["fingerprint_hash"],
        "created_at": latest["created_at"],
        "fingerprint": latest["fingerprint"],
    }
