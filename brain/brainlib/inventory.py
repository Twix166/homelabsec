from __future__ import annotations

from typing import Any

import psycopg

from brainlib.classification import get_classification_lookup_entry
from brainlib.config import FINGERPRINTS_LIST_LIMIT, OBSERVATIONS_LIST_LIMIT
from brainlib.errors import not_found
from brainlib.fingerprints import get_latest_fingerprint
from brainlib.rescan import latest_rescan_request


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


def asset_detail(conn: psycopg.Connection, asset_id: str) -> dict[str, Any]:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT asset_id, preferred_name, role, role_confidence, first_seen, last_seen
            FROM assets
            WHERE asset_id = %s
            """,
            (asset_id,),
        )
        asset = cur.fetchone()
        if not asset:
            raise not_found("Asset not found")

        cur.execute(
            """
            SELECT identifier_type, identifier_value
            FROM asset_identifiers
            WHERE asset_id = %s
            ORDER BY identifier_type, identifier_value
            """,
            (asset_id,),
        )
        identifiers = [{"type": row[0], "value": row[1]} for row in cur.fetchall()]

        cur.execute(
            """
            SELECT ip_address,
                   port,
                   protocol,
                   service_name,
                   service_product,
                   service_version,
                   os_guess,
                   observed_at
            FROM network_observations
            WHERE asset_id = %s
            ORDER BY observed_at DESC, observation_id DESC
            """,
            (asset_id,),
        )
        observation_rows = cur.fetchall()

    seen_services = set()
    exposed_services = []
    for row in observation_rows:
        if row[1] is None:
            continue
        key = (row[1], row[2], row[3], row[4], row[5])
        if key in seen_services:
            continue
        seen_services.add(key)
        exposed_services.append(
            {
                "ip_address": str(row[0]) if row[0] is not None else None,
                "port": row[1],
                "protocol": row[2],
                "service_name": row[3],
                "service_product": row[4],
                "service_version": row[5],
                "os_guess": row[6],
                "observed_at": row[7].isoformat(),
            }
        )

    latest = get_latest_fingerprint(conn, asset_id)
    learned_lookup = get_classification_lookup_entry(conn, latest["fingerprint"]) if latest else None

    return {
        "asset": {
            "asset_id": str(asset[0]),
            "preferred_name": asset[1],
            "role": asset[2],
            "role_confidence": float(asset[3]) if asset[3] is not None else None,
            "first_seen": asset[4].isoformat(),
            "last_seen": asset[5].isoformat(),
        },
        "identifiers": identifiers,
        "exposed_services": exposed_services,
        "fingerprint": latest,
        "learned_lookup": learned_lookup,
        "latest_rescan_request": latest_rescan_request(conn, asset_id),
    }
