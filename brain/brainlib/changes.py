from __future__ import annotations

from typing import Any

import psycopg

from brainlib.database import asset_exists
from brainlib.errors import not_found
from brainlib.fingerprints import detect_and_persist_changes_for_asset, get_latest_fingerprint


def detect_changes_for_asset(conn: psycopg.Connection, asset_id: str) -> dict[str, Any]:
    if not asset_exists(conn, asset_id):
        raise not_found("Asset not found")

    latest = get_latest_fingerprint(conn, asset_id)
    if latest is None:
        raise not_found("No fingerprint found for asset")

    return detect_and_persist_changes_for_asset(conn, asset_id)


def detect_changes_all(conn: psycopg.Connection) -> dict[str, Any]:
    all_results = []

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT DISTINCT asset_id
            FROM fingerprints
            ORDER BY asset_id
            """
        )
        asset_ids = [str(r[0]) for r in cur.fetchall()]

    for asset_id in asset_ids:
        result = detect_and_persist_changes_for_asset(conn, asset_id)
        if result["changes"]:
            all_results.append(result)

    return {
        "assets_with_changes": len(all_results),
        "results": all_results,
    }
