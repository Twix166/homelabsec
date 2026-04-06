from __future__ import annotations

import psycopg

from brainlib.config import NOTABLE_ASSET_LIMIT, utcnow_iso


def daily_report(conn: psycopg.Connection) -> dict[str, object]:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                c.change_id,
                c.asset_id,
                a.preferred_name,
                a.role,
                c.change_type,
                c.severity,
                c.confidence,
                c.old_value,
                c.new_value,
                c.detected_at
            FROM changes c
            JOIN assets a ON a.asset_id = c.asset_id
            WHERE c.detected_at >= now() - interval '1 day'
            ORDER BY
                CASE c.severity
                    WHEN 'critical' THEN 5
                    WHEN 'high' THEN 4
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 2
                    ELSE 1
                END DESC,
                c.detected_at DESC
            """
        )
        recent_changes_rows = cur.fetchall()

        cur.execute(
            """
            SELECT
                asset_id,
                preferred_name,
                role,
                role_confidence,
                first_seen,
                last_seen
            FROM assets
            WHERE last_seen >= now() - interval '1 day'
            ORDER BY last_seen DESC
            """
        )
        recent_assets_rows = cur.fetchall()

        cur.execute(
            """
            SELECT
                asset_id,
                preferred_name,
                role,
                role_confidence,
                last_seen
            FROM assets
            WHERE role IS NULL
               OR role = 'unknown'
               OR role_confidence IS NULL
               OR role_confidence < 0.60
            ORDER BY last_seen DESC
            LIMIT %s
            """,
            (NOTABLE_ASSET_LIMIT,),
        )
        notable_assets_rows = cur.fetchall()

    recent_changes = [
        {
            "change_id": str(r[0]),
            "asset_id": str(r[1]),
            "preferred_name": r[2],
            "role": r[3],
            "change_type": r[4],
            "severity": r[5],
            "confidence": float(r[6]) if r[6] is not None else None,
            "old_value": r[7],
            "new_value": r[8],
            "detected_at": r[9].isoformat(),
        }
        for r in recent_changes_rows
    ]

    recent_assets = [
        {
            "asset_id": str(r[0]),
            "preferred_name": r[1],
            "role": r[2],
            "role_confidence": float(r[3]) if r[3] is not None else None,
            "first_seen": r[4].isoformat(),
            "last_seen": r[5].isoformat(),
        }
        for r in recent_assets_rows
    ]

    notable_assets = [
        {
            "asset_id": str(r[0]),
            "preferred_name": r[1],
            "role": r[2],
            "role_confidence": float(r[3]) if r[3] is not None else None,
            "last_seen": r[4].isoformat(),
        }
        for r in notable_assets_rows
    ]

    return {
        "report_generated_at": utcnow_iso(),
        "recent_change_count": len(recent_changes),
        "recent_asset_count": len(recent_assets),
        "notable_asset_count": len(notable_assets),
        "recent_changes": recent_changes,
        "recent_assets": recent_assets,
        "notable_assets": notable_assets,
    }


def summary_report(conn: psycopg.Connection) -> dict[str, int]:
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM assets")
        assets = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM network_observations")
        observations = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM fingerprints")
        fingerprints = cur.fetchone()[0]

    return {
        "assets": assets,
        "network_observations": observations,
        "fingerprints": fingerprints,
    }
