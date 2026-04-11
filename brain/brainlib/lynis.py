from __future__ import annotations

from typing import Any

import psycopg

from brainlib.admin_console import is_module_enabled, is_raw_data_source_enabled
from brainlib.database import asset_exists
from brainlib.errors import conflict, not_found


def lynis_target_for_asset(conn: psycopg.Connection, asset_id: str) -> dict[str, Any] | None:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT asset_id, ssh_host, ssh_port, ssh_username, use_sudo, enabled, notes, created_at, updated_at
            FROM lynis_targets
            WHERE asset_id = %s
            """,
            (asset_id,),
        )
        row = cur.fetchone()
    if row is None:
        return None
    return {
        "asset_id": str(row[0]),
        "ssh_host": row[1],
        "ssh_port": row[2],
        "ssh_username": row[3],
        "use_sudo": bool(row[4]),
        "enabled": bool(row[5]),
        "notes": row[6],
        "created_at": row[7].isoformat(),
        "updated_at": row[8].isoformat(),
    }


def latest_lynis_run(conn: psycopg.Connection, asset_id: str) -> dict[str, Any] | None:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT run_id, asset_id, requested_by_user_id, status, source, target_ip, summary_json,
                   report_text, log_text, error_text, requested_at, started_at, completed_at
            FROM lynis_runs
            WHERE asset_id = %s
            ORDER BY requested_at DESC, run_id DESC
            LIMIT 1
            """,
            (asset_id,),
        )
        row = cur.fetchone()
    if row is None:
        return None
    return {
        "run_id": str(row[0]),
        "asset_id": str(row[1]),
        "requested_by_user_id": str(row[2]) if row[2] else None,
        "status": row[3],
        "source": row[4],
        "target_ip": str(row[5]) if row[5] is not None else None,
        "summary": row[6] or {},
        "report_text": row[7],
        "log_text": row[8],
        "error_text": row[9],
        "requested_at": row[10].isoformat(),
        "started_at": row[11].isoformat() if row[11] else None,
        "completed_at": row[12].isoformat() if row[12] else None,
    }


def configure_lynis_target(
    conn: psycopg.Connection,
    asset_id: str,
    *,
    ssh_host: str,
    ssh_port: int,
    ssh_username: str,
    ssh_password: str | None,
    use_sudo: bool,
    enabled: bool,
    notes: str | None,
) -> dict[str, Any]:
    if not asset_exists(conn, asset_id):
        raise not_found("Asset not found")

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO lynis_targets (asset_id, ssh_host, ssh_port, ssh_username, ssh_password, use_sudo, enabled, notes)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (asset_id) DO UPDATE
            SET ssh_host = EXCLUDED.ssh_host,
                ssh_port = EXCLUDED.ssh_port,
                ssh_username = EXCLUDED.ssh_username,
                ssh_password = EXCLUDED.ssh_password,
                use_sudo = EXCLUDED.use_sudo,
                enabled = EXCLUDED.enabled,
                notes = EXCLUDED.notes,
                updated_at = now()
            """,
            (asset_id, ssh_host.strip(), ssh_port, ssh_username.strip(), ssh_password, use_sudo, enabled, notes),
        )
        conn.commit()
    return lynis_target_for_asset(conn, asset_id)


def lynis_status_for_asset(conn: psycopg.Connection, asset_id: str) -> dict[str, Any]:
    if not asset_exists(conn, asset_id):
        raise not_found("Asset not found")
    return {
        "asset_id": asset_id,
        "module_enabled": is_module_enabled(conn, "lynis_audit"),
        "source_enabled": is_raw_data_source_enabled(conn, "lynis_remote_audit"),
        "target": lynis_target_for_asset(conn, asset_id),
        "latest_run": latest_lynis_run(conn, asset_id),
    }


def enqueue_lynis_run(conn: psycopg.Connection, asset_id: str, requested_by_user_id: str | None) -> dict[str, Any]:
    if not asset_exists(conn, asset_id):
        raise not_found("Asset not found")
    if not is_module_enabled(conn, "lynis_audit"):
        raise conflict("Lynis audit enrichment is disabled in the admin console")
    if not is_raw_data_source_enabled(conn, "lynis_remote_audit"):
        raise conflict("Lynis remote audit is disabled in the admin console")

    target = lynis_target_for_asset(conn, asset_id)
    if target is None or not target["enabled"]:
        raise conflict("No enabled Lynis target is configured for this asset")

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT run_id
            FROM lynis_runs
            WHERE asset_id = %s
              AND status IN ('pending', 'running')
            ORDER BY requested_at DESC
            LIMIT 1
            """,
            (asset_id,),
        )
        existing = cur.fetchone()
        if existing is not None:
            return {
                "queued": False,
                "run": latest_lynis_run(conn, asset_id),
            }

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
        latest_ip = cur.fetchone()
        cur.execute(
            """
            INSERT INTO lynis_runs (asset_id, requested_by_user_id, status, target_ip)
            VALUES (%s::uuid, %s::uuid, 'pending', %s)
            RETURNING run_id
            """,
            (asset_id, requested_by_user_id, latest_ip[0] if latest_ip else None),
        )
        cur.fetchone()
        conn.commit()

    return {
        "queued": True,
        "run": latest_lynis_run(conn, asset_id),
    }


def claim_lynis_run(conn: psycopg.Connection) -> dict[str, Any]:
    with conn.cursor() as cur:
        cur.execute(
            """
            WITH candidate AS (
                SELECT run_id
                FROM lynis_runs
                WHERE status = 'pending'
                ORDER BY requested_at ASC
                LIMIT 1
                FOR UPDATE SKIP LOCKED
            )
            UPDATE lynis_runs
            SET status = 'running',
                started_at = now()
            WHERE run_id IN (SELECT run_id FROM candidate)
            RETURNING run_id, asset_id
            """
        )
        row = cur.fetchone()
        conn.commit()

    if row is None:
        return {"claimed": False}

    run_id = str(row[0])
    asset_id = str(row[1])
    target = lynis_target_for_asset(conn, asset_id)
    if target is None:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE lynis_runs SET status = 'failed', error_text = %s, completed_at = now() WHERE run_id = %s",
                ("No Lynis target configured", run_id),
            )
            conn.commit()
        return {"claimed": False}

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT ssh_password
            FROM lynis_targets
            WHERE asset_id = %s
            """,
            (asset_id,),
        )
        password_row = cur.fetchone()
        cur.execute(
            """
            SELECT target_ip, requested_at
            FROM lynis_runs
            WHERE run_id = %s
            """,
            (run_id,),
        )
        run_row = cur.fetchone()

    return {
        "claimed": True,
        "run": {
            "run_id": run_id,
            "asset_id": asset_id,
            "target_ip": str(run_row[0]) if run_row and run_row[0] is not None else None,
            "requested_at": run_row[1].isoformat() if run_row else None,
            "target": {
                **target,
                "ssh_password": password_row[0] if password_row else None,
            },
        },
    }


def complete_lynis_run(
    conn: psycopg.Connection,
    run_id: str,
    *,
    status: str,
    summary: dict[str, Any] | None = None,
    report_text: str | None = None,
    log_text: str | None = None,
    error_text: str | None = None,
) -> dict[str, Any]:
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE lynis_runs
            SET status = %s,
                summary_json = %s::jsonb,
                report_text = %s,
                log_text = %s,
                error_text = %s,
                completed_at = now()
            WHERE run_id = %s
            RETURNING asset_id
            """,
            (status, psycopg.types.json.Json(summary or {}), report_text, log_text, error_text, run_id),
        )
        row = cur.fetchone()
        conn.commit()

    if row is None:
        raise not_found("Lynis run not found")

    return latest_lynis_run(conn, str(row[0])) or {"run_id": run_id, "status": status}
