from __future__ import annotations

from typing import Any

import psycopg

from brainlib.errors import not_found


VALID_INTENTS = {"fix", "investigate", "defer", "accept_risk", "note"}
VALID_PRIORITIES = {"low", "normal", "high", "urgent"}


def _serialize_instruction(row) -> dict[str, Any]:
    return {
        "instruction_id": str(row[0]),
        "finding_id": str(row[1]),
        "requested_by_user_id": str(row[2]) if row[2] is not None else None,
        "instruction_text": row[3],
        "intent": row[4],
        "priority": row[5],
        "status": row[6],
        "created_at": row[7].isoformat(),
        "updated_at": row[8].isoformat(),
    }


def _serialize_latest_instruction(row) -> dict[str, Any] | None:
    if row[11] is None:
        return None
    return {
        "instruction_id": str(row[11]),
        "instruction_text": row[12],
        "intent": row[13],
        "priority": row[14],
        "status": row[15],
        "created_at": row[16].isoformat(),
    }


def list_findings(conn: psycopg.Connection) -> dict[str, list[dict[str, Any]]]:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                f.finding_id,
                f.asset_id,
                a.preferred_name,
                f.title,
                f.description,
                f.severity,
                f.confidence,
                f.evidence,
                f.recommended_action,
                f.created_at,
                COALESCE(ic.instruction_count, 0) AS instruction_count,
                li.instruction_id,
                li.instruction_text,
                li.intent,
                li.priority,
                li.status,
                li.created_at AS latest_instruction_created_at
            FROM findings f
            JOIN assets a ON a.asset_id = f.asset_id
            LEFT JOIN LATERAL (
                SELECT count(*) AS instruction_count
                FROM finding_remediation_instructions i
                WHERE i.finding_id = f.finding_id
            ) ic ON TRUE
            LEFT JOIN LATERAL (
                SELECT instruction_id, instruction_text, intent, priority, status, created_at
                FROM finding_remediation_instructions i
                WHERE i.finding_id = f.finding_id
                ORDER BY created_at DESC, instruction_id DESC
                LIMIT 1
            ) li ON TRUE
            ORDER BY
                CASE lower(f.severity)
                    WHEN 'critical' THEN 5
                    WHEN 'high' THEN 4
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 2
                    ELSE 1
                END DESC,
                f.created_at DESC,
                f.finding_id DESC
            """
        )
        rows = cur.fetchall()

    return {
        "findings": [
            {
                "finding_id": str(row[0]),
                "asset_id": str(row[1]),
                "preferred_name": row[2],
                "title": row[3],
                "description": row[4],
                "severity": row[5],
                "confidence": float(row[6]) if row[6] is not None else None,
                "evidence": row[7],
                "recommended_action": row[8],
                "created_at": row[9].isoformat(),
                "instruction_count": int(row[10]),
                "latest_instruction": _serialize_latest_instruction(row),
            }
            for row in rows
        ]
    }


def create_finding_instruction(
    conn: psycopg.Connection,
    finding_id: str,
    *,
    instruction_text: str,
    requested_by_user_id: str | None,
    intent: str = "fix",
    priority: str = "normal",
) -> dict[str, Any]:
    instruction_text = instruction_text.strip()
    if not instruction_text:
        raise ValueError("Instruction text is required")
    if intent not in VALID_INTENTS:
        raise ValueError("Unsupported instruction intent")
    if priority not in VALID_PRIORITIES:
        raise ValueError("Unsupported instruction priority")

    with conn.cursor() as cur:
        cur.execute("SELECT 1 FROM findings WHERE finding_id = %s", (finding_id,))
        if cur.fetchone() is None:
            raise KeyError(finding_id)

        cur.execute(
            """
            INSERT INTO finding_remediation_instructions (
                finding_id,
                requested_by_user_id,
                instruction_text,
                intent,
                priority
            )
            VALUES (%s, %s, %s, %s, %s)
            RETURNING
                instruction_id,
                finding_id,
                requested_by_user_id,
                instruction_text,
                intent,
                priority,
                status,
                created_at,
                updated_at
            """,
            (finding_id, requested_by_user_id, instruction_text, intent, priority),
        )
        row = cur.fetchone()
    conn.commit()
    return {"instruction": _serialize_instruction(row)}


def create_finding_instruction_or_404(
    conn: psycopg.Connection,
    finding_id: str,
    *,
    instruction_text: str,
    requested_by_user_id: str | None,
    intent: str = "fix",
    priority: str = "normal",
) -> dict[str, Any]:
    try:
        return create_finding_instruction(
            conn,
            finding_id,
            instruction_text=instruction_text,
            requested_by_user_id=requested_by_user_id,
            intent=intent,
            priority=priority,
        )
    except KeyError as exc:
        raise not_found("Finding not found") from exc
