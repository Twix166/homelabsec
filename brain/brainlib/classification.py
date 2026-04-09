from __future__ import annotations

import json
from typing import Any

import psycopg

from brainlib.assets import normalize_role
from brainlib.config import CLASSIFICATION_FALLBACK_CONFIDENCE, CLASSIFICATION_FALLBACK_ROLE
from brainlib.database import asset_exists
from brainlib.errors import not_found
from brainlib.fingerprints import build_fingerprint, store_fingerprint_if_changed
from brainlib.ollama import chat_json


def classify_asset(conn: psycopg.Connection, asset_id: str) -> dict[str, Any]:
    if not asset_exists(conn, asset_id):
        raise not_found("Asset not found")

    fingerprint = build_fingerprint(conn, asset_id)
    data = chat_json(
        [
            {
                "role": "system",
                "content": (
                    "You are a homelab asset classifier. "
                    "Use only the provided fingerprint. "
                    "Return strict JSON with keys role and confidence. "
                    "Role must be a short snake_case label like gateway, nas, printer, web_server, server, switch, access_point, iot_device, workstation, unknown."
                ),
            },
            {
                "role": "user",
                "content": f"Fingerprint: {json.dumps(fingerprint)}",
            },
        ]
    )

    content = data.get("message", {}).get("content", "")
    raw_error = None

    try:
        parsed = json.loads(content)
    except json.JSONDecodeError:
        raw_error = content
        parsed = {
            "role": CLASSIFICATION_FALLBACK_ROLE,
            "confidence": CLASSIFICATION_FALLBACK_CONFIDENCE,
            "raw_model_output": content,
        }

    role = normalize_role(parsed.get("role", CLASSIFICATION_FALLBACK_ROLE))
    confidence = parsed.get("confidence", CLASSIFICATION_FALLBACK_CONFIDENCE)

    try:
        confidence = float(confidence)
    except (TypeError, ValueError):
        confidence = CLASSIFICATION_FALLBACK_CONFIDENCE

    if not isinstance(role, str) or not role.strip():
        role = CLASSIFICATION_FALLBACK_ROLE

    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE assets
            SET role = %s, role_confidence = %s
            WHERE asset_id = %s
            """,
            (role, confidence, asset_id),
        )
        conn.commit()

    updated_fingerprint = build_fingerprint(conn, asset_id)
    fingerprint_store_result = store_fingerprint_if_changed(conn, asset_id, updated_fingerprint)

    return {
        "asset_id": asset_id,
        "classification": {
            "role": role,
            "confidence": confidence,
        },
        "fingerprint": updated_fingerprint,
        "fingerprint_store": fingerprint_store_result,
        "raw_model_output": raw_error,
    }


def classify_all_assets(
    conn: psycopg.Connection,
    classify_asset_fn,
) -> dict[str, Any]:
    ok = 0
    errors = 0
    failed = []

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT asset_id
            FROM assets
            ORDER BY last_seen DESC
            """
        )
        asset_ids = [str(r[0]) for r in cur.fetchall()]

    for asset_id in asset_ids:
        try:
            classify_asset_fn(asset_id)
            ok += 1
        except Exception as exc:
            errors += 1
            failed.append(
                {
                    "asset_id": asset_id,
                    "error": str(exc),
                }
            )

    return {
        "total_assets": len(asset_ids),
        "classified_ok": ok,
        "errors": errors,
        "failed": failed,
    }
