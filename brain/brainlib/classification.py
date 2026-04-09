from __future__ import annotations

import json
from typing import Any

import psycopg

from brainlib.assets import normalize_role
from brainlib.config import CLASSIFICATION_FALLBACK_CONFIDENCE, CLASSIFICATION_FALLBACK_ROLE
from brainlib.database import asset_exists
from brainlib.errors import not_found
from brainlib.fingerprints import (
    build_fingerprint,
    classification_lookup_signature,
    classification_lookup_signature_hash,
    store_fingerprint_if_changed,
)
from brainlib.ollama import chat_json


def get_classification_lookup_entry(
    conn: psycopg.Connection,
    fingerprint: dict[str, Any],
) -> dict[str, Any] | None:
    signature = classification_lookup_signature(fingerprint)
    signature_hash = classification_lookup_signature_hash(fingerprint)

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT lookup_id,
                   role,
                   confidence,
                   source,
                   sample_count,
                   first_learned_at,
                   last_learned_at
            FROM classification_lookup
            WHERE signature_hash = %s
            """,
            (signature_hash,),
        )
        row = cur.fetchone()

    if not row:
        return None

    return {
        "lookup_id": str(row[0]),
        "signature_hash": signature_hash,
        "signature": signature,
        "role": row[1],
        "confidence": float(row[2]),
        "source": row[3],
        "sample_count": row[4],
        "first_learned_at": row[5].isoformat(),
        "last_learned_at": row[6].isoformat(),
    }


def learn_classification_lookup_entry(
    conn: psycopg.Connection,
    fingerprint: dict[str, Any],
    role: str,
    confidence: float,
    *,
    source: str = "llm_learned",
) -> None:
    signature = classification_lookup_signature(fingerprint)
    signature_hash = classification_lookup_signature_hash(fingerprint)

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO classification_lookup (
                signature_hash,
                signature_json,
                role,
                confidence,
                source,
                sample_count
            )
            VALUES (%s, %s::jsonb, %s, %s, %s, 1)
            ON CONFLICT (signature_hash) DO UPDATE
            SET role = EXCLUDED.role,
                confidence = EXCLUDED.confidence,
                source = EXCLUDED.source,
                sample_count = classification_lookup.sample_count + 1,
                last_learned_at = now()
            """,
            (signature_hash, json.dumps(signature), role, confidence, source),
        )
        conn.commit()


def apply_classification_to_asset(
    conn: psycopg.Connection,
    asset_id: str,
    role: str,
    confidence: float,
) -> tuple[dict[str, Any], dict[str, Any]]:
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
    return updated_fingerprint, fingerprint_store_result


def list_classification_lookup_entries(conn: psycopg.Connection) -> dict[str, Any]:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT lookup_id,
                   signature_hash,
                   signature_json,
                   role,
                   confidence,
                   source,
                   sample_count,
                   first_learned_at,
                   last_learned_at
            FROM classification_lookup
            ORDER BY last_learned_at DESC, first_learned_at DESC
            """
        )
        rows = cur.fetchall()

    return {
        "entries": [
            {
                "lookup_id": str(row[0]),
                "signature_hash": row[1],
                "signature": row[2],
                "role": row[3],
                "confidence": float(row[4]),
                "source": row[5],
                "sample_count": row[6],
                "first_learned_at": row[7].isoformat(),
                "last_learned_at": row[8].isoformat(),
            }
            for row in rows
        ]
    }


def classify_asset(conn: psycopg.Connection, asset_id: str) -> dict[str, Any]:
    if not asset_exists(conn, asset_id):
        raise not_found("Asset not found")

    fingerprint = build_fingerprint(conn, asset_id)
    lookup_entry = get_classification_lookup_entry(conn, fingerprint)
    if lookup_entry:
        updated_fingerprint, fingerprint_store_result = apply_classification_to_asset(
            conn,
            asset_id,
            lookup_entry["role"],
            lookup_entry["confidence"],
        )
        return {
            "asset_id": asset_id,
            "classification": {
                "role": lookup_entry["role"],
                "confidence": lookup_entry["confidence"],
            },
            "classification_source": "lookup",
            "lookup": lookup_entry,
            "fingerprint": updated_fingerprint,
            "fingerprint_store": fingerprint_store_result,
            "raw_model_output": None,
        }

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

    updated_fingerprint, fingerprint_store_result = apply_classification_to_asset(
        conn,
        asset_id,
        role,
        confidence,
    )
    learn_classification_lookup_entry(conn, fingerprint, role, confidence)

    return {
        "asset_id": asset_id,
        "classification": {
            "role": role,
            "confidence": confidence,
        },
        "classification_source": "llm",
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
    lookup_hits = 0
    llm_classified = 0
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
            result = classify_asset_fn(asset_id)
            ok += 1
            if result.get("classification_source") == "lookup":
                lookup_hits += 1
            elif result.get("classification_source") == "llm":
                llm_classified += 1
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
        "lookup_hits": lookup_hits,
        "llm_classified": llm_classified,
        "errors": errors,
        "failed": failed,
    }
