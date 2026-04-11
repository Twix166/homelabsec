from __future__ import annotations

import json
from typing import Any

import psycopg
import requests

from brainlib.config import FINGERBANK_API_KEY, FINGERBANK_BASE_URL, FINGERBANK_TIMEOUT_SECONDS
from brainlib.fingerbank_mapping import resolve_fingerbank_role_mapping


class FingerbankError(RuntimeError):
    pass


def _parse_match_payload(payload: dict[str, Any]) -> dict[str, Any]:
    device = payload.get("device") or {}
    manufacturer = payload.get("manufacturer") or {}
    hierarchy = payload.get("hierarchy")
    if isinstance(hierarchy, list):
        hierarchy_value = " > ".join(str(part).strip() for part in hierarchy if str(part).strip())
    else:
        hierarchy_value = str(hierarchy).strip() if hierarchy else None

    return {
        "fingerbank_device_id": device.get("id") or payload.get("device_id"),
        "device_name": device.get("name") or payload.get("device_name"),
        "device_version": device.get("version") or payload.get("device_version"),
        "device_hierarchy": hierarchy_value or device.get("hierarchy"),
        "manufacturer_name": manufacturer.get("name") or payload.get("manufacturer_name"),
        "score": float(payload.get("score") or 0),
        "can_be_more_precise": bool(payload.get("can_be_more_precise", False)),
    }


def get_cached_fingerbank_match(
    conn: psycopg.Connection,
    asset_id: str,
    evidence_hash: str,
) -> dict[str, Any] | None:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT match_id,
                   fingerbank_device_id,
                   device_name,
                   device_version,
                   device_hierarchy,
                   manufacturer_name,
                   score,
                   can_be_more_precise,
                   mapped_role,
                   mapped_confidence,
                   response_json,
                   matched_at
            FROM fingerbank_matches
            WHERE asset_id = %s
              AND evidence_hash = %s
            ORDER BY matched_at DESC
            LIMIT 1
            """,
            (asset_id, evidence_hash),
        )
        row = cur.fetchone()

    if not row:
        return None

    return {
        "match_id": str(row[0]),
        "fingerbank_device_id": row[1],
        "device_name": row[2],
        "device_version": row[3],
        "device_hierarchy": row[4],
        "manufacturer_name": row[5],
        "score": float(row[6]) if row[6] is not None else 0.0,
        "can_be_more_precise": bool(row[7]),
        "mapped_role": row[8],
        "mapped_confidence": float(row[9]) if row[9] is not None else None,
        "response_json": row[10],
        "matched_at": row[11].isoformat(),
        "cached": True,
        "no_match": row[1] is None and not row[10],
    }


def _store_fingerbank_match(
    conn: psycopg.Connection,
    asset_id: str,
    evidence_hash: str,
    match: dict[str, Any],
    response_payload: dict[str, Any],
) -> dict[str, Any]:
    mapping = resolve_fingerbank_role_mapping(
        conn,
        fingerbank_device_id=match.get("fingerbank_device_id"),
        device_name=match.get("device_name"),
        manufacturer_name=match.get("manufacturer_name"),
        device_hierarchy=match.get("device_hierarchy"),
    )

    mapped_role = mapping["mapped_role"] if mapping else None
    mapped_confidence = mapping["default_confidence"] if mapping else None

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO fingerbank_matches (
                asset_id,
                evidence_hash,
                fingerbank_device_id,
                device_name,
                device_version,
                device_hierarchy,
                manufacturer_name,
                score,
                can_be_more_precise,
                mapped_role,
                mapped_confidence,
                response_json
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb)
            RETURNING match_id, matched_at
            """,
            (
                asset_id,
                evidence_hash,
                match.get("fingerbank_device_id"),
                match.get("device_name"),
                match.get("device_version"),
                match.get("device_hierarchy"),
                match.get("manufacturer_name"),
                match.get("score"),
                match.get("can_be_more_precise"),
                mapped_role,
                mapped_confidence,
                json.dumps(response_payload, sort_keys=True),
            ),
        )
        inserted = cur.fetchone()
        conn.commit()

    return {
        **match,
        "mapped_role": mapped_role,
        "mapped_confidence": float(mapped_confidence) if mapped_confidence is not None else None,
        "mapping": mapping,
        "response_json": response_payload,
        "match_id": str(inserted[0]),
        "matched_at": inserted[1].isoformat(),
        "cached": False,
        "no_match": match.get("fingerbank_device_id") is None,
    }


def _store_no_match(
    conn: psycopg.Connection,
    asset_id: str,
    evidence_hash: str,
) -> dict[str, Any]:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO fingerbank_matches (
                asset_id,
                evidence_hash,
                response_json,
                score,
                can_be_more_precise
            )
            VALUES (%s, %s, '{}'::jsonb, 0, false)
            RETURNING match_id, matched_at
            """,
            (asset_id, evidence_hash),
        )
        inserted = cur.fetchone()
        conn.commit()

    return {
        "match_id": str(inserted[0]),
        "matched_at": inserted[1].isoformat(),
        "fingerbank_device_id": None,
        "device_name": None,
        "device_version": None,
        "device_hierarchy": None,
        "manufacturer_name": None,
        "score": 0.0,
        "can_be_more_precise": False,
        "mapped_role": None,
        "mapped_confidence": None,
        "response_json": {},
        "cached": False,
        "no_match": True,
    }


def _fingerbank_request(evidence: dict[str, Any]) -> dict[str, Any]:
    if not FINGERBANK_API_KEY:
        raise FingerbankError("Fingerbank API key is not configured")

    response = requests.post(
        f"{FINGERBANK_BASE_URL}/api/v2/combinations/interrogate",
        headers={
            "Authorization": f"Bearer {FINGERBANK_API_KEY}",
            "Content-Type": "application/json",
        },
        json=evidence,
        timeout=FINGERBANK_TIMEOUT_SECONDS,
    )

    if response.status_code == 404:
        return {}
    if response.status_code == 429:
        raise FingerbankError("Fingerbank rate limit exceeded")
    if response.status_code >= 500:
        raise FingerbankError(f"Fingerbank API error ({response.status_code})")

    response.raise_for_status()
    return response.json()


def interrogate_fingerbank(
    conn: psycopg.Connection,
    asset_id: str,
    evidence_hash: str,
    evidence: dict[str, Any],
) -> dict[str, Any] | None:
    cached = get_cached_fingerbank_match(conn, asset_id, evidence_hash)
    if cached:
        if cached.get("no_match"):
            return None
        return cached

    payload = _fingerbank_request(evidence)
    if not payload:
        _store_no_match(conn, asset_id, evidence_hash)
        return None

    parsed = _parse_match_payload(payload)
    return _store_fingerbank_match(conn, asset_id, evidence_hash, parsed, payload)
