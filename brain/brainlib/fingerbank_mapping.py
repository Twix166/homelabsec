from __future__ import annotations

from typing import Any

import psycopg

from brainlib.assets import normalize_role


def _matches_pattern(candidate: str | None, pattern: str | None) -> bool:
    if not candidate or not pattern:
        return False
    return pattern.strip().lower() in candidate.strip().lower()


def _mapping_payload(row) -> dict[str, Any]:
    return {
        "mapping_id": str(row[0]),
        "fingerbank_device_id": row[1],
        "device_name_pattern": row[2],
        "manufacturer_pattern": row[3],
        "hierarchy_pattern": row[4],
        "mapped_role": row[5],
        "default_confidence": float(row[6]),
        "priority": row[7],
        "is_enabled": bool(row[8]),
        "notes": row[9],
    }


def resolve_fingerbank_role_mapping(
    conn: psycopg.Connection,
    *,
    fingerbank_device_id: int | None,
    device_name: str | None,
    manufacturer_name: str | None,
    device_hierarchy: str | None,
) -> dict[str, Any] | None:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT mapping_id,
                   fingerbank_device_id,
                   device_name_pattern,
                   manufacturer_pattern,
                   hierarchy_pattern,
                   mapped_role,
                   default_confidence,
                   priority,
                   is_enabled,
                   notes
            FROM fingerbank_role_mappings
            WHERE is_enabled = true
            ORDER BY priority DESC, mapped_role ASC
            """
        )
        rows = cur.fetchall()

    exact_matches = [row for row in rows if row[1] is not None and fingerbank_device_id == row[1]]
    if exact_matches:
        mapping = _mapping_payload(exact_matches[0])
        mapping["mapped_role"] = normalize_role(mapping["mapped_role"])
        return mapping

    hierarchy_matches = [row for row in rows if _matches_pattern(device_hierarchy, row[4])]
    if hierarchy_matches:
        mapping = _mapping_payload(hierarchy_matches[0])
        mapping["mapped_role"] = normalize_role(mapping["mapped_role"])
        return mapping

    name_matches = [row for row in rows if _matches_pattern(device_name, row[2])]
    if name_matches:
        mapping = _mapping_payload(name_matches[0])
        mapping["mapped_role"] = normalize_role(mapping["mapped_role"])
        return mapping

    manufacturer_matches = [row for row in rows if _matches_pattern(manufacturer_name, row[3])]
    if manufacturer_matches:
        mapping = _mapping_payload(manufacturer_matches[0])
        mapping["mapped_role"] = normalize_role(mapping["mapped_role"])
        return mapping

    return None
