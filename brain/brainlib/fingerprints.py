from __future__ import annotations

import hashlib
import json
from typing import Any, Optional

import psycopg


def build_fingerprint(conn: psycopg.Connection, asset_id: str) -> dict[str, Any]:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT preferred_name, first_seen, last_seen, role, role_confidence
            FROM assets
            WHERE asset_id = %s
            """,
            (asset_id,),
        )
        asset = cur.fetchone()
        if not asset:
            raise ValueError(f"Asset {asset_id} not found")

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
            SELECT ip_address, mac_address, mac_vendor, port, protocol, service_name, service_product, service_version, os_guess
            FROM network_observations
            WHERE asset_id = %s
            ORDER BY observed_at DESC
            """,
            (asset_id,),
        )
        rows = cur.fetchall()

    ip_addresses = sorted({str(r[0]) for r in rows if r[0]})
    mac_addresses = sorted({str(r[1]) for r in rows if r[1]})
    open_ports = []
    os_guess = None

    seen_ports = set()
    for r in rows:
        if not os_guess and r[8]:
            os_guess = r[8]
        if r[3] is not None:
            key = (r[3], r[4], r[5], r[6], r[7])
            if key not in seen_ports:
                seen_ports.add(key)
                open_ports.append(
                    {
                        "port": r[3],
                        "protocol": r[4],
                        "service_name": r[5],
                        "service_product": r[6],
                        "service_version": r[7],
                    }
                )

    return {
        "identity": {
            "preferred_name": asset[0],
            "identifiers": identifiers,
        },
        "network": {
            "ip_addresses": ip_addresses,
            "mac_addresses": mac_addresses,
            "open_ports": sorted(open_ports, key=lambda p: (p["port"], p["protocol"])),
            "os_guess": os_guess,
        },
        "history": {
            "first_seen": asset[1].isoformat(),
            "last_seen": asset[2].isoformat(),
        },
        "role": asset[3],
        "role_confidence": float(asset[4]) if asset[4] is not None else None,
    }


def fingerprint_hash(fingerprint: dict[str, Any]) -> str:
    stable_fp = json.loads(json.dumps(fingerprint))
    history = stable_fp.get("history", {})
    if isinstance(history, dict):
        history.pop("last_seen", None)

    canonical = json.dumps(stable_fp, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def get_latest_fingerprint(conn: psycopg.Connection, asset_id: str) -> Optional[dict[str, Any]]:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT fingerprint_json, fingerprint_hash, created_at
            FROM fingerprints
            WHERE asset_id = %s
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (asset_id,),
        )
        row = cur.fetchone()

    if not row:
        return None

    return {
        "fingerprint": row[0],
        "fingerprint_hash": row[1],
        "created_at": row[2].isoformat(),
    }


def store_fingerprint_if_changed(
    conn: psycopg.Connection,
    asset_id: str,
    fingerprint: dict[str, Any],
) -> dict[str, Any]:
    new_hash = fingerprint_hash(fingerprint)

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT fingerprint_id, fingerprint_hash, created_at
            FROM fingerprints
            WHERE asset_id = %s
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (asset_id,),
        )
        row = cur.fetchone()

        if row and row[1] == new_hash:
            return {
                "stored": False,
                "fingerprint_id": str(row[0]),
                "fingerprint_hash": row[1],
                "created_at": row[2].isoformat(),
            }

        cur.execute(
            """
            INSERT INTO fingerprints (asset_id, fingerprint_hash, fingerprint_json)
            VALUES (%s, %s, %s)
            RETURNING fingerprint_id, created_at
            """,
            (asset_id, new_hash, json.dumps(fingerprint)),
        )
        inserted = cur.fetchone()
        conn.commit()

    return {
        "stored": True,
        "fingerprint_id": str(inserted[0]),
        "fingerprint_hash": new_hash,
        "created_at": inserted[1].isoformat(),
    }


def get_previous_fingerprint(conn: psycopg.Connection, asset_id: str) -> Optional[dict[str, Any]]:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT fingerprint_json, fingerprint_hash, created_at
            FROM fingerprints
            WHERE asset_id = %s
            ORDER BY created_at DESC
            OFFSET 1
            LIMIT 1
            """,
            (asset_id,),
        )
        row = cur.fetchone()

    if not row:
        return None

    return {
        "fingerprint": row[0],
        "fingerprint_hash": row[1],
        "created_at": row[2].isoformat(),
    }


def diff_fingerprints(
    old_fp: Optional[dict[str, Any]],
    new_fp: dict[str, Any],
) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []

    old_identity = (old_fp or {}).get("identity", {})
    new_identity = new_fp.get("identity", {})
    old_network = (old_fp or {}).get("network", {})
    new_network = new_fp.get("network", {})
    old_role = (old_fp or {}).get("role")
    new_role = new_fp.get("role")

    old_ips = set(old_network.get("ip_addresses", []))
    new_ips = set(new_network.get("ip_addresses", []))
    old_macs = set(old_network.get("mac_addresses", []))
    new_macs = set(new_network.get("mac_addresses", []))

    old_ports = {
        (
            p.get("port"),
            p.get("protocol"),
            p.get("service_name"),
            p.get("service_product"),
            p.get("service_version"),
        )
        for p in old_network.get("open_ports", [])
    }
    new_ports = {
        (
            p.get("port"),
            p.get("protocol"),
            p.get("service_name"),
            p.get("service_product"),
            p.get("service_version"),
        )
        for p in new_network.get("open_ports", [])
    }

    if old_fp is None:
        changes.append(
            {
                "change_type": "new_asset",
                "severity": "medium",
                "confidence": 1.0,
                "old_value": None,
                "new_value": {
                    "preferred_name": new_identity.get("preferred_name"),
                    "ip_addresses": sorted(new_ips),
                    "mac_addresses": sorted(new_macs),
                },
                "evidence": {"source": "fingerprint_diff"},
            }
        )
        return changes

    if old_ips != new_ips:
        changes.append(
            {
                "change_type": "ip_addresses_changed",
                "severity": "info",
                "confidence": 0.95,
                "old_value": sorted(old_ips),
                "new_value": sorted(new_ips),
                "evidence": {"source": "fingerprint_diff"},
            }
        )

    if old_macs != new_macs:
        changes.append(
            {
                "change_type": "mac_addresses_changed",
                "severity": "medium",
                "confidence": 0.95,
                "old_value": sorted(old_macs),
                "new_value": sorted(new_macs),
                "evidence": {"source": "fingerprint_diff"},
            }
        )

    def _port_sort_key(port_tuple):
        return (
            port_tuple[0] if port_tuple[0] is not None else -1,
            str(port_tuple[1] or ""),
            str(port_tuple[2] or ""),
            str(port_tuple[3] or ""),
            str(port_tuple[4] or ""),
        )

    for port in sorted(new_ports - old_ports, key=_port_sort_key):
        changes.append(
            {
                "change_type": "new_port_opened",
                "severity": "medium",
                "confidence": 0.90,
                "old_value": None,
                "new_value": {
                    "port": port[0],
                    "protocol": port[1],
                    "service_name": port[2],
                    "service_product": port[3],
                    "service_version": port[4],
                },
                "evidence": {"source": "fingerprint_diff"},
            }
        )

    for port in sorted(old_ports - new_ports, key=_port_sort_key):
        changes.append(
            {
                "change_type": "port_closed",
                "severity": "info",
                "confidence": 0.90,
                "old_value": {
                    "port": port[0],
                    "protocol": port[1],
                    "service_name": port[2],
                    "service_product": port[3],
                    "service_version": port[4],
                },
                "new_value": None,
                "evidence": {"source": "fingerprint_diff"},
            }
        )

    if old_role != new_role:
        changes.append(
            {
                "change_type": "role_changed",
                "severity": "low",
                "confidence": 0.80,
                "old_value": old_role,
                "new_value": new_role,
                "evidence": {"source": "fingerprint_diff"},
            }
        )

    return changes


def jsonb_param(value: Any) -> Optional[str]:
    if value is None:
        return None
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def change_dedupe_key(asset_id: str, change: dict[str, Any]) -> tuple[Any, ...]:
    return (
        asset_id,
        change.get("change_type"),
        change.get("severity"),
        change.get("confidence"),
        jsonb_param(change.get("old_value")),
        jsonb_param(change.get("new_value")),
        jsonb_param(change.get("evidence", {})),
    )


def persist_changes(
    conn: psycopg.Connection,
    asset_id: str,
    changes: list[dict[str, Any]],
) -> dict[str, Any]:
    inserted = 0
    skipped = 0
    seen_keys: set[tuple[Any, ...]] = set()

    with conn.cursor() as cur:
        for change in changes:
            dedupe_key = change_dedupe_key(asset_id, change)
            if dedupe_key in seen_keys:
                skipped += 1
                continue

            seen_keys.add(dedupe_key)

            old_value_json = dedupe_key[4]
            new_value_json = dedupe_key[5]
            evidence_json = dedupe_key[6]

            cur.execute(
                """
                SELECT 1
                FROM changes
                WHERE asset_id = %s
                  AND change_type = %s
                  AND severity = %s
                  AND confidence = %s
                  AND old_value IS NOT DISTINCT FROM %s::jsonb
                  AND new_value IS NOT DISTINCT FROM %s::jsonb
                  AND evidence IS NOT DISTINCT FROM %s::jsonb
                LIMIT 1
                """,
                (
                    asset_id,
                    change.get("change_type"),
                    change.get("severity"),
                    change.get("confidence"),
                    old_value_json,
                    new_value_json,
                    evidence_json,
                ),
            )
            if cur.fetchone():
                skipped += 1
                continue

            cur.execute(
                """
                INSERT INTO changes (
                    asset_id,
                    change_type,
                    severity,
                    confidence,
                    old_value,
                    new_value,
                    evidence
                )
                VALUES (%s, %s, %s, %s, %s::jsonb, %s::jsonb, %s::jsonb)
                """,
                (
                    asset_id,
                    change.get("change_type"),
                    change.get("severity"),
                    change.get("confidence"),
                    old_value_json,
                    new_value_json,
                    evidence_json,
                ),
            )
            inserted += 1

    conn.commit()

    return {
        "inserted": inserted,
        "skipped": skipped,
    }


def detect_and_persist_changes_for_asset(
    conn: psycopg.Connection,
    asset_id: str,
) -> dict[str, Any]:
    latest = get_latest_fingerprint(conn, asset_id)

    if latest is None:
        return {
            "asset_id": asset_id,
            "latest_fingerprint_created_at": None,
            "previous_fingerprint_created_at": None,
            "changes": [],
            "persist_result": {"inserted": 0, "skipped": 0},
        }

    previous = get_previous_fingerprint(conn, asset_id)
    changes = diff_fingerprints(
        previous["fingerprint"] if previous else None,
        latest["fingerprint"],
    )
    evidence = {
        "source": "fingerprint_diff",
        "latest_fingerprint_hash": latest["fingerprint_hash"],
        "previous_fingerprint_hash": previous["fingerprint_hash"] if previous else None,
    }
    for change in changes:
        base_evidence = change.get("evidence", {})
        change["evidence"] = {
            **evidence,
            **base_evidence,
        }
    persist_result = persist_changes(conn, asset_id, changes)

    return {
        "asset_id": asset_id,
        "latest_fingerprint_created_at": latest["created_at"],
        "previous_fingerprint_created_at": previous["created_at"] if previous else None,
        "changes": changes,
        "persist_result": persist_result,
    }
