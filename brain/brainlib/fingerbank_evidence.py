from __future__ import annotations

import hashlib
import json
from typing import Any

import psycopg


def _canonical_json(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _clean_scalar(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        cleaned = value.strip()
        return cleaned or None
    return str(value)


def _dedupe_sorted(values: list[str]) -> list[str]:
    return sorted({item.strip() for item in values if item and item.strip()})


def _extract_rows(
    conn: psycopg.Connection,
    asset_id: str,
    observation_type: str,
    *,
    limit: int = 50,
) -> list[dict[str, Any]]:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT raw_json
            FROM network_observations
            WHERE asset_id = %s
              AND raw_json->>'type' = %s
            ORDER BY observed_at DESC
            LIMIT %s
            """,
            (asset_id, observation_type, limit),
        )
        return [row[0] for row in cur.fetchall()]


def collect_recent_dhcp(conn: psycopg.Connection, asset_id: str) -> dict[str, Any]:
    rows = _extract_rows(conn, asset_id, "dhcp")
    if not rows:
        return {}

    latest = rows[0]
    return {
        "mac": _clean_scalar(latest.get("src_mac")),
        "hostname": _clean_scalar(latest.get("hostname")),
        "dhcp_fingerprint": _clean_scalar(latest.get("dhcp_fingerprint")),
        "dhcp_vendor": _clean_scalar(latest.get("dhcp_vendor")),
        "src_ip": _clean_scalar(latest.get("src_ip")),
    }


def collect_recent_mdns(conn: psycopg.Connection, asset_id: str) -> dict[str, Any]:
    rows = _extract_rows(conn, asset_id, "mdns")
    if not rows:
        return {}

    services: list[str] = []
    hostname = None
    for row in rows:
        if hostname is None:
            hostname = _clean_scalar(row.get("hostname"))
        services.extend(
            item
            for item in row.get("services", [])
            if isinstance(item, str)
        )

    return {
        "hostname": hostname,
        "mdns_services": _dedupe_sorted(services),
    }


def collect_recent_ssdp(conn: psycopg.Connection, asset_id: str) -> dict[str, Any]:
    rows = _extract_rows(conn, asset_id, "ssdp")
    if not rows:
        return {}

    server_strings: list[str] = []
    user_agents: list[str] = []
    for row in rows:
        server = _clean_scalar(row.get("upnp_server_string"))
        user_agent = _clean_scalar(row.get("upnp_user_agent"))
        if server:
            server_strings.append(server)
        if user_agent:
            user_agents.append(user_agent)

    return {
        "upnp_server_strings": _dedupe_sorted(server_strings),
        "upnp_user_agents": _dedupe_sorted(user_agents),
    }


def merge_evidence(
    dhcp_data: dict[str, Any],
    mdns_data: dict[str, Any],
    ssdp_data: dict[str, Any],
) -> dict[str, Any]:
    mac = dhcp_data.get("mac")
    hostname = dhcp_data.get("hostname") or mdns_data.get("hostname")
    evidence = {
        "mac": mac,
        "hostname": hostname,
        "dhcp_fingerprint": dhcp_data.get("dhcp_fingerprint"),
        "dhcp_vendor": dhcp_data.get("dhcp_vendor"),
        "mdns_services": _dedupe_sorted(list(mdns_data.get("mdns_services", []))),
        "upnp_server_strings": _dedupe_sorted(list(ssdp_data.get("upnp_server_strings", []))),
        "upnp_user_agents": _dedupe_sorted(list(ssdp_data.get("upnp_user_agents", []))),
    }
    return {key: value for key, value in evidence.items() if value not in (None, "", [])}


def evidence_hash_for_payload(evidence: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(evidence).encode("utf-8")).hexdigest()


def store_fingerbank_evidence(
    conn: psycopg.Connection,
    asset_id: str,
    evidence: dict[str, Any],
    *,
    sources: dict[str, Any],
) -> dict[str, Any]:
    evidence_hash = evidence_hash_for_payload(evidence)

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT evidence_id, created_at
            FROM fingerbank_evidence
            WHERE asset_id = %s
              AND evidence_hash = %s
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (asset_id, evidence_hash),
        )
        existing = cur.fetchone()
        if existing:
            return {
                "evidence_id": str(existing[0]),
                "asset_id": asset_id,
                "evidence_hash": evidence_hash,
                "evidence": evidence,
                "sources": sources,
                "created_at": existing[1].isoformat(),
                "stored": False,
            }

        cur.execute(
            """
            INSERT INTO fingerbank_evidence (asset_id, evidence_hash, evidence_json, sources_json)
            VALUES (%s, %s, %s::jsonb, %s::jsonb)
            RETURNING evidence_id, created_at
            """,
            (asset_id, evidence_hash, _canonical_json(evidence), _canonical_json(sources)),
        )
        inserted = cur.fetchone()
        conn.commit()

    return {
        "evidence_id": str(inserted[0]),
        "asset_id": asset_id,
        "evidence_hash": evidence_hash,
        "evidence": evidence,
        "sources": sources,
        "created_at": inserted[1].isoformat(),
        "stored": True,
    }


def build_fingerbank_evidence(conn: psycopg.Connection, asset_id: str) -> dict[str, Any] | None:
    dhcp_data = collect_recent_dhcp(conn, asset_id)
    mdns_data = collect_recent_mdns(conn, asset_id)
    ssdp_data = collect_recent_ssdp(conn, asset_id)

    evidence = merge_evidence(dhcp_data, mdns_data, ssdp_data)
    if not evidence:
        return None

    sources = {
        "dhcp": bool(dhcp_data),
        "mdns": bool(mdns_data),
        "ssdp": bool(ssdp_data),
    }
    return store_fingerbank_evidence(conn, asset_id, evidence, sources=sources)
