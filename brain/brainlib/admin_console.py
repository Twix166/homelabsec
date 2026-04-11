from __future__ import annotations

import json
from typing import Any

import psycopg


DEFAULT_MODULES = [
    {
        "module_key": "mac_vendor_lookup",
        "display_name": "MAC Brand Lookup",
        "description": "Use a local OUI lookup to enrich MAC addresses with vendor or brand data when Nmap does not provide a vendor.",
        "enabled": True,
    },
    {
        "module_key": "llm_classification",
        "display_name": "LLM Categorisation",
        "description": "Use Ollama as a fallback enrichment step for role classification when no learned lookup entry matches.",
        "enabled": True,
    },
    {
        "module_key": "fingerbank_classification",
        "display_name": "Fingerbank Classification",
        "description": "Use Fingerbank evidence interrogation and role mappings as a passive-device classification enrichment step before the LLM fallback.",
        "enabled": True,
    },
    {
        "module_key": "lynis_audit",
        "display_name": "Lynis Audit",
        "description": "Trigger remote Lynis host audits over SSH and store the audit result as enrichment data.",
        "enabled": True,
    },
]


DEFAULT_RAW_DATA_SOURCES = [
    {
        "source_key": "nmap_xml_ingest",
        "display_name": "Nmap XML ingest",
        "source_kind": "network_scan",
        "description": "Accept raw Nmap XML discovery data into inventory and observations.",
        "enabled": True,
        "config_json": {},
    },
    {
        "source_key": "scheduler_discovery",
        "display_name": "Scheduled discovery",
        "source_kind": "network_scan",
        "description": "Periodic discovery driven by the scheduler service.",
        "enabled": True,
        "config_json": {"scan_engine": "nmap"},
    },
    {
        "source_key": "lynis_remote_audit",
        "display_name": "Lynis remote audit",
        "source_kind": "host_audit",
        "description": "Remote host security audit jobs executed over SSH by the Lynis runner microservice.",
        "enabled": True,
        "config_json": {"installer": "official_github_repo"},
    },
    {
        "source_key": "collector_dhcp",
        "display_name": "Passive DHCP collector",
        "source_kind": "passive_network",
        "description": "Passive DHCP observation collector for hostname, MAC, vendor, and DHCP fingerprint evidence.",
        "enabled": True,
        "config_json": {"transport": "tshark_or_tcpdump"},
    },
    {
        "source_key": "collector_mdns",
        "display_name": "Passive mDNS collector",
        "source_kind": "passive_network",
        "description": "Passive mDNS observation collector for advertised services and hostnames.",
        "enabled": True,
        "config_json": {"transport": "tshark"},
    },
    {
        "source_key": "collector_ssdp",
        "display_name": "Passive SSDP collector",
        "source_kind": "passive_network",
        "description": "Passive SSDP observation collector for UPnP server strings, user agents, and locations.",
        "enabled": True,
        "config_json": {"transport": "tshark"},
    },
]


def ensure_admin_console_defaults(conn: psycopg.Connection) -> None:
    with conn.cursor() as cur:
        for module in DEFAULT_MODULES:
            cur.execute(
                """
                INSERT INTO enrichment_modules (module_key, display_name, description, enabled)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (module_key) DO NOTHING
                """,
                (
                    module["module_key"],
                    module["display_name"],
                    module["description"],
                    module["enabled"],
                ),
            )
        for source in DEFAULT_RAW_DATA_SOURCES:
            cur.execute(
                """
                INSERT INTO raw_data_sources (source_key, display_name, source_kind, description, enabled, config_json)
                VALUES (%s, %s, %s, %s, %s, %s::jsonb)
                ON CONFLICT (source_key) DO NOTHING
                """,
                (
                    source["source_key"],
                    source["display_name"],
                    source["source_kind"],
                    source["description"],
                    source["enabled"],
                    json.dumps(source["config_json"]),
                ),
            )
        conn.commit()


def is_module_enabled(conn: psycopg.Connection, module_key: str, default: bool = True) -> bool:
    ensure_admin_console_defaults(conn)
    with conn.cursor() as cur:
        cur.execute("SELECT enabled FROM enrichment_modules WHERE module_key = %s", (module_key,))
        row = cur.fetchone()
    if row is None:
        return default
    return bool(row[0])


def is_raw_data_source_enabled(conn: psycopg.Connection, source_key: str, default: bool = True) -> bool:
    ensure_admin_console_defaults(conn)
    with conn.cursor() as cur:
        cur.execute("SELECT enabled FROM raw_data_sources WHERE source_key = %s", (source_key,))
        row = cur.fetchone()
    if row is None:
        return default
    return bool(row[0])


def list_enrichment_modules(conn: psycopg.Connection) -> dict[str, Any]:
    ensure_admin_console_defaults(conn)
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT module_key, display_name, description, enabled, updated_at
            FROM enrichment_modules
            ORDER BY display_name ASC
            """
        )
        rows = cur.fetchall()

    return {
        "modules": [
            {
                "module_key": row[0],
                "display_name": row[1],
                "description": row[2],
                "enabled": bool(row[3]),
                "updated_at": row[4].isoformat(),
            }
            for row in rows
        ]
    }


def update_enrichment_module(conn: psycopg.Connection, module_key: str, enabled: bool) -> dict[str, Any]:
    ensure_admin_console_defaults(conn)
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE enrichment_modules
            SET enabled = %s,
                updated_at = now()
            WHERE module_key = %s
            RETURNING module_key, display_name, description, enabled, updated_at
            """,
            (enabled, module_key),
        )
        row = cur.fetchone()
        conn.commit()

    if row is None:
        raise KeyError(module_key)

    return {
        "module_key": row[0],
        "display_name": row[1],
        "description": row[2],
        "enabled": bool(row[3]),
        "updated_at": row[4].isoformat(),
    }


def list_raw_data_sources(conn: psycopg.Connection) -> dict[str, Any]:
    ensure_admin_console_defaults(conn)
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT source_key, display_name, source_kind, description, enabled, config_json, updated_at
            FROM raw_data_sources
            ORDER BY display_name ASC
            """
        )
        rows = cur.fetchall()

    return {
        "sources": [
            {
                "source_key": row[0],
                "display_name": row[1],
                "source_kind": row[2],
                "description": row[3],
                "enabled": bool(row[4]),
                "config": row[5],
                "updated_at": row[6].isoformat(),
            }
            for row in rows
        ]
    }


def update_raw_data_source(conn: psycopg.Connection, source_key: str, enabled: bool) -> dict[str, Any]:
    ensure_admin_console_defaults(conn)
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE raw_data_sources
            SET enabled = %s,
                updated_at = now()
            WHERE source_key = %s
            RETURNING source_key, display_name, source_kind, description, enabled, config_json, updated_at
            """,
            (enabled, source_key),
        )
        row = cur.fetchone()
        conn.commit()

    if row is None:
        raise KeyError(source_key)

    return {
        "source_key": row[0],
        "display_name": row[1],
        "source_kind": row[2],
        "description": row[3],
        "enabled": bool(row[4]),
        "config": row[5],
        "updated_at": row[6].isoformat(),
    }
