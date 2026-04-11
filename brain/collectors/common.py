from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from typing import Any

from brainlib.assets import get_or_create_asset
from brainlib.database import db
from brainlib.logging_utils import configure_logging, log_event


logger = configure_logging("homelabsec.collectors")
MAC_RE = re.compile(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})")
IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def command_available(command: str) -> bool:
    return shutil.which(command) is not None


def run_command(command: list[str], *, timeout: int = 15) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        return None


def flatten_json_values(value: Any) -> list[tuple[str, str]]:
    flattened: list[tuple[str, str]] = []

    def _walk(prefix: str, node: Any) -> None:
        if isinstance(node, dict):
            for key, child in node.items():
                next_prefix = f"{prefix}.{key}" if prefix else str(key)
                _walk(next_prefix, child)
        elif isinstance(node, list):
            for child in node:
                _walk(prefix, child)
        elif node is not None:
            flattened.append((prefix, str(node)))

    _walk("", value)
    return flattened


def first_matching_value(payload: Any, *suffixes: str) -> str | None:
    suffixes_lower = tuple(suffix.lower() for suffix in suffixes)
    for key, value in flatten_json_values(payload):
        if any(key.lower().endswith(suffix) for suffix in suffixes_lower):
            cleaned = value.strip()
            if cleaned:
                return cleaned
    return None


def all_matching_values(payload: Any, *suffixes: str) -> list[str]:
    suffixes_lower = tuple(suffix.lower() for suffix in suffixes)
    values: list[str] = []
    for key, value in flatten_json_values(payload):
        if any(key.lower().endswith(suffix) for suffix in suffixes_lower):
            cleaned = value.strip()
            if cleaned:
                values.append(cleaned)
    return sorted(set(values))


def normalize_mac(value: str | None) -> str | None:
    if not value:
        return None
    match = MAC_RE.search(value)
    if not match:
        return None
    return match.group(1).lower()


def normalize_ip(value: str | None) -> str | None:
    if not value:
        return None
    match = IP_RE.search(value)
    if not match:
        return None
    return match.group(0)


def normalize_hostname(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = value.strip().rstrip(".")
    return cleaned or None


def parse_tshark_json(stdout: str) -> list[dict[str, Any]]:
    cleaned = stdout.strip()
    if not cleaned:
        return []
    try:
        payload = json.loads(cleaned)
    except json.JSONDecodeError:
        return []
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        return [payload]
    return []


def insert_passive_observation(
    source_key: str,
    observation_type: str,
    record: dict[str, Any],
) -> str | None:
    ip_address = normalize_ip(record.get("src_ip") or record.get("ip"))
    mac_address = normalize_mac(record.get("src_mac") or record.get("mac"))
    hostname = normalize_hostname(record.get("hostname"))

    if not any([ip_address, mac_address, hostname]):
        return None

    with db() as conn:
        asset_id = get_or_create_asset(conn, ip_address, mac_address, hostname)
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO scan_runs (scan_type, status, started_at, completed_at)
                VALUES (%s, 'completed', now(), now())
                RETURNING scan_run_id
                """,
                (source_key,),
            )
            scan_run_id = cur.fetchone()[0]

            service_name = None
            if observation_type == "mdns":
                services = record.get("services", [])
                service_name = services[0] if services else None
            elif observation_type == "ssdp":
                service_name = record.get("upnp_server_string") or record.get("upnp_user_agent")

            cur.execute(
                """
                INSERT INTO network_observations (
                    scan_run_id,
                    asset_id,
                    ip_address,
                    mac_address,
                    mac_vendor,
                    reachable,
                    service_name,
                    raw_json
                )
                VALUES (%s, %s, %s, %s, %s, true, %s, %s::jsonb)
                """,
                (
                    scan_run_id,
                    asset_id,
                    ip_address,
                    mac_address,
                    record.get("dhcp_vendor"),
                    service_name,
                    json.dumps(record, sort_keys=True),
                ),
            )
        conn.commit()
        return str(asset_id)


def collector_sleep(seconds: float) -> None:
    time.sleep(seconds)


def log_collector_event(level: str, event: str, message: str, **fields: Any) -> None:
    log_event(logger, level, event, message, **fields)
