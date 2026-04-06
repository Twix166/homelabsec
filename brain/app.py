import hashlib
import json
import os
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Optional

import psycopg
import requests
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

DATABASE_URL = os.environ["DATABASE_URL"]
OLLAMA_URL = os.environ["OLLAMA_URL"].rstrip("/")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "homelabsec-classifier")

app = FastAPI(title="HomelabSec Brain")


def db():
    return psycopg.connect(DATABASE_URL)


class NmapXmlIngestRequest(BaseModel):
    xml_path: str


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def normalize_role(role: str) -> str:
    if not role:
        return "unknown"

    r = role.strip().lower().replace(" ", "_").replace("-", "_")

    mapping = {
        "nas": "nas",
        "file_server": "nas",
        "storage": "nas",

        "printer": "printer",

        "camera": "camera",
        "webcam": "camera",
        "surveillance_camera": "camera",

        "gateway": "gateway",
        "router": "gateway",

        "web_server": "web_server",
        "webserver": "web_server",

        "server": "server",
        "ssh_server": "server",
        "ftp_server": "server",
        "dns_server": "server",

        "workstation": "workstation",
        "desktop": "workstation",
        "laptop": "workstation",

        "mobile_device": "mobile_device",
        "phone": "mobile_device",
        "tablet": "mobile_device",

        "iot_device": "iot_device",
        "smart_device": "iot_device",

        "proxy": "proxy",

        "access_point": "access_point",
        "ap": "access_point",

        "switch": "switch",

        "unknown": "unknown",
    }

    return mapping.get(r, "unknown")

def get_or_create_asset(
    conn: psycopg.Connection,
    ip: Optional[str],
    mac: Optional[str],
    hostname: Optional[str],
) -> str:
    with conn.cursor() as cur:
        if mac:
            cur.execute(
                """
                SELECT asset_id
                FROM asset_identifiers
                WHERE identifier_type = 'mac' AND identifier_value = %s
                """,
                (mac,),
            )
            row = cur.fetchone()
            if row:
                asset_id = str(row[0])
                cur.execute(
                    "UPDATE assets SET last_seen = now() WHERE asset_id = %s",
                    (asset_id,),
                )
                if ip:
                    cur.execute(
                        """
                        INSERT INTO asset_identifiers (asset_id, identifier_type, identifier_value)
                        VALUES (%s, 'ip', %s)
                        ON CONFLICT (identifier_type, identifier_value) DO NOTHING
                        """,
                        (asset_id, ip),
                    )
                if hostname:
                    cur.execute(
                        """
                        INSERT INTO asset_identifiers (asset_id, identifier_type, identifier_value)
                        VALUES (%s, 'hostname', %s)
                        ON CONFLICT (identifier_type, identifier_value) DO NOTHING
                        """,
                        (asset_id, hostname),
                    )
                conn.commit()
                return asset_id

        if ip:
            cur.execute(
                """
                SELECT asset_id
                FROM asset_identifiers
                WHERE identifier_type = 'ip' AND identifier_value = %s
                """,
                (ip,),
            )
            row = cur.fetchone()
            if row:
                asset_id = str(row[0])
                cur.execute(
                    "UPDATE assets SET last_seen = now() WHERE asset_id = %s",
                    (asset_id,),
                )
                if mac:
                    cur.execute(
                        """
                        INSERT INTO asset_identifiers (asset_id, identifier_type, identifier_value)
                        VALUES (%s, 'mac', %s)
                        ON CONFLICT (identifier_type, identifier_value) DO NOTHING
                        """,
                        (asset_id, mac),
                    )
                if hostname:
                    cur.execute(
                        """
                        INSERT INTO asset_identifiers (asset_id, identifier_type, identifier_value)
                        VALUES (%s, 'hostname', %s)
                        ON CONFLICT (identifier_type, identifier_value) DO NOTHING
                        """,
                        (asset_id, hostname),
                    )
                conn.commit()
                return asset_id

        cur.execute(
            """
            INSERT INTO assets (preferred_name)
            VALUES (%s)
            RETURNING asset_id
            """,
            (hostname or ip or mac or "unknown",),
        )
        asset_id = str(cur.fetchone()[0])

        if ip:
            cur.execute(
                """
                INSERT INTO asset_identifiers (asset_id, identifier_type, identifier_value)
                VALUES (%s, 'ip', %s)
                ON CONFLICT (identifier_type, identifier_value) DO NOTHING
                """,
                (asset_id, ip),
            )
        if mac:
            cur.execute(
                """
                INSERT INTO asset_identifiers (asset_id, identifier_type, identifier_value)
                VALUES (%s, 'mac', %s)
                ON CONFLICT (identifier_type, identifier_value) DO NOTHING
                """,
                (asset_id, mac),
            )
        if hostname:
            cur.execute(
                """
                INSERT INTO asset_identifiers (asset_id, identifier_type, identifier_value)
                VALUES (%s, 'hostname', %s)
                ON CONFLICT (identifier_type, identifier_value) DO NOTHING
                """,
                (asset_id, hostname),
            )

        conn.commit()
        return asset_id


def parse_nmap_xml(xml_path: str) -> list[dict[str, Any]]:
    tree = ET.parse(xml_path)
    root = tree.getroot()
    hosts: list[dict[str, Any]] = []

    for host in root.findall("host"):
        status_el = host.find("status")
        if status_el is not None and status_el.attrib.get("state") != "up":
            continue

        ip = None
        mac = None
        vendor = None

        for addr in host.findall("address"):
            addrtype = addr.attrib.get("addrtype")
            if addrtype == "ipv4":
                ip = addr.attrib.get("addr")
            elif addrtype == "mac":
                mac = addr.attrib.get("addr")
                vendor = addr.attrib.get("vendor")

        hostname = None
        hostnames_el = host.find("hostnames")
        if hostnames_el is not None:
            first_hn = hostnames_el.find("hostname")
            if first_hn is not None:
                hostname = first_hn.attrib.get("name")

        os_guess = None
        os_el = host.find("os")
        if os_el is not None:
            match = os_el.find("osmatch")
            if match is not None:
                os_guess = match.attrib.get("name")

        ports: list[dict[str, Any]] = []
        ports_el = host.find("ports")
        if ports_el is not None:
            for port in ports_el.findall("port"):
                state_el = port.find("state")
                if state_el is None or state_el.attrib.get("state") != "open":
                    continue
                service_el = port.find("service")
                ports.append(
                    {
                        "port": int(port.attrib["portid"]),
                        "protocol": port.attrib.get("protocol", "tcp"),
                        "service_name": service_el.attrib.get("name") if service_el is not None else None,
                        "service_product": service_el.attrib.get("product") if service_el is not None else None,
                        "service_version": service_el.attrib.get("version") if service_el is not None else None,
                    }
                )

        hosts.append(
            {
                "ip": ip,
                "mac": mac,
                "vendor": vendor,
                "hostname": hostname,
                "os_guess": os_guess,
                "ports": ports,
            }
        )

    return hosts


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
    # make a deep copy via JSON roundtrip so we can safely normalize it
    stable_fp = json.loads(json.dumps(fingerprint))

    # remove volatile fields that should not create a new fingerprint version
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

    for port in sorted(new_ports - old_ports):
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

    for port in sorted(old_ports - new_ports):
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

def persist_changes(
    conn: psycopg.Connection,
    asset_id: str,
    changes: list[dict[str, Any]],
) -> dict[str, Any]:
    inserted = 0
    skipped = 0

    # latest scan_run_id for this asset from fingerprints/network observations
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT scan_run_id
            FROM fingerprints
            WHERE asset_id = %s
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (asset_id,),
        )
        row = cur.fetchone()

        if not row:
            return {"inserted": 0, "skipped": 0}

        scan_run_id = row[0]

        for change in changes:
            change_type = change.get("change_type")
            old_value = change.get("old_value")
            new_value = change.get("new_value")

            # de-dup by same asset + same scan + same change_type + same values
            cur.execute(
                """
                SELECT change_id
                FROM changes
                WHERE asset_id = %s
                  AND scan_run_id = %s
                  AND change_type = %s
                  AND COALESCE(old_value, 'null'::jsonb) = COALESCE(%s::jsonb, 'null'::jsonb)
                  AND COALESCE(new_value, 'null'::jsonb) = COALESCE(%s::jsonb, 'null'::jsonb)
                LIMIT 1
                """,
                (
                    asset_id,
                    scan_run_id,
                    change_type,
                    json.dumps(old_value) if old_value is not None else None,
                    json.dumps(new_value) if new_value is not None else None,
                ),
            )
            existing = cur.fetchone()

            if existing:
                skipped += 1
                continue

            cur.execute(
                """
                INSERT INTO changes (
                    asset_id,
                    scan_run_id,
                    change_type,
                    severity,
                    confidence,
                    old_value,
                    new_value,
                    evidence
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    asset_id,
                    scan_run_id,
                    change.get("change_type"),
                    change.get("severity", "info"),
                    change.get("confidence", 0.5),
                    json.dumps(change.get("old_value")) if change.get("old_value") is not None else None,
                    json.dumps(change.get("new_value")) if change.get("new_value") is not None else None,
                    json.dumps(change.get("evidence", {})),
                ),
            )
            inserted += 1

        conn.commit()

    return {"inserted": inserted, "skipped": skipped}

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

    persist_result = persist_changes(conn, asset_id, changes)

    return {
        "asset_id": asset_id,
        "latest_fingerprint_created_at": latest["created_at"],
        "previous_fingerprint_created_at": previous["created_at"] if previous else None,
        "changes": changes,
        "persist_result": persist_result,
    }



@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/ollama/test")
def ollama_test() -> dict[str, Any]:
    payload = {
        "model": OLLAMA_MODEL,
        "format": "json",
        "stream": False,
        "messages": [
            {
                "role": "system",
                "content": "Return strict JSON only with keys role and confidence.",
            },
            {
                "role": "user",
                "content": "Classify a host with ports 22, 80, 443 and nginx detected.",
            },
        ],
    }
    r = requests.post(f"{OLLAMA_URL}/api/chat", json=payload, timeout=120)
    r.raise_for_status()
    data = r.json()
    content = data["message"]["content"]
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError:
        parsed = {"raw_content": content}
    return {"model": data.get("model"), "result": parsed}


@app.post("/ingest/nmap_xml")
def ingest_nmap_xml(req: NmapXmlIngestRequest):
    if not os.path.exists(req.xml_path):
        raise HTTPException(status_code=404, detail="XML file not found")

    parsed_hosts = parse_nmap_xml(req.xml_path)
    inserted = 0

    with db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO scan_runs (scan_type, status)
                VALUES ('nmap_xml_ingest', 'completed')
                RETURNING scan_run_id
                """
            )
            scan_run_id = str(cur.fetchone()[0])
            conn.commit()

        for item in parsed_hosts:
            asset_id = get_or_create_asset(conn, item["ip"], item["mac"], item["hostname"])

            with conn.cursor() as cur:
                if item["ports"]:
                    for p in item["ports"]:
                        cur.execute(
                            """
                            INSERT INTO network_observations (
                                scan_run_id, asset_id, ip_address, mac_address, mac_vendor,
                                reachable, port, protocol, service_name, service_product, service_version,
                                os_guess, raw_json
                            )
                            VALUES (%s, %s, %s, %s, %s, true, %s, %s, %s, %s, %s, %s, %s)
                            """,
                            (
                                scan_run_id,
                                asset_id,
                                item["ip"],
                                item["mac"],
                                item["vendor"],
                                p["port"],
                                p["protocol"],
                                p["service_name"],
                                p["service_product"],
                                p["service_version"],
                                item["os_guess"],
                                json.dumps(item),
                            ),
                        )
                        inserted += 1
                else:
                    cur.execute(
                        """
                        INSERT INTO network_observations (
                            scan_run_id, asset_id, ip_address, mac_address, mac_vendor,
                            reachable, os_guess, raw_json
                        )
                        VALUES (%s, %s, %s, %s, %s, true, %s, %s)
                        """,
                        (
                            scan_run_id,
                            asset_id,
                            item["ip"],
                            item["mac"],
                            item["vendor"],
                            item["os_guess"],
                            json.dumps(item),
                        ),
                    )
                    inserted += 1

                fp = build_fingerprint(conn, asset_id)
                store_fingerprint_if_changed(conn, asset_id, fp)

            conn.commit()

    return {
        "scan_run_id": scan_run_id,
        "hosts_parsed": len(parsed_hosts),
        "observations_inserted": inserted,
    }


@app.get("/assets")
def list_assets():
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT asset_id, preferred_name, role, role_confidence, first_seen, last_seen
                FROM assets
                ORDER BY last_seen DESC
                """
            )
            rows = cur.fetchall()

    return {
        "assets": [
            {
                "asset_id": str(r[0]),
                "preferred_name": r[1],
                "role": r[2],
                "role_confidence": float(r[3]) if r[3] is not None else None,
                "first_seen": r[4].isoformat(),
                "last_seen": r[5].isoformat(),
            }
            for r in rows
        ]
    }


@app.post("/classify/{asset_id}")
def classify_asset(asset_id: str):
    with db() as conn:
        fp = build_fingerprint(conn, asset_id)

        payload = {
            "model": OLLAMA_MODEL,
            "format": "json",
            "stream": False,
            "messages": [
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
                    "content": f"Fingerprint: {json.dumps(fp)}",
                },
            ],
        }

        r = requests.post(f"{OLLAMA_URL}/api/chat", json=payload, timeout=120)
        r.raise_for_status()
        data = r.json()

        content = data.get("message", {}).get("content", "")
        parsed = None
        raw_error = None

        try:
            parsed = json.loads(content)
        except json.JSONDecodeError:
            raw_error = content
            parsed = {
                "role": "unknown",
                "confidence": 0.10,
                "raw_model_output": content
            }

        role = normalize_role(parsed.get("role", "unknown"))
        confidence = parsed.get("confidence", 0.10)

        # normalize confidence to float if possible
        try:
            confidence = float(confidence)
        except (TypeError, ValueError):
            confidence = 0.10

        # normalize role to string
        if not isinstance(role, str) or not role.strip():
            role = "unknown"

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

        # rebuild fingerprint so the latest fingerprint includes normalized role/confidence
        updated_fp = build_fingerprint(conn, asset_id)
        fingerprint_store_result = store_fingerprint_if_changed(conn, asset_id, updated_fp)

    return {
        "asset_id": asset_id,
        "classification": {
            "role": role,
            "confidence": confidence
        },
        "fingerprint": updated_fp,
        "fingerprint_store": fingerprint_store_result,
        "raw_model_output": raw_error
    }

@app.get("/fingerprint/{asset_id}")
def get_fingerprint(asset_id: str):
    with db() as conn:
        latest = get_latest_fingerprint(conn, asset_id)

        if latest is None:
            raise HTTPException(status_code=404, detail="No fingerprint found for asset")

        return {
            "asset_id": asset_id,
            "fingerprint_hash": latest["fingerprint_hash"],
            "created_at": latest["created_at"],
            "fingerprint": latest["fingerprint"],
        }
    
@app.get("/detect_changes/{asset_id}")
def detect_changes_for_asset(asset_id: str):
    with db() as conn:
        latest = get_latest_fingerprint(conn, asset_id)

        if latest is None:
            raise HTTPException(status_code=404, detail="No fingerprint found for asset")

        result = detect_and_persist_changes_for_asset(conn, asset_id)
        return result

@app.get("/detect_changes")
def detect_changes_all():
    all_results = []

    with db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT DISTINCT asset_id
                FROM fingerprints
                ORDER BY asset_id
                """
            )
            asset_ids = [str(r[0]) for r in cur.fetchall()]

        for asset_id in asset_ids:
            result = detect_and_persist_changes_for_asset(conn, asset_id)
            if result["changes"]:
                all_results.append(result)

    return {
        "assets_with_changes": len(all_results),
        "results": all_results,
    }

@app.get("/report/daily")
def report_daily():
    with db() as conn:
        with conn.cursor() as cur:
            # recent changes
            cur.execute(
                """
                SELECT
                    c.change_id,
                    c.asset_id,
                    a.preferred_name,
                    a.role,
                    c.change_type,
                    c.severity,
                    c.confidence,
                    c.old_value,
                    c.new_value,
                    c.detected_at
                FROM changes c
                JOIN assets a ON a.asset_id = c.asset_id
                WHERE c.detected_at >= now() - interval '1 day'
                ORDER BY
                    CASE c.severity
                        WHEN 'critical' THEN 5
                        WHEN 'high' THEN 4
                        WHEN 'medium' THEN 3
                        WHEN 'low' THEN 2
                        ELSE 1
                    END DESC,
                    c.detected_at DESC
                """
            )
            recent_changes_rows = cur.fetchall()

            # recently seen assets
            cur.execute(
                """
                SELECT
                    asset_id,
                    preferred_name,
                    role,
                    role_confidence,
                    first_seen,
                    last_seen
                FROM assets
                WHERE last_seen >= now() - interval '1 day'
                ORDER BY last_seen DESC
                """
            )
            recent_assets_rows = cur.fetchall()

            # unknown / weakly classified assets
            cur.execute(
                """
                SELECT
                    asset_id,
                    preferred_name,
                    role,
                    role_confidence,
                    last_seen
                FROM assets
                WHERE role IS NULL
                   OR role = 'unknown'
                   OR role_confidence IS NULL
                   OR role_confidence < 0.60
                ORDER BY last_seen DESC
                LIMIT 20
                """
            )
            notable_assets_rows = cur.fetchall()

    recent_changes = [
        {
            "change_id": str(r[0]),
            "asset_id": str(r[1]),
            "preferred_name": r[2],
            "role": r[3],
            "change_type": r[4],
            "severity": r[5],
            "confidence": float(r[6]) if r[6] is not None else None,
            "old_value": r[7],
            "new_value": r[8],
            "detected_at": r[9].isoformat(),
        }
        for r in recent_changes_rows
    ]

    recent_assets = [
        {
            "asset_id": str(r[0]),
            "preferred_name": r[1],
            "role": r[2],
            "role_confidence": float(r[3]) if r[3] is not None else None,
            "first_seen": r[4].isoformat(),
            "last_seen": r[5].isoformat(),
        }
        for r in recent_assets_rows
    ]

    notable_assets = [
        {
            "asset_id": str(r[0]),
            "preferred_name": r[1],
            "role": r[2],
            "role_confidence": float(r[3]) if r[3] is not None else None,
            "last_seen": r[4].isoformat(),
        }
        for r in notable_assets_rows
    ]

    summary = {
        "report_generated_at": utcnow_iso(),
        "recent_change_count": len(recent_changes),
        "recent_asset_count": len(recent_assets),
        "notable_asset_count": len(notable_assets),
        "recent_changes": recent_changes,
        "recent_assets": recent_assets,
        "notable_assets": notable_assets,
    }

    return summary

@app.get("/report/summary")
def report_summary():
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM assets")
            assets = cur.fetchone()[0]
            cur.execute("SELECT count(*) FROM network_observations")
            observations = cur.fetchone()[0]
            cur.execute("SELECT count(*) FROM fingerprints")
            fingerprints = cur.fetchone()[0]

    return {
        "assets": assets,
        "network_observations": observations,
        "fingerprints": fingerprints,
    }

@app.post("/classify_all")
def classify_all():
    ok = 0
    errors = 0
    failed = []

    with db() as conn:
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
            classify_asset(asset_id)
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