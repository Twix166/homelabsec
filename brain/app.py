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
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen3:8b-q4_K_M")

app = FastAPI(title="HomelabSec Brain")


def db():
    return psycopg.connect(DATABASE_URL)


class NmapXmlIngestRequest(BaseModel):
    xml_path: str


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


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
    canonical = json.dumps(fingerprint, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


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
                fp_hash = fingerprint_hash(fp)
                cur.execute(
                    """
                    INSERT INTO fingerprints (asset_id, fingerprint_hash, fingerprint_json)
                    VALUES (%s, %s, %s)
                    """,
                    (asset_id, fp_hash, json.dumps(fp)),
                )

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
                        "Return strict JSON with keys role and confidence."
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

        content = data["message"]["content"]
        try:
            parsed = json.loads(content)
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=500, detail=f"Model returned non-JSON content: {content}") from exc

        role = parsed.get("role")
        confidence = parsed.get("confidence")

        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE assets
                SET role = %s, role_confidence = %s, last_seen = now()
                WHERE asset_id = %s
                """,
                (role, confidence, asset_id),
            )
            conn.commit()

    return {"asset_id": asset_id, "classification": parsed, "fingerprint": fp}


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
