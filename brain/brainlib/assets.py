from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Optional

import psycopg


class NmapXmlError(ValueError):
    pass


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
    path = Path(xml_path)
    if not path.exists():
        raise FileNotFoundError(xml_path)
    if not path.is_file():
        raise NmapXmlError("XML path must point to a file")

    try:
        tree = ET.parse(path)
    except ET.ParseError as exc:
        raise NmapXmlError(f"Invalid Nmap XML: {exc}") from exc
    except OSError as exc:
        raise NmapXmlError(f"Unable to read XML file: {exc}") from exc

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
