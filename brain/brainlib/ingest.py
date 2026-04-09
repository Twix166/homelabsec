from __future__ import annotations

import json
from typing import Any

import psycopg

from brainlib.assets import get_or_create_asset, parse_nmap_xml
from brainlib.fingerprints import build_fingerprint, store_fingerprint_if_changed


def ingest_nmap_xml(conn: psycopg.Connection, xml_path: str) -> dict[str, Any]:
    parsed_hosts = parse_nmap_xml(xml_path)
    inserted = 0

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
                for port in item["ports"]:
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
                            port["port"],
                            port["protocol"],
                            port["service_name"],
                            port["service_product"],
                            port["service_version"],
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

            fingerprint = build_fingerprint(conn, asset_id)
            store_fingerprint_if_changed(conn, asset_id, fingerprint)

        conn.commit()

    return {
        "scan_run_id": scan_run_id,
        "hosts_parsed": len(parsed_hosts),
        "observations_inserted": inserted,
    }
