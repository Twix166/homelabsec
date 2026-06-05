from __future__ import annotations

from typing import Any

import psycopg

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def _iso(value) -> str | None:
    return value.isoformat() if value is not None else None


def exposure_summary(conn: psycopg.Connection) -> dict[str, Any]:
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM exposure_routes")
        route_count = int(cur.fetchone()[0])
        cur.execute("SELECT count(*) FROM exposure_dns_records")
        dns_count = int(cur.fetchone()[0])
        cur.execute("SELECT count(*) FROM exposure_launcher_links")
        launcher_count = int(cur.fetchone()[0])
        cur.execute("SELECT count(*) FROM exposure_findings")
        finding_count = int(cur.fetchone()[0])
        cur.execute(
            """
            SELECT severity, count(*)
            FROM exposure_findings
            WHERE status = 'open'
            GROUP BY severity
            """
        )
        severity_rows = cur.fetchall()
        cur.execute("SELECT now()")
        generated_at = cur.fetchone()[0]

    open_by_severity = {severity: int(count) for severity, count in severity_rows}
    return {
        "generated_at": generated_at.isoformat(),
        "routes": route_count,
        "dns_records": dns_count,
        "launcher_links": launcher_count,
        "findings": finding_count,
        "open_findings_by_severity": {
            severity: open_by_severity[severity]
            for severity in SEVERITY_ORDER
            if severity in open_by_severity
        },
    }


def list_exposure_routes(conn: psycopg.Connection) -> dict[str, list[dict[str, Any]]]:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                route_id,
                source,
                domain,
                scheme,
                upstream_host,
                upstream_port,
                tls_status,
                certificate_status,
                force_ssl,
                http2_support,
                block_exploits,
                websocket_support,
                raw_json,
                observed_at
            FROM exposure_routes
            ORDER BY domain ASC, source ASC, observed_at DESC
            """
        )
        rows = cur.fetchall()

    return {
        "routes": [
            {
                "route_id": str(row[0]),
                "source": row[1],
                "domain": row[2],
                "scheme": row[3],
                "upstream_host": row[4],
                "upstream_port": row[5],
                "tls_status": row[6],
                "certificate_status": row[7],
                "force_ssl": row[8],
                "http2_support": row[9],
                "block_exploits": row[10],
                "websocket_support": row[11],
                "raw_json": row[12],
                "observed_at": _iso(row[13]),
            }
            for row in rows
        ]
    }


def list_exposure_dns_records(conn: psycopg.Connection) -> dict[str, list[dict[str, Any]]]:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                dns_record_id,
                hostname,
                resolver,
                record_type,
                record_value,
                status,
                raw_json,
                observed_at
            FROM exposure_dns_records
            ORDER BY hostname ASC, resolver ASC, record_type ASC, record_value ASC
            """
        )
        rows = cur.fetchall()

    return {
        "dns_records": [
            {
                "dns_record_id": str(row[0]),
                "hostname": row[1],
                "resolver": row[2],
                "record_type": row[3],
                "record_value": row[4],
                "status": row[5],
                "raw_json": row[6],
                "observed_at": _iso(row[7]),
            }
            for row in rows
        ]
    }


def list_exposure_launcher_links(conn: psycopg.Connection) -> dict[str, list[dict[str, Any]]]:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                launcher_link_id,
                source,
                title,
                url,
                normalized_host,
                link_kind,
                preferred_route_domain,
                hygiene_status,
                raw_json,
                observed_at
            FROM exposure_launcher_links
            ORDER BY hygiene_status ASC, title ASC, observed_at DESC
            """
        )
        rows = cur.fetchall()

    return {
        "launcher_links": [
            {
                "launcher_link_id": str(row[0]),
                "source": row[1],
                "title": row[2],
                "url": row[3],
                "normalized_host": row[4],
                "link_kind": row[5],
                "preferred_route_domain": row[6],
                "hygiene_status": row[7],
                "raw_json": row[8],
                "observed_at": _iso(row[9]),
            }
            for row in rows
        ]
    }


def list_exposure_findings(conn: psycopg.Connection) -> dict[str, list[dict[str, Any]]]:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                exposure_finding_id,
                finding_type,
                severity,
                status,
                title,
                description,
                evidence,
                created_at,
                updated_at
            FROM exposure_findings
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 5
                    WHEN 'high' THEN 4
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 2
                    ELSE 1
                END DESC,
                created_at DESC,
                exposure_finding_id DESC
            """
        )
        rows = cur.fetchall()

    return {
        "findings": [
            {
                "exposure_finding_id": str(row[0]),
                "finding_type": row[1],
                "severity": row[2],
                "status": row[3],
                "title": row[4],
                "description": row[5],
                "evidence": row[6],
                "created_at": _iso(row[7]),
                "updated_at": _iso(row[8]),
            }
            for row in rows
        ]
    }
