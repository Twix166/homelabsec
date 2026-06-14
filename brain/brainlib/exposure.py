from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

import psycopg
from psycopg.types.json import Jsonb

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def _iso(value) -> str | None:
    return value.isoformat() if value is not None else None


def upsert_exposure_routes(conn: psycopg.Connection, routes: list[dict[str, Any]]) -> int:
    with conn.cursor() as cur:
        for route in routes:
            cur.execute(
                """
                INSERT INTO exposure_routes (
                    source, domain, scheme, upstream_host, upstream_port,
                    tls_status, certificate_status, force_ssl, http2_support,
                    block_exploits, websocket_support, raw_json, observed_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, now())
                ON CONFLICT (source, domain, upstream_host, upstream_port)
                DO UPDATE SET
                    scheme = EXCLUDED.scheme,
                    tls_status = EXCLUDED.tls_status,
                    certificate_status = EXCLUDED.certificate_status,
                    force_ssl = EXCLUDED.force_ssl,
                    http2_support = EXCLUDED.http2_support,
                    block_exploits = EXCLUDED.block_exploits,
                    websocket_support = EXCLUDED.websocket_support,
                    raw_json = EXCLUDED.raw_json,
                    observed_at = now()
                """,
                (
                    route["source"],
                    route["domain"],
                    route.get("scheme"),
                    route.get("upstream_host"),
                    route.get("upstream_port"),
                    route.get("tls_status"),
                    route.get("certificate_status"),
                    route.get("force_ssl"),
                    route.get("http2_support"),
                    route.get("block_exploits"),
                    route.get("websocket_support"),
                    Jsonb(route.get("raw_json") or {}),
                ),
            )
    return len(routes)


def upsert_exposure_dns_records(conn: psycopg.Connection, records: list[dict[str, Any]]) -> int:
    with conn.cursor() as cur:
        for record in records:
            cur.execute(
                """
                INSERT INTO exposure_dns_records (
                    hostname, resolver, record_type, record_value, status, raw_json, observed_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, now())
                ON CONFLICT (hostname, resolver, record_type, record_value)
                DO UPDATE SET
                    status = EXCLUDED.status,
                    raw_json = EXCLUDED.raw_json,
                    observed_at = now()
                """,
                (
                    record["hostname"],
                    record["resolver"],
                    record["record_type"],
                    record["record_value"],
                    record.get("status", "observed"),
                    Jsonb(record.get("raw_json") or {}),
                ),
            )
    return len(records)


def upsert_exposure_launcher_links(conn: psycopg.Connection, links: list[dict[str, Any]]) -> int:
    with conn.cursor() as cur:
        for link in links:
            cur.execute(
                """
                INSERT INTO exposure_launcher_links (
                    source, title, url, normalized_host, link_kind,
                    preferred_route_domain, hygiene_status, raw_json, observed_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, now())
                ON CONFLICT (source, title, url)
                DO UPDATE SET
                    normalized_host = EXCLUDED.normalized_host,
                    link_kind = EXCLUDED.link_kind,
                    preferred_route_domain = EXCLUDED.preferred_route_domain,
                    hygiene_status = EXCLUDED.hygiene_status,
                    raw_json = EXCLUDED.raw_json,
                    observed_at = now()
                """,
                (
                    link["source"],
                    link["title"],
                    link["url"],
                    link.get("normalized_host"),
                    link.get("link_kind", "unknown"),
                    link.get("preferred_route_domain"),
                    link.get("hygiene_status", "observed"),
                    Jsonb(link.get("raw_json") or {}),
                ),
            )
    return len(links)


def _host_port_from_url(value: str | None) -> tuple[str | None, int | None]:
    parsed = urlparse(value or "")
    return parsed.hostname, parsed.port


def correlate_exposure_findings(
    routes: list[dict[str, Any]],
    dns_records: list[dict[str, Any]],
    launcher_links: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    routes_by_upstream: dict[tuple[str, int | None], dict[str, Any]] = {}

    for route in routes:
        host = route.get("upstream_host")
        if host:
            routes_by_upstream[(str(host), route.get("upstream_port"))] = route

        tls_status = str(route.get("tls_status") or "").lower()
        force_ssl = route.get("force_ssl")
        if tls_status in {"", "missing", "invalid", "expired"} or force_ssl is False:
            domain = str(route.get("domain"))
            findings.append(
                {
                    "finding_type": "route_tls",
                    "severity": "medium",
                    "status": "open",
                    "title": f"Route TLS/HTTPS hardening gap: {domain}",
                    "description": "A routed service is missing a valid TLS state or is not configured to force HTTPS.",
                    "evidence": {
                        "domain": domain,
                        "tls_status": route.get("tls_status"),
                        "force_ssl": force_ssl,
                    },
                }
            )

    for link in launcher_links:
        if link.get("link_kind") != "raw_ip":
            continue
        link_host, link_port = _host_port_from_url(link.get("url"))
        route = routes_by_upstream.get((link_host or "", link_port))
        if not route:
            continue
        upstream = f"{route.get('upstream_host')}:{route.get('upstream_port')}"
        findings.append(
            {
                "finding_type": "launcher_hygiene",
                "severity": "high",
                "status": "open",
                "title": f"Launcher uses raw backend link for {route.get('domain')}",
                "description": "A dashboard launcher link points directly at a raw backend while a preferred route exists.",
                "evidence": {
                    "launcher_title": link.get("title"),
                    "launcher_url": link.get("url"),
                    "preferred_route_domain": route.get("domain"),
                    "route_upstream": upstream,
                },
            }
        )

    for record in dns_records:
        status = str(record.get("status") or "")
        if status not in {"unresolved", "planned_unresolved"}:
            continue
        findings.append(
            {
                "finding_type": "dns_resolution",
                "severity": "info" if status == "planned_unresolved" else "medium",
                "status": "open",
                "title": f"DNS record is unresolved: {record.get('hostname')}",
                "description": "A tracked hostname does not currently resolve through the observed resolver.",
                "evidence": {
                    "hostname": record.get("hostname"),
                    "resolver": record.get("resolver"),
                    "record_type": record.get("record_type"),
                    "status": status,
                },
            }
        )

    return findings


def replace_exposure_findings(conn: psycopg.Connection, findings: list[dict[str, Any]]) -> int:
    with conn.cursor() as cur:
        cur.execute("DELETE FROM exposure_findings")
        for finding in findings:
            cur.execute(
                """
                INSERT INTO exposure_findings (
                    finding_type, severity, status, title, description, evidence,
                    created_at, updated_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, now(), now())
                """,
                (
                    finding["finding_type"],
                    finding["severity"],
                    finding.get("status", "open"),
                    finding["title"],
                    finding["description"],
                    Jsonb(finding.get("evidence") or {}),
                ),
            )
    return len(findings)


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
