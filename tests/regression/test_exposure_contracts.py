import os
import sys
from pathlib import Path

import psycopg
import pytest
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[2]
BRAIN_DIR = REPO_ROOT / "brain"
if str(BRAIN_DIR) not in sys.path:
    sys.path.insert(0, str(BRAIN_DIR))
os.environ.setdefault("DATABASE_URL", "postgresql://test:***@localhost:5432/test")
os.environ.setdefault("OLLAMA_URL", "http://ollama.test")

from brainlib.exposure import (
    correlate_exposure_findings,
    replace_exposure_findings,
    upsert_exposure_dns_records,
    upsert_exposure_launcher_links,
    upsert_exposure_routes,
)
from collectors.exposure_collectors import (
    normalize_dns_answer,
    normalize_heimdall_link,
    normalize_npm_proxy_host,
)


FRONTEND_INDEX_PATH = Path(__file__).resolve().parents[2] / "frontend" / "index.html"
FRONTEND_APP_PATH = Path(__file__).resolve().parents[2] / "frontend" / "app.js"
FRONTEND_STYLES_PATH = Path(__file__).resolve().parents[2] / "frontend" / "styles.css"


@pytest.fixture
def regression_client(integration_brain_module):
    client = TestClient(integration_brain_module.app)
    response = client.post("/auth/login", json={"username": "admin", "password": "change-me-now"})
    assert response.status_code == 200
    return client


def _seed_exposure_rows(integration_db_url):
    with psycopg.connect(integration_db_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO exposure_routes (
                    source, domain, scheme, upstream_host, upstream_port,
                    tls_status, force_ssl, block_exploits, websocket_support
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    "fixture",
                    "service.home.example",
                    "https",
                    "10.0.0.10",
                    8443,
                    "valid",
                    True,
                    True,
                    False,
                ),
            )
            cur.execute(
                """
                INSERT INTO exposure_dns_records (
                    hostname, resolver, record_type, record_value, status
                )
                VALUES (%s, %s, %s, %s, %s)
                """,
                ("service.home.example", "fixture-resolver", "A", "10.0.0.10", "aligned"),
            )
            cur.execute(
                """
                INSERT INTO exposure_launcher_links (
                    source, title, url, normalized_host, link_kind,
                    preferred_route_domain, hygiene_status
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    "fixture",
                    "Service",
                    "http://10.0.0.10:8080",
                    "10.0.0.10",
                    "raw_ip",
                    "service.home.example",
                    "raw_link_has_preferred_route",
                ),
            )
            cur.execute(
                """
                INSERT INTO exposure_findings (
                    finding_type, severity, status, title, description, evidence
                )
                VALUES (%s, %s, %s, %s, %s, %s::jsonb)
                """,
                (
                    "launcher_hygiene",
                    "high",
                    "open",
                    "Raw launcher link has preferred route",
                    "A dashboard link still points to a raw service while a preferred HTTPS route exists.",
                    '{"domain": "service.home.example"}',
                ),
            )
        conn.commit()


def test_exposure_endpoints_return_empty_contracts(regression_client):
    summary = regression_client.get("/exposure/summary")
    routes = regression_client.get("/exposure/routes")
    dns = regression_client.get("/exposure/dns")
    launcher_links = regression_client.get("/exposure/launcher-links")
    findings = regression_client.get("/exposure/findings")

    assert summary.status_code == 200
    assert routes.status_code == 200
    assert dns.status_code == 200
    assert launcher_links.status_code == 200
    assert findings.status_code == 200

    assert set(summary.json()) == {
        "generated_at",
        "routes",
        "dns_records",
        "launcher_links",
        "findings",
        "open_findings_by_severity",
    }
    assert routes.json() == {"routes": []}
    assert dns.json() == {"dns_records": []}
    assert launcher_links.json() == {"launcher_links": []}
    assert findings.json() == {"findings": []}


def test_exposure_endpoints_return_seeded_records(regression_client, integration_db_url):
    _seed_exposure_rows(integration_db_url)

    summary = regression_client.get("/exposure/summary").json()
    routes = regression_client.get("/exposure/routes").json()
    dns = regression_client.get("/exposure/dns").json()
    launcher_links = regression_client.get("/exposure/launcher-links").json()
    findings = regression_client.get("/exposure/findings").json()

    assert summary["routes"] == 1
    assert summary["dns_records"] == 1
    assert summary["launcher_links"] == 1
    assert summary["findings"] == 1
    assert summary["open_findings_by_severity"] == {"high": 1}

    route = routes["routes"][0]
    assert {
        "route_id",
        "source",
        "domain",
        "scheme",
        "upstream_host",
        "upstream_port",
        "tls_status",
        "force_ssl",
        "block_exploits",
        "websocket_support",
        "observed_at",
    }.issubset(route)
    assert route["domain"] == "service.home.example"
    assert route["force_ssl"] is True

    record = dns["dns_records"][0]
    assert record["hostname"] == "service.home.example"
    assert record["record_value"] == "10.0.0.10"
    assert record["status"] == "aligned"

    link = launcher_links["launcher_links"][0]
    assert link["link_kind"] == "raw_ip"
    assert link["hygiene_status"] == "raw_link_has_preferred_route"
    assert link["preferred_route_domain"] == "service.home.example"

    finding = findings["findings"][0]
    assert finding["finding_type"] == "launcher_hygiene"
    assert finding["severity"] == "high"
    assert finding["status"] == "open"
    assert finding["evidence"] == {"domain": "service.home.example"}


def test_exposure_collectors_persist_secret_safe_records(regression_client, integration_db_url):
    npm_routes = normalize_npm_proxy_host(
        {
            "id": 42,
            "domain_names": ["service.home.example"],
            "forward_scheme": "http",
            "forward_host": "10.0.0.10",
            "forward_port": 8080,
            "certificate_id": 7,
            "ssl_forced": True,
            "http2_support": True,
            "block_exploits": True,
            "allow_websocket_upgrade": False,
            "access_list": {"secret": "must-not-leak"},
            "advanced_config": "proxy_set_header Authorization bearer-secret;",
            "meta": {"letsencrypt_agree": True, "dns_challenge_token": "secret"},
        }
    )
    dns_records = normalize_dns_answer(
        hostname="service.home.example",
        resolver="synology-lan",
        values=["10.0.0.17"],
    )
    launcher_links = [
        normalize_heimdall_link(
            {
                "title": "Service",
                "url": "http://10.0.0.10:8080",
                "password": "must-not-leak",
            }
        )
    ]

    with psycopg.connect(integration_db_url) as conn:
        upsert_exposure_routes(conn, npm_routes)
        upsert_exposure_dns_records(conn, dns_records)
        upsert_exposure_launcher_links(conn, launcher_links)
        conn.commit()

    route = regression_client.get("/exposure/routes").json()["routes"][0]
    dns = regression_client.get("/exposure/dns").json()["dns_records"][0]
    link = regression_client.get("/exposure/launcher-links").json()["launcher_links"][0]
    combined = str({"route": route, "dns": dns, "link": link})

    assert route["domain"] == "service.home.example"
    assert route["upstream_host"] == "10.0.0.10"
    assert route["raw_json"] == {
        "proxy_host_id": 42,
        "certificate_id": 7,
        "caching_enabled": None,
    }
    assert dns["record_value"] == "10.0.0.17"
    assert link["link_kind"] == "raw_ip"
    assert "must-not-leak" not in combined
    assert "Authorization" not in combined
    assert "dns_challenge_token" not in combined


def test_exposure_correlation_persists_generated_findings(regression_client, integration_db_url):
    routes = normalize_npm_proxy_host(
        {
            "id": 99,
            "domain_names": ["rawsvc.home.example"],
            "forward_scheme": "http",
            "forward_host": "10.0.0.25",
            "forward_port": 9000,
            "certificate_id": None,
            "ssl_forced": False,
        }
    )
    dns_records = normalize_dns_answer(
        hostname="rawsvc.home.example",
        resolver="synology-lan",
        values=[],
        planned=True,
    )
    launcher_links = [
        normalize_heimdall_link({"title": "Raw Service", "url": "http://10.0.0.25:9000"})
    ]
    findings = correlate_exposure_findings(routes, dns_records, launcher_links)

    with psycopg.connect(integration_db_url) as conn:
        upsert_exposure_routes(conn, routes)
        upsert_exposure_dns_records(conn, dns_records)
        upsert_exposure_launcher_links(conn, launcher_links)
        replace_exposure_findings(conn, findings)
        conn.commit()

    api_findings = regression_client.get("/exposure/findings").json()["findings"]
    by_type = {finding["finding_type"]: finding for finding in api_findings}

    assert set(by_type) == {"launcher_hygiene", "route_tls", "dns_resolution"}
    assert by_type["launcher_hygiene"]["severity"] == "high"
    assert by_type["route_tls"]["status"] == "open"
    assert by_type["dns_resolution"]["evidence"]["hostname"] == "rawsvc.home.example"


def test_exposure_dashboard_markup_and_script_contracts():
    html = FRONTEND_INDEX_PATH.read_text(encoding="utf-8")
    script = FRONTEND_APP_PATH.read_text(encoding="utf-8")
    styles = FRONTEND_STYLES_PATH.read_text(encoding="utf-8")

    assert 'id="exposure-summary"' in html
    assert 'id="exposure-routes"' in html
    assert 'id="exposure-dns"' in html
    assert 'id="exposure-launcher-links"' in html
    assert 'id="exposure-findings"' in html
    assert 'id="exposure-status-panel"' in html
    assert 'id="exposure-last-generated"' in html
    assert 'id="exposure-coverage-grid"' in html
    assert 'id="exposure-severity-summary"' in html
    assert "collector-backed view" in html
    assert "/exposure/summary" in script
    assert "/exposure/routes" in script
    assert "/exposure/dns" in script
    assert "/exposure/launcher-links" in script
    assert "/exposure/findings" in script
    assert "function exposureReadiness(summary)" in script
    assert "function renderExposureStatus(summary)" in script
    assert "function renderExposureCoverage(summary)" in script
    assert "function renderExposureSeveritySummary(summary)" in script
    assert "collector coverage incomplete" in script
    assert ".exposure-status-panel" in styles
    assert ".exposure-coverage-grid" in styles
    assert ".severity-summary" in styles
