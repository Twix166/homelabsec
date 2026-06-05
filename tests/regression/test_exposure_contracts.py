import psycopg
import pytest
from fastapi.testclient import TestClient


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


def test_exposure_dashboard_markup_and_script_contracts():
    html = open("frontend/index.html", encoding="utf-8").read()
    script = open("frontend/app.js", encoding="utf-8").read()

    assert 'id="exposure-summary"' in html
    assert 'id="exposure-routes"' in html
    assert 'id="exposure-dns"' in html
    assert 'id="exposure-launcher-links"' in html
    assert 'id="exposure-findings"' in html
    assert "/exposure/summary" in script
    assert "/exposure/routes" in script
    assert "/exposure/dns" in script
    assert "/exposure/launcher-links" in script
    assert "/exposure/findings" in script
