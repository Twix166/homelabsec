from pathlib import Path

import pytest
from fastapi.testclient import TestClient


FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "nmap_single_host.xml"
FRONTEND_INDEX_PATH = Path(__file__).resolve().parents[2] / "frontend" / "index.html"
FRONTEND_APP_PATH = Path(__file__).resolve().parents[2] / "frontend" / "app.js"


@pytest.fixture
def regression_client(integration_brain_module):
    return TestClient(integration_brain_module.app)


@pytest.fixture
def populated_dashboard_data(regression_client):
    ingest_response = regression_client.post("/ingest/nmap_xml", json={"xml_path": str(FIXTURE_PATH)})
    assert ingest_response.status_code == 200

    detect_response = regression_client.get("/detect_changes")
    assert detect_response.status_code == 200

    return regression_client


def test_health_contract_shape(regression_client):
    payload = regression_client.get("/health").json()

    assert set(payload.keys()) == {"status"}
    assert isinstance(payload["status"], str)


def test_report_summary_contract_shape(populated_dashboard_data):
    payload = populated_dashboard_data.get("/report/summary").json()

    assert set(payload.keys()) == {"assets", "network_observations", "fingerprints"}
    assert isinstance(payload["assets"], int)
    assert isinstance(payload["network_observations"], int)
    assert isinstance(payload["fingerprints"], int)


def test_report_daily_contract_shape(populated_dashboard_data):
    payload = populated_dashboard_data.get("/report/daily").json()

    expected_top_level_keys = {
        "report_generated_at",
        "recent_change_count",
        "recent_asset_count",
        "notable_asset_count",
        "recent_changes",
        "recent_assets",
        "notable_assets",
    }

    assert set(payload.keys()) == expected_top_level_keys
    assert isinstance(payload["report_generated_at"], str)
    assert isinstance(payload["recent_change_count"], int)
    assert isinstance(payload["recent_asset_count"], int)
    assert isinstance(payload["notable_asset_count"], int)
    assert isinstance(payload["recent_changes"], list)
    assert isinstance(payload["recent_assets"], list)
    assert isinstance(payload["notable_assets"], list)

    recent_change = payload["recent_changes"][0]
    assert {
        "change_id",
        "asset_id",
        "preferred_name",
        "role",
        "change_type",
        "severity",
        "confidence",
        "old_value",
        "new_value",
        "detected_at",
    }.issubset(recent_change.keys())

    recent_asset = payload["recent_assets"][0]
    assert {
        "asset_id",
        "preferred_name",
        "role",
        "role_confidence",
        "first_seen",
        "last_seen",
    }.issubset(recent_asset.keys())

    if payload["notable_assets"]:
        notable_asset = payload["notable_assets"][0]
        assert {
            "asset_id",
            "preferred_name",
            "role",
            "role_confidence",
            "last_seen",
        }.issubset(notable_asset.keys())


def test_assets_contract_shape(populated_dashboard_data):
    payload = populated_dashboard_data.get("/assets").json()

    assert set(payload.keys()) == {"assets"}
    assert isinstance(payload["assets"], list)
    assert payload["assets"]

    asset = payload["assets"][0]
    assert {
        "asset_id",
        "preferred_name",
        "role",
        "role_confidence",
        "first_seen",
        "last_seen",
    }.issubset(asset.keys())


def test_observations_contract_shape(populated_dashboard_data):
    payload = populated_dashboard_data.get("/observations").json()

    assert set(payload.keys()) == {"observations"}
    assert isinstance(payload["observations"], list)
    assert payload["observations"]

    observation = payload["observations"][0]
    assert {
        "observation_id",
        "asset_id",
        "preferred_name",
        "ip_address",
        "mac_address",
        "port",
        "protocol",
        "service_name",
        "service_product",
        "service_version",
        "os_guess",
        "observed_at",
    }.issubset(observation.keys())


def test_fingerprints_contract_shape(populated_dashboard_data):
    payload = populated_dashboard_data.get("/fingerprints").json()

    assert set(payload.keys()) == {"fingerprints"}
    assert isinstance(payload["fingerprints"], list)
    assert payload["fingerprints"]

    fingerprint = payload["fingerprints"][0]
    assert {
        "fingerprint_id",
        "asset_id",
        "preferred_name",
        "role",
        "fingerprint_hash",
        "created_at",
    }.issubset(fingerprint.keys())


def test_admin_status_contract_shape(populated_dashboard_data):
    payload = populated_dashboard_data.get("/admin/status").json()

    assert {
        "generated_at",
        "api_status",
        "version",
        "summary",
        "latest_scan_run",
        "scheduler_freshness",
    } == set(payload.keys())
    assert payload["api_status"] == "ok"
    assert payload["version"] == "0.1.0"
    assert set(payload["summary"].keys()) == {"assets", "network_observations", "fingerprints"}
    assert {
        "status",
        "stale_after_minutes",
        "age_minutes",
    } == set(payload["scheduler_freshness"].keys())


def test_dashboard_markup_exposes_clickable_summary_cards():
    html = FRONTEND_INDEX_PATH.read_text(encoding="utf-8")

    assert '<button id="summary-assets"' in html
    assert '<button id="summary-observations"' in html
    assert '<button id="summary-fingerprints"' in html
    assert '<button id="summary-changes"' in html
    assert 'id="filter-assets-all"' in html
    assert 'id="filter-assets-notable"' in html
    assert 'id="asset-count"' in html
    assert 'id="detail-list"' in html
    assert 'id="admin-status"' in html
    assert "Most notable" in html


def test_dashboard_script_wires_frontend_contracts():
    script = FRONTEND_APP_PATH.read_text(encoding="utf-8")

    assert 'observations: "/api/observations"' in script
    assert 'fingerprints: "/api/fingerprints"' in script
    assert 'adminStatus: "/api/admin/status"' in script
    assert 'renderSummaryDetail("assets")' in script
    assert 'renderSummaryDetail("observations")' in script
    assert 'renderSummaryDetail("fingerprints")' in script
    assert 'renderSummaryDetail("changes")' in script
    assert "function confidenceBand(value)" in script
    assert "function confidenceTooltip(value)" in script
    assert 'class="pill confidence-pill ${escapeHtml(confidence.className)}"' in script
    assert 'elements.assetCount.textContent = `${shownCount}/${totalCount}`' in script
    assert "renderAdminStatus(dashboardState.adminStatus)" in script
    assert 'dashboardState.notableAssetIds = new Set' in script
    assert 'dashboardState.assetFilter = "notable"' in script
    assert "Most notable" in script
