from pathlib import Path

import pytest
from fastapi.testclient import TestClient


FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "nmap_single_host.xml"
FRONTEND_INDEX_PATH = Path(__file__).resolve().parents[2] / "frontend" / "index.html"
FRONTEND_APP_PATH = Path(__file__).resolve().parents[2] / "frontend" / "app.js"
FRONTEND_ASSET_PATH = Path(__file__).resolve().parents[2] / "frontend" / "asset.html"
FRONTEND_ASSET_SCRIPT_PATH = Path(__file__).resolve().parents[2] / "frontend" / "asset.js"
FRONTEND_LOGIN_PATH = Path(__file__).resolve().parents[2] / "frontend" / "login.html"
FRONTEND_PROFILE_PATH = Path(__file__).resolve().parents[2] / "frontend" / "profile.html"
FRONTEND_ADMIN_PATH = Path(__file__).resolve().parents[2] / "frontend" / "admin.html"


@pytest.fixture
def regression_client(integration_brain_module):
    client = TestClient(integration_brain_module.app)
    response = client.post("/auth/login", json={"username": "admin", "password": "change-me-now"})
    assert response.status_code == 200
    return client


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
        "mac_address",
        "mac_vendor",
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
        "enrichment_modules",
        "raw_data_sources",
        "latest_scan_run",
        "scheduler_freshness",
    } == set(payload.keys())
    assert payload["api_status"] == "ok"
    assert payload["version"] == "0.2.0"
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
    assert 'id="filter-confidence-red"' in html
    assert 'id="filter-confidence-green"' in html
    assert 'id="filter-confidence-blue"' in html
    assert 'id="asset-count"' in html
    assert 'id="detail-list"' in html
    assert 'id="profile-menu"' in html
    assert 'id="page-nav"' in html
    assert "Most notable" in html
    assert 'data-sort-key="last_seen"' in html
    assert 'data-sort-key="mac_vendor"' in html
    assert "Red" in html
    assert "Green" in html
    assert "Blue" in html
    assert "Recent changes" not in html


def test_dashboard_script_wires_frontend_contracts():
    script = FRONTEND_APP_PATH.read_text(encoding="utf-8")

    assert 'observations: "/api/observations"' in script
    assert 'fingerprints: "/api/fingerprints"' in script
    assert 'window.HomelabSecAuth.requireUser()' in script
    assert 'renderSummaryDetail("assets")' in script
    assert 'renderSummaryDetail("observations")' in script
    assert 'renderSummaryDetail("fingerprints")' in script
    assert 'renderSummaryDetail("changes")' in script
    assert "function confidenceBand(value)" in script
    assert "function confidenceTooltip(value)" in script
    assert "function sortedAssets(assets)" in script
    assert 'dashboardState.assetSortKey = "last_seen"' in script or 'assetSortKey: "last_seen"' in script
    assert 'dashboardState.assetFilter = "red"' in script
    assert 'dashboardState.assetFilter = "green"' in script
    assert 'dashboardState.assetFilter = "blue"' in script
    assert 'href="/asset.html?id=${encodeURIComponent(asset.asset_id)}"' in script
    assert '&focus=notable' in script
    assert '&focus=recent_change' in script
    assert 'escapeHtml(asset.mac_vendor || "Unknown brand")' in script
    assert 'class="pill confidence-pill ${escapeHtml(confidence.className)}"' in script
    assert 'elements.assetCount.textContent = `${shownCount}/${totalCount}`' in script
    assert 'dashboardState.notableAssetIds = new Set' in script
    assert 'dashboardState.assetFilter = "notable"' in script
    assert "Most notable" in script
    assert "Recent change" in script
    assert 'Use the Asset inventory flags to inspect recent changes.' in script


def test_asset_detail_markup_and_script_exist():
    html = FRONTEND_ASSET_PATH.read_text(encoding="utf-8")
    script = FRONTEND_ASSET_SCRIPT_PATH.read_text(encoding="utf-8")

    assert 'id="rescan-button"' in html
    assert 'id="lynis-button"' in html
    assert 'id="lynis-modal"' in html
    assert 'id="lynis-run-state"' in html
    assert 'id="asset-lynis-panel"' in html
    assert 'id="page-nav"' in html
    assert 'id="asset-overview"' in html
    assert 'id="asset-status-flags"' in html
    assert 'id="asset-services"' in html
    assert 'id="asset-lookup"' in html
    assert 'id="profile-menu"' in html
    assert '/auth.js' in html
    assert 'window.HomelabSecAuth.requireUser()' in script
    assert 'fetchJson(`/api/assets/${assetId}`)' in script
    assert 'renderStatusFlags(detail)' in script
    assert 'renderLynisPanel(detail)' in script
    assert 'focusFromUrl()' in script
    assert 'id="notable-panel"' in script
    assert 'id="recent-change-panel"' in script
    assert 'fetchJson(`/api/assets/${assetId}/lynis`)' in script
    assert 'fetchJson(`/api/assets/${assetId}/lynis/run`' in script
    assert 'fetchJson(`/api/assets/${assetId}/lynis_target`' in script
    assert "scheduleLynisPolling" in script
    assert 'latestRun.status === "running"' in script
    assert 'latestRun.status === "pending"' in script
    assert 'fetchJson(`/api/rescan/${assetId}`' in script
    assert 'MAC brand' in html


def test_auth_and_admin_pages_exist():
    login_html = FRONTEND_LOGIN_PATH.read_text(encoding="utf-8")
    profile_html = FRONTEND_PROFILE_PATH.read_text(encoding="utf-8")
    admin_html = FRONTEND_ADMIN_PATH.read_text(encoding="utf-8")
    admin_script = (Path(__file__).resolve().parents[2] / "frontend" / "admin.js").read_text(encoding="utf-8")

    assert 'id="login-form"' in login_html
    assert 'id="profile-form"' in profile_html
    assert 'id="module-list"' in admin_html
    assert 'id="source-list"' in admin_html
    assert 'id="user-list"' in admin_html
    assert 'id="admin-status"' in admin_html
    assert 'id="page-nav"' in admin_html
    assert 'apiJson("/api/admin/status")' in admin_script
