from pathlib import Path

import pytest
from fastapi.testclient import TestClient


FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "nmap_single_host.xml"


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
    assert len(payload["assets"]) == 1

    asset = payload["assets"][0]
    assert {
        "asset_id",
        "preferred_name",
        "role",
        "role_confidence",
        "first_seen",
        "last_seen",
    }.issubset(asset.keys())
