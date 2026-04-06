from pathlib import Path

import pytest
from fastapi.testclient import TestClient


FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "nmap_single_host.xml"


@pytest.fixture
def client(integration_brain_module):
    return TestClient(integration_brain_module.app)


@pytest.fixture
def mock_ollama(integration_brain_module, monkeypatch):
    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "model": "homelabsec-classifier",
                "message": {
                    "content": '{"role":"web_server","confidence":0.88}',
                },
            }

    def fake_post(url, json, timeout):
        assert url == "http://ollama.test/api/chat"
        assert json["model"] == "homelabsec-classifier"
        return FakeResponse()

    monkeypatch.setattr(integration_brain_module.requests, "post", fake_post)


def test_health_endpoint(client):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_ingest_detect_changes_and_reports_flow(client):
    ingest_response = client.post("/ingest/nmap_xml", json={"xml_path": str(FIXTURE_PATH)})

    assert ingest_response.status_code == 200
    ingest_payload = ingest_response.json()
    assert ingest_payload["hosts_parsed"] == 1
    assert ingest_payload["observations_inserted"] == 1

    assets_response = client.get("/assets")
    assert assets_response.status_code == 200
    assets = assets_response.json()["assets"]
    assert len(assets) == 1

    asset_id = assets[0]["asset_id"]
    fingerprint_response = client.get(f"/fingerprint/{asset_id}")
    assert fingerprint_response.status_code == 200
    fingerprint_payload = fingerprint_response.json()
    assert fingerprint_payload["asset_id"] == asset_id
    assert fingerprint_payload["fingerprint"]["network"]["ip_addresses"] == ["10.0.0.10"]

    detect_response = client.get("/detect_changes")
    assert detect_response.status_code == 200
    detect_payload = detect_response.json()
    assert detect_payload["assets_with_changes"] == 1
    assert detect_payload["results"][0]["changes"][0]["change_type"] == "new_asset"

    summary_response = client.get("/report/summary")
    assert summary_response.status_code == 200
    summary_payload = summary_response.json()
    assert summary_payload["assets"] == 1
    assert summary_payload["network_observations"] == 1
    assert summary_payload["fingerprints"] >= 1

    daily_response = client.get("/report/daily")
    assert daily_response.status_code == 200
    daily_payload = daily_response.json()
    assert daily_payload["recent_change_count"] >= 1
    assert daily_payload["recent_asset_count"] == 1
    assert daily_payload["recent_changes"][0]["change_type"] == "new_asset"


def test_classify_endpoints_with_mocked_ollama(client, mock_ollama):
    ingest_response = client.post("/ingest/nmap_xml", json={"xml_path": str(FIXTURE_PATH)})
    assert ingest_response.status_code == 200

    asset_id = client.get("/assets").json()["assets"][0]["asset_id"]

    classify_response = client.post(f"/classify/{asset_id}")
    assert classify_response.status_code == 200
    classify_payload = classify_response.json()
    assert classify_payload["classification"]["role"] == "web_server"
    assert classify_payload["classification"]["confidence"] == 0.88
    assert classify_payload["fingerprint"]["role"] == "web_server"

    classify_all_response = client.post("/classify_all")
    assert classify_all_response.status_code == 200
    classify_all_payload = classify_all_response.json()
    assert classify_all_payload["total_assets"] == 1
    assert classify_all_payload["classified_ok"] == 1
    assert classify_all_payload["errors"] == 0

    detect_single_response = client.get(f"/detect_changes/{asset_id}")
    assert detect_single_response.status_code == 200
    change_types = {change["change_type"] for change in detect_single_response.json()["changes"]}
    assert "role_changed" in change_types
