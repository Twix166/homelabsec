from pathlib import Path

import pytest
import requests
from fastapi.testclient import TestClient


FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "nmap_single_host.xml"
INVALID_FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "nmap_invalid.xml"


@pytest.fixture
def client(integration_brain_module):
    return TestClient(integration_brain_module.app)


def login_as_default_admin(client):
    response = client.post("/auth/login", json={"username": "admin", "password": "change-me-now"})
    assert response.status_code == 200
    return response.json()["user"]


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

    monkeypatch.setattr("brainlib.ollama.requests.post", fake_post)


def test_ingest_missing_file_returns_404(client):
    response = client.post("/ingest/nmap_xml", json={"xml_path": "/tmp/does-not-exist.xml"})

    assert response.status_code == 404
    assert response.json()["detail"] == "XML file not found"


def test_ingest_invalid_xml_returns_400(client):
    response = client.post("/ingest/nmap_xml", json={"xml_path": str(INVALID_FIXTURE_PATH)})

    assert response.status_code == 400
    assert "Invalid Nmap XML" in response.json()["detail"]


def test_health_endpoint(client):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_auth_login_profile_and_admin_console(client, mock_ollama, integration_db_url):
    import psycopg

    assert client.get("/auth/me").status_code == 401

    user = login_as_default_admin(client)
    assert user["username"] == "admin"
    assert user["role"] == "admin"

    me_response = client.get("/auth/me")
    assert me_response.status_code == 200
    assert me_response.json()["user"]["username"] == "admin"

    profile_response = client.patch("/auth/me", json={"display_name": "HomelabSec Admin"})
    assert profile_response.status_code == 200
    assert profile_response.json()["user"]["display_name"] == "HomelabSec Admin"

    modules_response = client.get("/admin/modules")
    assert modules_response.status_code == 200
    module_keys = {module["module_key"] for module in modules_response.json()["modules"]}
    assert {"mac_vendor_lookup", "llm_classification", "fingerbank_classification"} <= module_keys

    sources_response = client.get("/admin/data_sources")
    assert sources_response.status_code == 200
    source_keys = {source["source_key"] for source in sources_response.json()["sources"]}
    assert {"nmap_xml_ingest", "scheduler_discovery", "collector_dhcp", "collector_mdns", "collector_ssdp"} <= source_keys

    create_user_response = client.post(
        "/admin/users",
        json={
            "username": "operator1",
            "password": "operator-pass-123",
            "display_name": "Operator One",
            "email": "operator@example.com",
            "role": "operator",
        },
    )
    assert create_user_response.status_code == 200
    assert create_user_response.json()["user"]["username"] == "operator1"

    users_response = client.get("/admin/users")
    assert users_response.status_code == 200
    assert {user["username"] for user in users_response.json()["users"]} >= {"admin", "operator1"}

    ingest_response = client.post("/ingest/nmap_xml", json={"xml_path": str(FIXTURE_PATH)})
    assert ingest_response.status_code == 200
    asset_id = client.get("/assets").json()["assets"][0]["asset_id"]

    with psycopg.connect(integration_db_url) as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM classification_lookup")
            conn.commit()

    disable_llm_response = client.patch("/admin/modules/llm_classification", json={"enabled": False})
    assert disable_llm_response.status_code == 200
    assert disable_llm_response.json()["enabled"] is False

    classify_response = client.post(f"/classify/{asset_id}")
    assert classify_response.status_code == 200
    assert classify_response.json()["classification_source"] == "disabled"

    disable_ingest_response = client.patch("/admin/data_sources/nmap_xml_ingest", json={"enabled": False})
    assert disable_ingest_response.status_code == 200
    assert disable_ingest_response.json()["enabled"] is False

    blocked_ingest_response = client.post("/ingest/nmap_xml", json={"xml_path": str(FIXTURE_PATH)})
    assert blocked_ingest_response.status_code == 409

    assert client.patch("/admin/modules/llm_classification", json={"enabled": True}).status_code == 200
    assert client.patch("/admin/data_sources/nmap_xml_ingest", json={"enabled": True}).status_code == 200


def test_version_endpoint(client):
    response = client.get("/version")

    assert response.status_code == 200
    assert response.json() == {"version": "0.2.0"}


def test_schema_migrations_table_is_initialized(integration_brain_module, integration_db_url):
    import psycopg

    with psycopg.connect(integration_db_url) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT version FROM schema_migrations ORDER BY version")
            versions = [row[0] for row in cur.fetchall()]

    assert "0000_schema_migrations" in versions
    assert "0001_initial" in versions
    assert "0002_classification_lookup" in versions
    assert "0006_fingerbank" in versions


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
    assert assets[0]["mac_address"] == "aa:bb:cc:dd:ee:ff"
    assert assets[0]["mac_vendor"] == "Acme Devices"

    asset_id = assets[0]["asset_id"]
    fingerprint_response = client.get(f"/fingerprint/{asset_id}")
    assert fingerprint_response.status_code == 200
    fingerprint_payload = fingerprint_response.json()
    assert fingerprint_payload["asset_id"] == asset_id
    assert fingerprint_payload["fingerprint"]["network"]["ip_addresses"] == ["10.0.0.10"]

    observations_response = client.get("/observations")
    assert observations_response.status_code == 200
    observations = observations_response.json()["observations"]
    matching_observations = [item for item in observations if item["asset_id"] == asset_id]
    assert matching_observations
    assert matching_observations[0]["ip_address"] == "10.0.0.10"

    fingerprints_response = client.get("/fingerprints")
    assert fingerprints_response.status_code == 200
    fingerprints = fingerprints_response.json()["fingerprints"]
    assert len(fingerprints) >= 1
    assert any(item["asset_id"] == asset_id for item in fingerprints)

    detect_response = client.get("/detect_changes")
    assert detect_response.status_code == 200
    detect_payload = detect_response.json()
    assert detect_payload["assets_with_changes"] == 1
    assert detect_payload["results"][0]["changes"]

    summary_response = client.get("/report/summary")
    assert summary_response.status_code == 200
    summary_payload = summary_response.json()
    assert summary_payload["assets"] >= 1
    assert summary_payload["network_observations"] >= 1
    assert summary_payload["fingerprints"] >= 1

    daily_response = client.get("/report/daily")
    assert daily_response.status_code == 200
    daily_payload = daily_response.json()
    assert daily_payload["recent_change_count"] >= 1
    assert daily_payload["recent_asset_count"] >= 1
    assert daily_payload["recent_changes"]


def test_classify_endpoints_with_mocked_ollama(client, mock_ollama):
    ingest_response = client.post("/ingest/nmap_xml", json={"xml_path": str(FIXTURE_PATH)})
    assert ingest_response.status_code == 200

    asset_id = client.get("/assets").json()["assets"][0]["asset_id"]

    classify_response = client.post(f"/classify/{asset_id}")
    assert classify_response.status_code == 200
    classify_payload = classify_response.json()
    assert classify_payload["classification"]["role"] == "web_server"
    assert classify_payload["classification"]["confidence"] == 0.88
    assert classify_payload["classification_source"] == "llm"
    assert classify_payload["fingerprint"]["role"] == "web_server"

    classify_all_response = client.post("/classify_all")
    assert classify_all_response.status_code == 200
    classify_all_payload = classify_all_response.json()
    assert classify_all_payload["total_assets"] == 1
    assert classify_all_payload["classified_ok"] == 1
    assert classify_all_payload["lookup_hits"] == 1
    assert classify_all_payload["llm_classified"] == 0
    assert classify_all_payload["errors"] == 0

    detect_single_response = client.get(f"/detect_changes/{asset_id}")
    assert detect_single_response.status_code == 200
    change_types = {change["change_type"] for change in detect_single_response.json()["changes"]}
    assert "role_changed" in change_types


def test_classify_uses_fingerbank_before_llm(client, integration_db_url, monkeypatch):
    import json
    import psycopg

    ingest_response = client.post("/ingest/nmap_xml", json={"xml_path": str(FIXTURE_PATH)})
    assert ingest_response.status_code == 200
    asset_id = client.get("/assets").json()["assets"][0]["asset_id"]

    with psycopg.connect(integration_db_url) as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM classification_lookup")
            cur.execute(
                """
                INSERT INTO fingerbank_role_mappings (
                    manufacturer_pattern,
                    mapped_role,
                    default_confidence,
                    priority,
                    notes
                )
                VALUES (%s, %s, %s, %s, %s)
                """,
                ("HP", "printer", 0.89, 100, "Test mapping"),
            )
            cur.execute(
                """
                INSERT INTO scan_runs (scan_type, status, started_at, completed_at)
                VALUES ('collector_dhcp', 'completed', now(), now())
                RETURNING scan_run_id
                """
            )
            scan_run_id = cur.fetchone()[0]
            cur.execute(
                """
                INSERT INTO network_observations (
                    scan_run_id,
                    asset_id,
                    ip_address,
                    mac_address,
                    reachable,
                    raw_json
                )
                VALUES (%s, %s, %s, %s, true, %s::jsonb)
                """,
                (
                    scan_run_id,
                    asset_id,
                    "10.0.0.10",
                    "aa:bb:cc:dd:ee:ff",
                    json.dumps(
                        {
                            "type": "dhcp",
                            "src_mac": "aa:bb:cc:dd:ee:ff",
                            "src_ip": "10.0.0.10",
                            "hostname": "printer01",
                            "dhcp_fingerprint": "1,3,6,15",
                            "dhcp_vendor": "HP",
                        }
                    ),
                ),
            )
            conn.commit()

    def fake_interrogate(conn, asset_id_arg, evidence_hash, evidence):
        assert asset_id_arg == asset_id
        assert evidence["dhcp_vendor"] == "HP"
        return {
            "fingerbank_device_id": 501,
            "device_name": "OfficeJet Pro",
            "device_version": "1",
            "device_hierarchy": "Printing > Inkjet",
            "manufacturer_name": "HP",
            "score": 92.0,
            "can_be_more_precise": False,
            "mapped_role": "printer",
            "mapped_confidence": 0.89,
            "response_json": {"device": {"id": 501, "name": "OfficeJet Pro"}},
        }

    monkeypatch.setattr("brainlib.classification.interrogate_fingerbank", fake_interrogate)

    def fail_llm(*args, **kwargs):
        raise AssertionError("LLM fallback should not run when Fingerbank auto-accepts")

    monkeypatch.setattr("brainlib.classification.chat_json", fail_llm)

    classify_response = client.post(f"/classify/{asset_id}")
    assert classify_response.status_code == 200
    payload = classify_response.json()
    assert payload["classification_source"] == "fingerbank"
    assert payload["classification"]["role"] == "printer"
    assert payload["classification"]["confidence"] == 0.89
    assert payload["fingerbank_match"]["score"] == 92.0


def test_classify_missing_asset_returns_404(client, mock_ollama):
    response = client.post("/classify/00000000-0000-0000-0000-000000000000")

    assert response.status_code == 404
    assert response.json()["detail"] == "Asset not found"


def test_detect_changes_missing_asset_returns_404(client):
    response = client.get("/detect_changes/00000000-0000-0000-0000-000000000000")

    assert response.status_code == 404
    assert response.json()["detail"] == "Asset not found"


def test_classify_returns_502_when_ollama_is_unreachable(client, integration_db_url, monkeypatch):
    import psycopg

    with psycopg.connect(integration_db_url) as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM classification_lookup")
            conn.commit()

    ingest_response = client.post("/ingest/nmap_xml", json={"xml_path": str(FIXTURE_PATH)})
    assert ingest_response.status_code == 200

    asset_id = client.get("/assets").json()["assets"][0]["asset_id"]

    def fake_post(url, json, timeout):
        raise requests.ConnectionError("connection refused")

    monkeypatch.setattr("brainlib.ollama.requests.post", fake_post)

    response = client.post(f"/classify/{asset_id}")

    assert response.status_code == 502
    assert "Ollama request failed" in response.json()["detail"]


def test_classification_lookup_reuses_learned_result_without_ollama(
    client,
    monkeypatch,
    integration_db_url,
):
    import psycopg

    with psycopg.connect(integration_db_url) as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM classification_lookup")
            conn.commit()

    ingest_response = client.post("/ingest/nmap_xml", json={"xml_path": str(FIXTURE_PATH)})
    assert ingest_response.status_code == 200
    asset_id = client.get("/assets").json()["assets"][0]["asset_id"]

    calls = {"count": 0}

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

    def first_post(url, json, timeout):
        calls["count"] += 1
        return FakeResponse()

    monkeypatch.setattr("brainlib.ollama.requests.post", first_post)

    first_response = client.post(f"/classify/{asset_id}")
    assert first_response.status_code == 200
    assert first_response.json()["classification_source"] == "llm"
    assert calls["count"] == 1

    with psycopg.connect(integration_db_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE assets
                SET role = NULL, role_confidence = NULL
                WHERE asset_id = %s
                """,
                (asset_id,),
            )
            conn.commit()

    def failing_post(url, json, timeout):
        raise AssertionError("lookup path should not call Ollama")

    monkeypatch.setattr("brainlib.ollama.requests.post", failing_post)

    second_response = client.post(f"/classify/{asset_id}")
    assert second_response.status_code == 200
    second_payload = second_response.json()
    assert second_payload["classification"]["role"] == "web_server"
    assert second_payload["classification"]["confidence"] == 0.88
    assert second_payload["classification_source"] == "lookup"
    assert second_payload["lookup"]["sample_count"] >= 1


def test_classification_lookup_endpoint_lists_learned_entries(client, mock_ollama):
    ingest_response = client.post("/ingest/nmap_xml", json={"xml_path": str(FIXTURE_PATH)})
    assert ingest_response.status_code == 200
    asset_id = client.get("/assets").json()["assets"][0]["asset_id"]

    classify_response = client.post(f"/classify/{asset_id}")
    assert classify_response.status_code == 200

    response = client.get("/classification_lookup")

    assert response.status_code == 200
    payload = response.json()
    assert len(payload["entries"]) == 1
    entry = payload["entries"][0]
    assert entry["role"] == "web_server"
    assert entry["confidence"] == 0.88
    assert entry["source"] == "llm_learned"
    assert entry["sample_count"] >= 1
    assert "network" in entry["signature"]


def test_asset_detail_includes_services_and_lookup(client, mock_ollama):
    login_as_default_admin(client)
    ingest_response = client.post("/ingest/nmap_xml", json={"xml_path": str(FIXTURE_PATH)})
    assert ingest_response.status_code == 200
    asset_id = client.get("/assets").json()["assets"][0]["asset_id"]
    detect_response = client.get("/detect_changes")
    assert detect_response.status_code == 200

    classify_response = client.post(f"/classify/{asset_id}")
    assert classify_response.status_code == 200

    response = client.get(f"/assets/{asset_id}")

    assert response.status_code == 200
    payload = response.json()
    assert payload["asset"]["asset_id"] == asset_id
    assert "mac_vendor" in payload["asset"]
    assert payload["exposed_services"]
    assert payload["exposed_services"][0]["port"] == 22
    assert payload["learned_lookup"]["role"] == "web_server"
    assert "recent_change" in payload
    assert payload["recent_change"]["change_type"] in {"new_asset", "role_changed"}
    assert "notable_assessment" in payload
    assert payload["notable_assessment"]["is_notable"] is False
    assert payload["latest_rescan_request"] is None
    assert payload["lynis_target"] is None
    assert payload["latest_lynis_run"] is None


def test_lynis_target_and_queue_endpoints_round_trip(client):
    admin = login_as_default_admin(client)
    ingest_response = client.post("/ingest/nmap_xml", json={"xml_path": str(FIXTURE_PATH)})
    assert ingest_response.status_code == 200
    asset_id = client.get("/assets").json()["assets"][0]["asset_id"]

    configure_response = client.put(
        f"/assets/{asset_id}/lynis_target",
        json={
            "ssh_host": "10.0.0.10",
            "ssh_port": 22,
            "ssh_username": "root",
            "ssh_password": "secret",
            "use_sudo": True,
            "enabled": True,
            "notes": "lab target",
        },
    )
    assert configure_response.status_code == 200
    assert configure_response.json()["target"]["ssh_host"] == "10.0.0.10"

    status_response = client.get(f"/assets/{asset_id}/lynis")
    assert status_response.status_code == 200
    status_payload = status_response.json()
    assert status_payload["target"]["ssh_username"] == "root"
    assert status_payload["module_enabled"] is True
    assert status_payload["source_enabled"] is True

    queue_response = client.post(f"/assets/{asset_id}/lynis/run")
    assert queue_response.status_code == 200
    assert queue_response.json()["queued"] is True
    run_id = queue_response.json()["run"]["run_id"]

    claim_response = client.post("/lynis_runs/claim")
    assert claim_response.status_code == 200
    claim_payload = claim_response.json()
    assert claim_payload["claimed"] is True
    assert claim_payload["run"]["run_id"] == run_id
    assert claim_payload["run"]["target"]["ssh_password"] == "secret"

    complete_response = client.post(
        f"/lynis_runs/{run_id}/complete",
        json={
            "status": "completed",
            "summary": {"hardening_index": 76, "warning_count": 1, "suggestion_count": 2},
            "report_text": "hardening_index=76",
            "log_text": "audit ok",
        },
    )
    assert complete_response.status_code == 200
    assert complete_response.json()["status"] == "completed"
    assert complete_response.json()["summary"]["hardening_index"] == 76

    detail_response = client.get(f"/assets/{asset_id}")
    assert detail_response.status_code == 200
    assert detail_response.json()["latest_lynis_run"]["summary"]["hardening_index"] == 76


def test_rescan_queue_endpoints_round_trip(client):
    ingest_response = client.post("/ingest/nmap_xml", json={"xml_path": str(FIXTURE_PATH)})
    assert ingest_response.status_code == 200
    asset_id = client.get("/assets").json()["assets"][0]["asset_id"]

    queue_response = client.post(f"/rescan/{asset_id}")
    assert queue_response.status_code == 200
    queue_payload = queue_response.json()
    assert queue_payload["queued"] is True
    request_id = queue_payload["request"]["request_id"]
    assert queue_payload["request"]["status"] == "pending"

    duplicate_response = client.post(f"/rescan/{asset_id}")
    assert duplicate_response.status_code == 200
    assert duplicate_response.json()["queued"] is False

    claim_response = client.post("/rescan_requests/claim")
    assert claim_response.status_code == 200
    claim_payload = claim_response.json()
    assert claim_payload["claimed"] is True
    assert claim_payload["request"]["request_id"] == request_id
    assert claim_payload["request"]["asset_id"] == asset_id

    complete_response = client.post(
        f"/rescan_requests/{request_id}/complete",
        json={"status": "completed", "result": {"target_ip": "10.0.0.10"}},
    )
    assert complete_response.status_code == 200
    assert complete_response.json()["status"] == "completed"

    detail_response = client.get(f"/assets/{asset_id}")
    assert detail_response.status_code == 200
    assert detail_response.json()["latest_rescan_request"]["status"] == "completed"


def test_detect_changes_is_idempotent_for_same_fingerprint_pair(client, integration_db_url):
    import psycopg

    ingest_response = client.post("/ingest/nmap_xml", json={"xml_path": str(FIXTURE_PATH)})
    assert ingest_response.status_code == 200

    first_response = client.get("/detect_changes")
    assert first_response.status_code == 200
    assert first_response.json()["assets_with_changes"] == 1

    with psycopg.connect(integration_db_url) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM changes")
            after_first_count = cur.fetchone()[0]

    second_response = client.get("/detect_changes")
    assert second_response.status_code == 200
    assert second_response.json()["assets_with_changes"] == 1

    with psycopg.connect(integration_db_url) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM changes")
            after_second_count = cur.fetchone()[0]

    assert after_second_count == after_first_count


def test_admin_status_endpoint_reports_scheduler_freshness(client):
    login_as_default_admin(client)
    ingest_response = client.post("/ingest/nmap_xml", json={"xml_path": str(FIXTURE_PATH)})
    assert ingest_response.status_code == 200

    response = client.get("/admin/status")

    assert response.status_code == 200
    payload = response.json()
    assert payload["api_status"] == "ok"
    assert payload["version"] == "0.2.0"
    assert set(payload["summary"].keys()) == {"assets", "network_observations", "fingerprints"}
    assert isinstance(payload["enrichment_modules"], list)
    assert isinstance(payload["raw_data_sources"], list)
    assert any(module["module_key"] == "lynis_audit" for module in payload["enrichment_modules"])
    assert any(source["source_key"] == "lynis_remote_audit" for source in payload["raw_data_sources"])
    assert payload["scheduler_freshness"]["status"] in {"fresh", "stale", "unknown"}
    assert payload["latest_scan_run"]["scan_type"] == "nmap_xml_ingest"
