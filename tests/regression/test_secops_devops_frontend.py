from pathlib import Path

import psycopg
import pytest
from fastapi.testclient import TestClient


FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "nmap_single_host.xml"
FRONTEND_INDEX_PATH = Path(__file__).resolve().parents[2] / "frontend" / "index.html"
FRONTEND_APP_PATH = Path(__file__).resolve().parents[2] / "frontend" / "app.js"


@pytest.fixture
def secops_client(integration_brain_module):
    client = TestClient(integration_brain_module.app)
    response = client.post("/auth/login", json={"username": "admin", "password": "change-me-now"})
    assert response.status_code == 200
    return client


@pytest.fixture
def asset_with_finding(secops_client, integration_db_url):
    ingest_response = secops_client.post("/ingest/nmap_xml", json={"xml_path": str(FIXTURE_PATH)})
    assert ingest_response.status_code == 200
    asset_id = secops_client.get("/assets").json()["assets"][0]["asset_id"]

    with psycopg.connect(integration_db_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO findings (
                    asset_id,
                    title,
                    description,
                    severity,
                    confidence,
                    evidence,
                    recommended_action
                )
                VALUES (
                    %s,
                    'Raw IP dashboard link bypasses HTTPS route',
                    'The launcher still points operators at a raw IP and port instead of the managed proxy route.',
                    'high',
                    0.910,
                    '{"source":"heimdall","url":"http://10.0.0.17:8080"}'::jsonb,
                    'Replace the Heimdall URL with the preferred HTTPS hostname and verify the proxy route.'
                )
                RETURNING finding_id
                """,
                (asset_id,),
            )
            finding_id = str(cur.fetchone()[0])
        conn.commit()

    return {"asset_id": asset_id, "finding_id": finding_id}


def test_findings_contract_combines_security_and_remediation(secops_client, asset_with_finding):
    payload = secops_client.get("/findings").json()

    assert set(payload.keys()) == {"findings"}
    assert payload["findings"]
    finding = payload["findings"][0]
    assert {
        "finding_id",
        "asset_id",
        "preferred_name",
        "title",
        "description",
        "severity",
        "confidence",
        "evidence",
        "recommended_action",
        "created_at",
        "instruction_count",
        "latest_instruction",
    }.issubset(finding.keys())
    assert finding["title"] == "Raw IP dashboard link bypasses HTTPS route"
    assert finding["recommended_action"].startswith("Replace the Heimdall URL")
    assert finding["instruction_count"] == 0
    assert finding["latest_instruction"] is None


def test_operator_can_attach_fix_instructions_to_a_finding(secops_client, asset_with_finding):
    response = secops_client.post(
        f"/findings/{asset_with_finding['finding_id']}/instructions",
        json={
            "instruction_text": "Faye, fix the Heimdall link first and then verify the HTTPS route from the dashboard host.",
            "intent": "fix",
            "priority": "high",
        },
    )

    assert response.status_code == 200
    instruction = response.json()["instruction"]
    assert instruction["finding_id"] == asset_with_finding["finding_id"]
    assert instruction["instruction_text"].startswith("Faye, fix the Heimdall link")
    assert instruction["intent"] == "fix"
    assert instruction["priority"] == "high"
    assert instruction["status"] == "queued"

    findings = secops_client.get("/findings").json()["findings"]
    updated = next(item for item in findings if item["finding_id"] == asset_with_finding["finding_id"])
    assert updated["instruction_count"] == 1
    assert updated["latest_instruction"]["instruction_text"] == instruction["instruction_text"]


def test_secops_frontend_exposes_findings_remediation_and_instruction_workflow():
    html = FRONTEND_INDEX_PATH.read_text(encoding="utf-8")
    script = FRONTEND_APP_PATH.read_text(encoding="utf-8")

    assert "SecOps remediation board" in html
    assert 'id="findings-board"' in html
    assert 'id="finding-count"' in html
    assert 'id="remediation-count"' in html
    assert 'id="instruction-modal"' in html
    assert 'id="instruction-form"' in html
    assert 'findings: "/api/findings"' in script
    assert 'function renderFindingsBoard()' in script
    assert 'function openInstructionModal(findingId)' in script
    assert 'function submitFindingInstruction(event)' in script
    assert 'fetch(`${endpoints.findings}/${encodeURIComponent(findingId)}/instructions`' in script
