import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BRAIN_DIR = REPO_ROOT / "brain"
if str(BRAIN_DIR) not in sys.path:
    sys.path.insert(0, str(BRAIN_DIR))
os.environ.setdefault("DATABASE_URL", "postgresql://test:***@localhost:5432/test")
os.environ.setdefault("OLLAMA_URL", "http://ollama.test")

from brainlib.exposure import correlate_exposure_findings


def test_correlate_exposure_findings_flags_launcher_tls_and_dns_gaps():
    routes = [
        {
            "source": "npm",
            "domain": "service.home.example",
            "scheme": "http",
            "upstream_host": "10.0.0.10",
            "upstream_port": 8080,
            "tls_status": "missing",
            "force_ssl": False,
            "raw_json": {},
        }
    ]
    dns_records = [
        {
            "hostname": "service.home.example",
            "resolver": "synology-lan",
            "record_type": "A",
            "record_value": "<unresolved>",
            "status": "planned_unresolved",
            "raw_json": {"planned": True},
        }
    ]
    launcher_links = [
        {
            "source": "heimdall",
            "title": "Service",
            "url": "http://10.0.0.10:8080",
            "normalized_host": "10.0.0.10",
            "link_kind": "raw_ip",
            "preferred_route_domain": None,
            "hygiene_status": "weak_raw_http_ip",
            "raw_json": {},
        }
    ]

    findings = correlate_exposure_findings(routes, dns_records, launcher_links)

    by_type = {finding["finding_type"]: finding for finding in findings}
    assert set(by_type) == {"launcher_hygiene", "route_tls", "dns_resolution"}
    assert by_type["launcher_hygiene"]["severity"] == "high"
    assert by_type["launcher_hygiene"]["evidence"] == {
        "launcher_title": "Service",
        "launcher_url": "http://10.0.0.10:8080",
        "preferred_route_domain": "service.home.example",
        "route_upstream": "10.0.0.10:8080",
    }
    assert by_type["route_tls"]["severity"] == "medium"
    assert by_type["route_tls"]["evidence"]["domain"] == "service.home.example"
    assert by_type["dns_resolution"]["severity"] == "info"
    assert by_type["dns_resolution"]["evidence"] == {
        "hostname": "service.home.example",
        "resolver": "synology-lan",
        "record_type": "A",
        "status": "planned_unresolved",
    }
