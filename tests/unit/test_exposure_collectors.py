import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BRAIN_DIR = REPO_ROOT / "brain"
if str(BRAIN_DIR) not in sys.path:
    sys.path.insert(0, str(BRAIN_DIR))
os.environ.setdefault("DATABASE_URL", "postgresql://test:***@localhost:5432/test")
os.environ.setdefault("OLLAMA_URL", "http://ollama.test")

from collectors.exposure_collectors import (
    normalize_dns_answer,
    normalize_hcm_target,
    normalize_heimdall_link,
    normalize_npm_proxy_host,
)


def test_npm_proxy_host_normalization_uses_strict_non_secret_allowlist():
    record = {
        "id": 7,
        "domain_names": ["grafana.home.robertbalm.com"],
        "forward_scheme": "http",
        "forward_host": "10.0.0.17",
        "forward_port": 3000,
        "certificate_id": 12,
        "ssl_forced": True,
        "http2_support": True,
        "block_exploits": True,
        "caching_enabled": False,
        "allow_websocket_upgrade": True,
        "advanced_config": "proxy_set_header Authorization super-secret;",
        "meta": {"dns_challenge": {"token": "secret-token"}},
        "access_list_id": 1,
        "owner_user_id": 2,
        "certificate": {"provider": "letsencrypt", "meta": {"credentials": "secret"}},
        "password": "do-not-copy",
    }

    routes = normalize_npm_proxy_host(record)

    assert routes == [
        {
            "source": "npm",
            "domain": "grafana.home.robertbalm.com",
            "scheme": "http",
            "upstream_host": "10.0.0.17",
            "upstream_port": 3000,
            "tls_status": "configured",
            "certificate_status": "certificate_id:12",
            "force_ssl": True,
            "http2_support": True,
            "block_exploits": True,
            "websocket_support": True,
            "raw_json": {
                "proxy_host_id": 7,
                "certificate_id": 12,
                "caching_enabled": False,
            },
        }
    ]
    assert "secret" not in repr(routes).lower()
    assert "advanced_config" not in repr(routes)
    assert "meta" not in repr(routes)
    assert "password" not in repr(routes)


def test_hcm_target_normalization_keeps_route_and_certificate_health_only():
    target = {
        "name": "Grafana",
        "route_url": "https://grafana.home.robertbalm.com",
        "backend_url": "http://10.0.0.17:3000",
        "tls": {
            "status": "valid",
            "issuer": "Home CA",
            "not_after": "2026-09-01T00:00:00Z",
        },
        "health": {"status": "ok"},
        "token": "secret-token",
        "private_key_path": "/secret/path",
    }

    route = normalize_hcm_target(target)

    assert route == {
        "source": "hcm",
        "domain": "grafana.home.robertbalm.com",
        "scheme": "http",
        "upstream_host": "10.0.0.17",
        "upstream_port": 3000,
        "tls_status": "valid",
        "certificate_status": "valid",
        "force_ssl": None,
        "http2_support": None,
        "block_exploits": None,
        "websocket_support": None,
        "raw_json": {
            "name": "Grafana",
            "route_url": "https://grafana.home.robertbalm.com",
            "backend_url": "http://10.0.0.17:3000",
            "health_status": "ok",
            "tls_issuer": "Home CA",
            "tls_not_after": "2026-09-01T00:00:00Z",
        },
    }
    assert "secret" not in repr(route).lower()
    assert "private_key" not in repr(route)


def test_heimdall_link_normalization_classifies_raw_http_ip_and_named_https():
    raw_link = normalize_heimdall_link(
        {
            "title": "Grafana raw",
            "url": "http://10.0.0.17:3000/d/abc",
            "apikey": "secret",
            "password": "secret",
        }
    )
    named_link = normalize_heimdall_link(
        {"title": "Grafana", "url": "https://grafana.home.robertbalm.com/"}
    )

    assert raw_link == {
        "source": "heimdall",
        "title": "Grafana raw",
        "url": "http://10.0.0.17:3000/d/abc",
        "normalized_host": "10.0.0.17",
        "link_kind": "raw_ip",
        "preferred_route_domain": None,
        "hygiene_status": "weak_raw_http_ip",
        "raw_json": {},
    }
    assert named_link["link_kind"] == "named_https"
    assert named_link["hygiene_status"] == "preferred"
    assert "secret" not in repr(raw_link).lower()


def test_dns_answer_normalization_marks_candidate_unresolved_as_info():
    unresolved = normalize_dns_answer(
        hostname="future.home.robertbalm.com",
        resolver="10.0.0.14",
        record_type="A",
        values=[],
        planned=True,
    )
    aligned = normalize_dns_answer(
        hostname="grafana.home.robertbalm.com",
        resolver="10.0.0.14",
        record_type="A",
        values=["10.0.0.17"],
    )

    assert unresolved == [
        {
            "hostname": "future.home.robertbalm.com",
            "resolver": "10.0.0.14",
            "record_type": "A",
            "record_value": "<unresolved>",
            "status": "planned_unresolved",
            "raw_json": {"planned": True},
        }
    ]
    assert aligned[0]["status"] == "observed"
    assert aligned[0]["record_value"] == "10.0.0.17"
