from pathlib import Path

import pytest


def test_parse_nmap_xml_reads_up_hosts_and_open_ports_only(brain_module):
    fixture_path = Path(__file__).resolve().parents[1] / "fixtures" / "nmap_single_host.xml"

    parsed = brain_module.parse_nmap_xml(str(fixture_path))

    assert len(parsed) == 1
    host = parsed[0]
    assert host["ip"] == "10.0.0.10"
    assert host["mac"] == "AA:BB:CC:DD:EE:FF"
    assert host["vendor"] == "Acme Devices"
    assert host["hostname"] == "fileserver.local"
    assert host["os_guess"] == "Linux 5.X"
    assert host["ports"] == [
        {
            "port": 22,
            "protocol": "tcp",
            "service_name": "ssh",
            "service_product": "OpenSSH",
            "service_version": "9.0",
        }
    ]


@pytest.mark.parametrize(
    ("role", "expected"),
    [
        ("NAS", "nas"),
        ("file server", "nas"),
        ("router", "gateway"),
        ("web-server", "web_server"),
        ("smart device", "iot_device"),
        ("", "unknown"),
        ("something_else", "unknown"),
        (None, "unknown"),
    ],
)
def test_normalize_role_maps_aliases_and_unknowns(brain_module, role, expected):
    assert brain_module.normalize_role(role) == expected


def test_fingerprint_hash_ignores_last_seen(brain_module):
    baseline = {
        "identity": {"preferred_name": "nas-1", "identifiers": []},
        "network": {"ip_addresses": ["10.0.0.10"], "mac_addresses": [], "open_ports": [], "os_guess": None},
        "history": {"first_seen": "2026-01-01T00:00:00+00:00", "last_seen": "2026-01-01T00:05:00+00:00"},
        "role": "nas",
        "role_confidence": 0.9,
    }
    changed_last_seen = {
        **baseline,
        "history": {"first_seen": "2026-01-01T00:00:00+00:00", "last_seen": "2026-01-01T01:05:00+00:00"},
    }

    assert brain_module.fingerprint_hash(baseline) == brain_module.fingerprint_hash(changed_last_seen)


def test_fingerprint_hash_changes_when_stable_fields_change(brain_module):
    baseline = {
        "identity": {"preferred_name": "nas-1", "identifiers": []},
        "network": {"ip_addresses": ["10.0.0.10"], "mac_addresses": [], "open_ports": [], "os_guess": None},
        "history": {"first_seen": "2026-01-01T00:00:00+00:00", "last_seen": "2026-01-01T00:05:00+00:00"},
        "role": "nas",
        "role_confidence": 0.9,
    }
    changed_role = {**baseline, "role": "server"}

    assert brain_module.fingerprint_hash(baseline) != brain_module.fingerprint_hash(changed_role)


def test_diff_fingerprints_marks_new_asset(brain_module):
    new_fp = {
        "identity": {"preferred_name": "printer-1"},
        "network": {"ip_addresses": ["10.0.0.20"], "mac_addresses": ["AA:00:00:00:00:01"], "open_ports": []},
        "role": "printer",
    }

    changes = brain_module.diff_fingerprints(None, new_fp)

    assert len(changes) == 1
    assert changes[0]["change_type"] == "new_asset"
    assert changes[0]["severity"] == "medium"
    assert changes[0]["new_value"]["preferred_name"] == "printer-1"


def test_diff_fingerprints_detects_expected_change_types(brain_module):
    old_fp = {
        "identity": {"preferred_name": "host-1"},
        "network": {
            "ip_addresses": ["10.0.0.10"],
            "mac_addresses": ["AA:BB:CC:DD:EE:FF"],
            "open_ports": [
                {
                    "port": 22,
                    "protocol": "tcp",
                    "service_name": "ssh",
                    "service_product": "OpenSSH",
                    "service_version": "8.0",
                },
                {
                    "port": 8080,
                    "protocol": "tcp",
                    "service_name": "http-proxy",
                    "service_product": "TinyProxy",
                    "service_version": "1.0",
                },
            ],
        },
        "role": "unknown",
    }
    new_fp = {
        "identity": {"preferred_name": "host-1"},
        "network": {
            "ip_addresses": ["10.0.0.11"],
            "mac_addresses": ["AA:BB:CC:DD:EE:00"],
            "open_ports": [
                {
                    "port": 22,
                    "protocol": "tcp",
                    "service_name": "ssh",
                    "service_product": "OpenSSH",
                    "service_version": "8.0",
                },
                {
                    "port": 443,
                    "protocol": "tcp",
                    "service_name": "https",
                    "service_product": "nginx",
                    "service_version": "1.25",
                },
            ],
        },
        "role": "web_server",
    }

    changes = brain_module.diff_fingerprints(old_fp, new_fp)
    change_types = {change["change_type"] for change in changes}

    assert "ip_addresses_changed" in change_types
    assert "mac_addresses_changed" in change_types
    assert "new_port_opened" in change_types
    assert "port_closed" in change_types
    assert "role_changed" in change_types
