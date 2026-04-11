import sys
from pathlib import Path
import os


REPO_ROOT = Path(__file__).resolve().parents[2]
BRAIN_DIR = REPO_ROOT / "brain"
if str(BRAIN_DIR) not in sys.path:
    sys.path.insert(0, str(BRAIN_DIR))
os.environ.setdefault("DATABASE_URL", "postgresql://test:test@localhost:5432/test")
os.environ.setdefault("OLLAMA_URL", "http://ollama.test")

from brainlib.fingerbank_evidence import evidence_hash_for_payload, merge_evidence
from brainlib.fingerbank_mapping import resolve_fingerbank_role_mapping


def test_merge_evidence_builds_stable_payload():
    evidence = merge_evidence(
        {
            "mac": "aa:bb:cc:dd:ee:ff",
            "hostname": "printer01",
            "dhcp_fingerprint": "1,3,6,15",
            "dhcp_vendor": "HP",
        },
        {
            "hostname": "printer01",
            "mdns_services": ["_printer._tcp.local", "_ipp._tcp.local", "_ipp._tcp.local"],
        },
        {
            "upnp_server_strings": ["Linux/5.10 UPnP/1.0"],
            "upnp_user_agents": ["Sonos/65.1"],
        },
    )

    assert evidence == {
        "mac": "aa:bb:cc:dd:ee:ff",
        "hostname": "printer01",
        "dhcp_fingerprint": "1,3,6,15",
        "dhcp_vendor": "HP",
        "mdns_services": ["_ipp._tcp.local", "_printer._tcp.local"],
        "upnp_server_strings": ["Linux/5.10 UPnP/1.0"],
        "upnp_user_agents": ["Sonos/65.1"],
    }

    same_hash = evidence_hash_for_payload(
        {
            "upnp_user_agents": ["Sonos/65.1"],
            "hostname": "printer01",
            "mac": "aa:bb:cc:dd:ee:ff",
            "upnp_server_strings": ["Linux/5.10 UPnP/1.0"],
            "mdns_services": ["_ipp._tcp.local", "_printer._tcp.local"],
            "dhcp_vendor": "HP",
            "dhcp_fingerprint": "1,3,6,15",
        }
    )

    assert evidence_hash_for_payload(evidence) == same_hash


def test_resolve_fingerbank_mapping_prefers_device_id():
    rows = [
        ("00000000-0000-0000-0000-000000000002", None, None, None, "Printing", "printer", 0.80, 50, True, None),
        ("00000000-0000-0000-0000-000000000001", 123, None, None, None, "printer", 0.92, 200, True, "Exact device id"),
    ]

    class FakeCursor:
        def execute(self, query, params=None):
            self.query = query
            self.params = params

        def fetchall(self):
            return rows

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    class FakeConn:
        def cursor(self):
            return FakeCursor()

    mapping = resolve_fingerbank_role_mapping(
        FakeConn(),
        fingerbank_device_id=123,
        device_name="OfficeJet 7000",
        manufacturer_name="HP",
        device_hierarchy="Printing > Inkjet",
    )

    assert mapping is not None
    assert mapping["mapped_role"] == "printer"
    assert mapping["default_confidence"] == 0.92
