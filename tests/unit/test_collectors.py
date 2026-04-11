import sys
from pathlib import Path
import os


REPO_ROOT = Path(__file__).resolve().parents[2]
BRAIN_DIR = REPO_ROOT / "brain"
if str(BRAIN_DIR) not in sys.path:
    sys.path.insert(0, str(BRAIN_DIR))
os.environ.setdefault("DATABASE_URL", "postgresql://test:test@localhost:5432/test")
os.environ.setdefault("OLLAMA_URL", "http://ollama.test")

from collectors.dhcp_collector import parse_dhcp_packet, parse_tcpdump_dhcp
from collectors.mdns_collector import parse_mdns_packet
from collectors.ssdp_collector import parse_ssdp_packet


def test_parse_dhcp_packet_extracts_expected_fields():
    packet = {
        "_source": {
            "layers": {
                "eth": {"eth.src": "AA:BB:CC:DD:EE:FF"},
                "ip": {"ip.src": "10.0.0.20"},
                "bootp": {
                    "bootp.option.hostname": "printer01",
                    "bootp.option.vendor_class_id": "HP LaserJet",
                    "bootp.option.parameter_request_list_item": ["1", "3", "6", "15"],
                },
            }
        }
    }

    parsed = parse_dhcp_packet(packet)

    assert parsed == {
        "type": "dhcp",
        "src_mac": "aa:bb:cc:dd:ee:ff",
        "src_ip": "10.0.0.20",
        "hostname": "printer01",
        "dhcp_fingerprint": "1,3,6,15",
        "dhcp_vendor": "HP LaserJet",
    }


def test_parse_tcpdump_dhcp_extracts_expected_fields():
    stdout = """
Client-Ethernet-Address aa:bb:cc:dd:ee:11
Hostname Option 12, length 9: nasbox01
Vendor-Class Option 60, length 11: SynologyNAS
Parameter-Request Option 55, length 4: 1, 3, 6, 15
10.0.0.55
"""

    parsed = parse_tcpdump_dhcp(stdout)

    assert parsed == [
        {
            "type": "dhcp",
            "src_mac": "aa:bb:cc:dd:ee:11",
            "src_ip": "10.0.0.55",
            "hostname": "nasbox01",
            "dhcp_fingerprint": "1,3,6,15",
            "dhcp_vendor": "SynologyNAS",
        }
    ]


def test_parse_mdns_packet_extracts_services_and_host():
    packet = {
        "_source": {
            "layers": {
                "eth": {"eth.src": "AA:BB:CC:00:11:22"},
                "ip": {"ip.src": "10.0.0.30"},
                "dns": {
                    "dns.resp.name": "printer.local",
                    "dns.ptr.domain_name": ["_ipp._tcp.local", "_printer._tcp.local"],
                },
            }
        }
    }

    parsed = parse_mdns_packet(packet)

    assert parsed == {
        "type": "mdns",
        "services": ["_ipp._tcp.local", "_printer._tcp.local"],
        "hostname": "printer.local",
        "src_ip": "10.0.0.30",
        "src_mac": "aa:bb:cc:00:11:22",
    }


def test_parse_ssdp_packet_extracts_server_and_user_agent():
    packet = {
        "_source": {
            "layers": {
                "eth": {"eth.src": "AA:BB:CC:99:88:77"},
                "ip": {"ip.src": "10.0.0.40"},
                "http": {
                    "http.server": "Linux/5.10 UPnP/1.0 Sonos/65.1",
                    "http.user_agent": "Sonos/65.1 UPnP/1.0",
                    "http.location": "http://10.0.0.40:1400/xml/device_description.xml",
                },
            }
        }
    }

    parsed = parse_ssdp_packet(packet)

    assert parsed == {
        "type": "ssdp",
        "src_ip": "10.0.0.40",
        "src_mac": "aa:bb:cc:99:88:77",
        "upnp_server_string": "Linux/5.10 UPnP/1.0 Sonos/65.1",
        "upnp_user_agent": "Sonos/65.1 UPnP/1.0",
        "location": "http://10.0.0.40:1400/xml/device_description.xml",
    }
