from __future__ import annotations

from collectors.common import (
    collector_sleep,
    command_available,
    first_matching_value,
    insert_passive_observation,
    log_collector_event,
    normalize_ip,
    normalize_mac,
    parse_tshark_json,
    run_command,
)


def parse_ssdp_packet(packet: dict) -> dict | None:
    server = first_matching_value(packet, "http.server", "ssdp.server")
    user_agent = first_matching_value(packet, "http.user_agent", "ssdp.user_agent")
    location = first_matching_value(packet, "http.location", "ssdp.location")
    ip_address = normalize_ip(first_matching_value(packet, "ip.src"))
    mac = normalize_mac(first_matching_value(packet, "eth.src"))

    if not any([server, user_agent, location, ip_address, mac]):
        return None

    return {
        "type": "ssdp",
        "src_ip": ip_address,
        "src_mac": mac,
        "upnp_server_string": server,
        "upnp_user_agent": user_agent,
        "location": location,
    }


def collect_ssdp(interface: str) -> None:
    if not command_available("tshark"):
        log_collector_event(
            "warning",
            "collector_unavailable",
            "Passive SSDP collector disabled because tshark is not installed",
            collector="ssdp",
        )
        return

    while True:
        result = run_command(
            ["tshark", "-i", interface, "-f", "udp port 1900", "-a", "duration:5", "-T", "json"],
            timeout=10,
        )
        if result is not None and result.stdout:
            for packet in parse_tshark_json(result.stdout):
                record = parse_ssdp_packet(packet)
                if record:
                    insert_passive_observation("collector_ssdp", "ssdp", record)
        collector_sleep(5)
