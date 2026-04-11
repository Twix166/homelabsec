from __future__ import annotations

from collectors.common import (
    all_matching_values,
    collector_sleep,
    command_available,
    first_matching_value,
    insert_passive_observation,
    log_collector_event,
    normalize_hostname,
    normalize_ip,
    normalize_mac,
    parse_tshark_json,
    run_command,
)


def parse_mdns_packet(packet: dict) -> dict | None:
    hostname = normalize_hostname(
        first_matching_value(
            packet,
            "dns.resp.name",
            "dns.qry.name",
            "mdns.resp.name",
        )
    )
    services = [
        item
        for item in all_matching_values(packet, "dns.ptr.domain_name", "mdns.ptr.domain_name", "dns.resp.name")
        if item.startswith("_") and item.endswith(".local")
    ]
    ip_address = normalize_ip(first_matching_value(packet, "ip.src", "ip.dst"))
    mac = normalize_mac(first_matching_value(packet, "eth.src"))

    if not any([hostname, services, ip_address, mac]):
        return None

    return {
        "type": "mdns",
        "services": services,
        "hostname": hostname,
        "src_ip": ip_address,
        "src_mac": mac,
    }


def collect_mdns(interface: str) -> None:
    if not command_available("tshark"):
        log_collector_event(
            "warning",
            "collector_unavailable",
            "Passive mDNS collector disabled because tshark is not installed",
            collector="mdns",
        )
        return

    while True:
        result = run_command(
            ["tshark", "-i", interface, "-f", "udp port 5353", "-a", "duration:5", "-T", "json"],
            timeout=10,
        )
        if result is not None and result.stdout:
            for packet in parse_tshark_json(result.stdout):
                record = parse_mdns_packet(packet)
                if record:
                    insert_passive_observation("collector_mdns", "mdns", record)
        collector_sleep(5)
