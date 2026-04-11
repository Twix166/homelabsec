from __future__ import annotations

import re
from typing import Any

from collectors.common import (
    collector_sleep,
    command_available,
    first_matching_value,
    flatten_json_values,
    insert_passive_observation,
    log_collector_event,
    normalize_hostname,
    normalize_ip,
    normalize_mac,
    parse_tshark_json,
    run_command,
)


TCPDUMP_MAC_RE = re.compile(r"Client-Ethernet-Address\s+([0-9a-fA-F:]{17})")
TCPDUMP_HOST_RE = re.compile(r"Hostname Option 12, length \d+: ([^\n]+)")
TCPDUMP_VENDOR_RE = re.compile(r"Vendor-Class Option 60, length \d+: ([^\n]+)")
TCPDUMP_PARAM_RE = re.compile(r"Parameter-Request Option 55, length \d+: ([0-9, ]+)")


def parse_dhcp_packet(packet: dict[str, Any]) -> dict[str, Any] | None:
    mac = normalize_mac(first_matching_value(packet, "bootp.hw.mac_addr", "eth.src"))
    ip_address = normalize_ip(
        first_matching_value(
            packet,
            "bootp.ip.your",
            "bootp.ip.client",
            "ip.src",
        )
    )
    hostname = normalize_hostname(first_matching_value(packet, "bootp.option.hostname", "bootp.hostname"))
    fingerprint_values = [
        value.strip()
        for key, value in flatten_json_values(packet)
        if key.lower().endswith("bootp.option.parameter_request_list_item") and value.strip()
    ]
    fingerprint = ",".join(fingerprint_values) if fingerprint_values else first_matching_value(
        packet,
        "bootp.option.request_list",
    )
    vendor = first_matching_value(packet, "bootp.option.vendor_class_id", "bootp.vendor_class_id")

    if not any([mac, ip_address, hostname, fingerprint, vendor]):
        return None

    return {
        "type": "dhcp",
        "src_mac": mac,
        "src_ip": ip_address,
        "hostname": hostname,
        "dhcp_fingerprint": fingerprint,
        "dhcp_vendor": vendor,
    }


def parse_tcpdump_dhcp(stdout: str) -> list[dict[str, Any]]:
    if not stdout.strip():
        return []

    mac = normalize_mac(TCPDUMP_MAC_RE.search(stdout).group(1)) if TCPDUMP_MAC_RE.search(stdout) else None
    hostname = normalize_hostname(TCPDUMP_HOST_RE.search(stdout).group(1)) if TCPDUMP_HOST_RE.search(stdout) else None
    vendor = TCPDUMP_VENDOR_RE.search(stdout).group(1).strip() if TCPDUMP_VENDOR_RE.search(stdout) else None
    fingerprint = TCPDUMP_PARAM_RE.search(stdout).group(1).replace(" ", "") if TCPDUMP_PARAM_RE.search(stdout) else None
    ip_address = normalize_ip(stdout)

    if not any([mac, hostname, vendor, fingerprint, ip_address]):
        return []

    return [
        {
            "type": "dhcp",
            "src_mac": mac,
            "src_ip": ip_address,
            "hostname": hostname,
            "dhcp_fingerprint": fingerprint,
            "dhcp_vendor": vendor,
        }
    ]


def collect_dhcp(interface: str) -> None:
    while True:
        if command_available("tshark"):
            result = run_command(
                ["tshark", "-i", interface, "-Y", "bootp", "-a", "duration:5", "-T", "json"],
                timeout=10,
            )
            if result is not None and result.stdout:
                for packet in parse_tshark_json(result.stdout):
                    record = parse_dhcp_packet(packet)
                    if record:
                        insert_passive_observation("collector_dhcp", "dhcp", record)
        elif command_available("tcpdump"):
            result = run_command(
                ["tcpdump", "-i", interface, "-nn", "-v", "-l", "port", "67", "or", "68", "-c", "25"],
                timeout=10,
            )
            if result is not None and result.stdout:
                for record in parse_tcpdump_dhcp(result.stdout):
                    insert_passive_observation("collector_dhcp", "dhcp", record)
        else:
            log_collector_event(
                "warning",
                "collector_unavailable",
                "Passive DHCP collector disabled because no capture tool is installed",
                collector="dhcp",
            )
            return

        collector_sleep(5)
