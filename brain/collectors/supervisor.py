from __future__ import annotations

import threading

from brainlib.config import (
    COLLECTOR_DHCP_ENABLED,
    COLLECTOR_INTERFACE,
    COLLECTOR_MDNS_ENABLED,
    COLLECTOR_SSDP_ENABLED,
)
from brainlib.database import db
from brainlib.logging_utils import configure_logging, log_event
from brainlib.admin_console import is_raw_data_source_enabled
from collectors.dhcp_collector import collect_dhcp
from collectors.mdns_collector import collect_mdns
from collectors.ssdp_collector import collect_ssdp


logger = configure_logging("homelabsec.collector_supervisor")
_startup_lock = threading.Lock()
_started = False


def _source_enabled(source_key: str, env_enabled: bool) -> bool:
    if not env_enabled:
        return False
    with db() as conn:
        return is_raw_data_source_enabled(conn, source_key)


def _run_worker(name: str, target) -> None:
    while True:
        try:
            target(COLLECTOR_INTERFACE)
        except Exception as exc:
            log_event(
                logger,
                "error",
                "collector_failed",
                "Collector crashed and will be restarted",
                collector=name,
                error=str(exc),
            )


def run_collectors() -> None:
    workers: list[tuple[str, callable]] = []
    if _source_enabled("collector_dhcp", COLLECTOR_DHCP_ENABLED):
        workers.append(("dhcp", collect_dhcp))
    if _source_enabled("collector_mdns", COLLECTOR_MDNS_ENABLED):
        workers.append(("mdns", collect_mdns))
    if _source_enabled("collector_ssdp", COLLECTOR_SSDP_ENABLED):
        workers.append(("ssdp", collect_ssdp))

    if not workers:
        log_event(logger, "info", "collectors_disabled", "No passive collectors enabled")
        return

    for name, target in workers:
        thread = threading.Thread(target=_run_worker, args=(name, target), daemon=True, name=f"collector-{name}")
        thread.start()
        log_event(logger, "info", "collector_started", "Started passive collector", collector=name)


def start_collectors_once() -> None:
    global _started
    with _startup_lock:
        if _started:
            return
        _started = True
    thread = threading.Thread(target=run_collectors, daemon=True, name="collector-supervisor")
    thread.start()
