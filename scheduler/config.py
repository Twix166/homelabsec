from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping
from urllib.parse import urlparse


class ConfigError(RuntimeError):
    pass


def _read_env(name: str, environ: Mapping[str, str] | None) -> str | None:
    if environ is None:
        return os.environ.get(name)
    return environ.get(name)


def env_str(
    name: str,
    default: str,
    *,
    environ: Mapping[str, str] | None = None,
) -> str:
    raw_value = _read_env(name, environ)
    if raw_value is None or not raw_value.strip():
        return default
    return raw_value.strip()


def env_int(
    name: str,
    default: int,
    *,
    environ: Mapping[str, str] | None = None,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    raw_value = _read_env(name, environ)
    if raw_value is None or not raw_value.strip():
        value = default
    else:
        try:
            value = int(raw_value)
        except ValueError as exc:
            raise ConfigError(f"{name} must be an integer") from exc

    if minimum is not None and value < minimum:
        raise ConfigError(f"{name} must be >= {minimum}")
    if maximum is not None and value > maximum:
        raise ConfigError(f"{name} must be <= {maximum}")
    return value


def env_bool(
    name: str,
    default: bool = False,
    *,
    environ: Mapping[str, str] | None = None,
) -> bool:
    raw_value = _read_env(name, environ)
    if raw_value is None or not raw_value.strip():
        return default
    normalized = raw_value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ConfigError(f"{name} must be a boolean value")


def validate_api_base(api_base: str) -> str:
    parsed = urlparse(api_base)
    if parsed.scheme not in {"http", "https"}:
        raise ConfigError("API_BASE must use http:// or https://")
    if not parsed.netloc:
        raise ConfigError("API_BASE must include a host")
    return api_base.rstrip("/")


@dataclass(frozen=True)
class SchedulerConfig:
    api_base: str
    target_subnet: str
    discovery_interval_minutes: int
    report_hour_utc: int
    discovery_dir: str
    top_ports: str
    api_retry_attempts: int
    api_retry_delay_seconds: int
    startup_api_timeout_seconds: int
    startup_discovery: bool
    log_level: str
    scheduler_metrics_port: int


def load_scheduler_config(environ: Mapping[str, str] | None = None) -> SchedulerConfig:
    config = SchedulerConfig(
        api_base=validate_api_base(env_str("API_BASE", "http://brain:8088", environ=environ)),
        target_subnet=env_str("TARGET_SUBNET", "10.0.0.0/24", environ=environ),
        discovery_interval_minutes=env_int(
            "DISCOVERY_INTERVAL_MINUTES",
            30,
            environ=environ,
            minimum=1,
        ),
        report_hour_utc=env_int("REPORT_HOUR_UTC", 8, environ=environ, minimum=0, maximum=23),
        discovery_dir=env_str("DISCOVERY_DIR", "/data/discovery/raw", environ=environ),
        top_ports=env_str("TOP_PORTS", "100", environ=environ),
        api_retry_attempts=env_int("API_RETRY_ATTEMPTS", 5, environ=environ, minimum=1),
        api_retry_delay_seconds=env_int("API_RETRY_DELAY_SECONDS", 5, environ=environ, minimum=1),
        startup_api_timeout_seconds=env_int(
            "STARTUP_API_TIMEOUT_SECONDS",
            120,
            environ=environ,
            minimum=1,
        ),
        startup_discovery=env_bool("STARTUP_DISCOVERY", False, environ=environ),
        log_level=env_str("LOG_LEVEL", "INFO", environ=environ).upper(),
        scheduler_metrics_port=env_int(
            "SCHEDULER_METRICS_PORT",
            9100,
            environ=environ,
            minimum=1,
            maximum=65535,
        ),
    )
    return config


CONFIG = load_scheduler_config()
