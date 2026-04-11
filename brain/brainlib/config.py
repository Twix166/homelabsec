from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Mapping
from urllib.parse import urlparse


class ConfigError(RuntimeError):
    pass


VALID_LOG_LEVELS = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}


def _read_env(name: str, environ: Mapping[str, str] | None) -> str | None:
    if environ is None:
        return os.environ.get(name)
    return environ.get(name)


def env_str(
    name: str,
    default: str | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    required: bool = False,
    allow_blank: bool = False,
) -> str:
    value = _read_env(name, environ)
    if value is None:
        if required:
            raise ConfigError(f"{name} is required")
        if default is None:
            return ""
        return default

    cleaned = value.strip()
    if not cleaned and not allow_blank:
        if required:
            raise ConfigError(f"{name} must not be blank")
        if default is None:
            return ""
        return default
    return cleaned


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


def env_float(
    name: str,
    default: float,
    *,
    environ: Mapping[str, str] | None = None,
    minimum: float | None = None,
    maximum: float | None = None,
) -> float:
    raw_value = _read_env(name, environ)
    if raw_value is None or not raw_value.strip():
        value = default
    else:
        try:
            value = float(raw_value)
        except ValueError as exc:
            raise ConfigError(f"{name} must be a number") from exc

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


def env_log_level(
    name: str,
    default: str,
    *,
    environ: Mapping[str, str] | None = None,
) -> str:
    value = env_str(name, default, environ=environ).upper()
    if value not in VALID_LOG_LEVELS:
        raise ConfigError(f"{name} must be one of {', '.join(sorted(VALID_LOG_LEVELS))}")
    return value


def env_url(
    name: str,
    default: str | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    required: bool = False,
    allowed_schemes: tuple[str, ...] = ("http", "https"),
) -> str:
    value = env_str(name, default, environ=environ, required=required)
    parsed = urlparse(value)
    if parsed.scheme not in allowed_schemes:
        raise ConfigError(f"{name} must use one of: {', '.join(allowed_schemes)}")
    if not parsed.netloc:
        raise ConfigError(f"{name} must include a host")
    return value.rstrip("/")


def validate_database_url(database_url: str) -> str:
    parsed = urlparse(database_url)
    if parsed.scheme not in {"postgresql", "postgres"}:
        raise ConfigError("DATABASE_URL must use postgresql:// or postgres://")
    if not parsed.hostname:
        raise ConfigError("DATABASE_URL must include a host")
    if not parsed.path or parsed.path == "/":
        raise ConfigError("DATABASE_URL must include a database name")
    return database_url


@dataclass(frozen=True)
class BrainConfig:
    database_url: str
    ollama_url: str
    ollama_model: str
    ollama_timeout_seconds: int
    fingerbank_enabled: bool
    fingerbank_api_key: str
    fingerbank_base_url: str
    fingerbank_timeout_seconds: int
    fingerbank_min_score_accept: float
    fingerbank_min_score_auto_accept: float
    collectors_enabled: bool
    collector_interface: str
    collector_dhcp_enabled: bool
    collector_mdns_enabled: bool
    collector_ssdp_enabled: bool
    observations_list_limit: int
    fingerprints_list_limit: int
    notable_asset_limit: int
    classification_fallback_role: str
    classification_fallback_confidence: float
    log_level: str
    admin_stale_scan_minutes: int
    auth_session_days: int
    default_admin_username: str
    default_admin_password: str
    default_admin_display_name: str


def load_brain_config(environ: Mapping[str, str] | None = None) -> BrainConfig:
    config = BrainConfig(
        database_url=validate_database_url(env_str("DATABASE_URL", environ=environ, required=True)),
        ollama_url=env_url("OLLAMA_URL", environ=environ, required=True),
        ollama_model=env_str("OLLAMA_MODEL", "homelabsec-classifier", environ=environ),
        ollama_timeout_seconds=env_int(
            "OLLAMA_TIMEOUT_SECONDS",
            120,
            environ=environ,
            minimum=1,
        ),
        fingerbank_enabled=env_bool("FINGERBANK_ENABLED", True, environ=environ),
        fingerbank_api_key=env_str("FINGERBANK_API_KEY", "", environ=environ, allow_blank=True),
        fingerbank_base_url=env_url(
            "FINGERBANK_BASE_URL",
            "https://api.fingerbank.org",
            environ=environ,
        ),
        fingerbank_timeout_seconds=env_int(
            "FINGERBANK_TIMEOUT_SECONDS",
            10,
            environ=environ,
            minimum=1,
        ),
        fingerbank_min_score_accept=env_float(
            "FINGERBANK_MIN_SCORE_ACCEPT",
            51,
            environ=environ,
            minimum=0,
            maximum=100,
        ),
        fingerbank_min_score_auto_accept=env_float(
            "FINGERBANK_MIN_SCORE_AUTO_ACCEPT",
            76,
            environ=environ,
            minimum=0,
            maximum=100,
        ),
        collectors_enabled=env_bool("COLLECTORS_ENABLED", True, environ=environ),
        collector_interface=env_str("COLLECTOR_INTERFACE", "any", environ=environ),
        collector_dhcp_enabled=env_bool("COLLECTOR_DHCP_ENABLED", True, environ=environ),
        collector_mdns_enabled=env_bool("COLLECTOR_MDNS_ENABLED", True, environ=environ),
        collector_ssdp_enabled=env_bool("COLLECTOR_SSDP_ENABLED", True, environ=environ),
        observations_list_limit=env_int(
            "OBSERVATIONS_LIST_LIMIT",
            200,
            environ=environ,
            minimum=1,
        ),
        fingerprints_list_limit=env_int(
            "FINGERPRINTS_LIST_LIMIT",
            200,
            environ=environ,
            minimum=1,
        ),
        notable_asset_limit=env_int(
            "NOTABLE_ASSET_LIMIT",
            20,
            environ=environ,
            minimum=1,
        ),
        classification_fallback_role=env_str(
            "CLASSIFICATION_FALLBACK_ROLE",
            "unknown",
            environ=environ,
        ),
        classification_fallback_confidence=env_float(
            "CLASSIFICATION_FALLBACK_CONFIDENCE",
            0.10,
            environ=environ,
            minimum=0.0,
            maximum=1.0,
        ),
        log_level=env_log_level("LOG_LEVEL", "INFO", environ=environ),
        admin_stale_scan_minutes=env_int(
            "ADMIN_STALE_SCAN_MINUTES",
            90,
            environ=environ,
            minimum=1,
        ),
        auth_session_days=env_int(
            "AUTH_SESSION_DAYS",
            7,
            environ=environ,
            minimum=1,
        ),
        default_admin_username=env_str(
            "DEFAULT_ADMIN_USERNAME",
            "admin",
            environ=environ,
        ),
        default_admin_password=env_str(
            "DEFAULT_ADMIN_PASSWORD",
            "change-me-now",
            environ=environ,
        ),
        default_admin_display_name=env_str(
            "DEFAULT_ADMIN_DISPLAY_NAME",
            "Administrator",
            environ=environ,
        ),
    )

    if not config.ollama_model:
        raise ConfigError("OLLAMA_MODEL must not be blank")
    if config.fingerbank_min_score_auto_accept < config.fingerbank_min_score_accept:
        raise ConfigError("FINGERBANK_MIN_SCORE_AUTO_ACCEPT must be >= FINGERBANK_MIN_SCORE_ACCEPT")
    if not config.collector_interface:
        raise ConfigError("COLLECTOR_INTERFACE must not be blank")
    if not config.classification_fallback_role:
        raise ConfigError("CLASSIFICATION_FALLBACK_ROLE must not be blank")
    if not config.default_admin_username:
        raise ConfigError("DEFAULT_ADMIN_USERNAME must not be blank")
    if not config.default_admin_password:
        raise ConfigError("DEFAULT_ADMIN_PASSWORD must not be blank")
    if not config.default_admin_display_name:
        raise ConfigError("DEFAULT_ADMIN_DISPLAY_NAME must not be blank")
    return config


CONFIG = load_brain_config()

DATABASE_URL = CONFIG.database_url
OLLAMA_URL = CONFIG.ollama_url
OLLAMA_MODEL = CONFIG.ollama_model
OLLAMA_TIMEOUT_SECONDS = CONFIG.ollama_timeout_seconds
FINGERBANK_ENABLED = CONFIG.fingerbank_enabled
FINGERBANK_API_KEY = CONFIG.fingerbank_api_key
FINGERBANK_BASE_URL = CONFIG.fingerbank_base_url
FINGERBANK_TIMEOUT_SECONDS = CONFIG.fingerbank_timeout_seconds
FINGERBANK_MIN_SCORE_ACCEPT = CONFIG.fingerbank_min_score_accept
FINGERBANK_MIN_SCORE_AUTO_ACCEPT = CONFIG.fingerbank_min_score_auto_accept
COLLECTORS_ENABLED = CONFIG.collectors_enabled
COLLECTOR_INTERFACE = CONFIG.collector_interface
COLLECTOR_DHCP_ENABLED = CONFIG.collector_dhcp_enabled
COLLECTOR_MDNS_ENABLED = CONFIG.collector_mdns_enabled
COLLECTOR_SSDP_ENABLED = CONFIG.collector_ssdp_enabled
OBSERVATIONS_LIST_LIMIT = CONFIG.observations_list_limit
FINGERPRINTS_LIST_LIMIT = CONFIG.fingerprints_list_limit
NOTABLE_ASSET_LIMIT = CONFIG.notable_asset_limit
CLASSIFICATION_FALLBACK_ROLE = CONFIG.classification_fallback_role
CLASSIFICATION_FALLBACK_CONFIDENCE = CONFIG.classification_fallback_confidence
LOG_LEVEL = CONFIG.log_level
ADMIN_STALE_SCAN_MINUTES = CONFIG.admin_stale_scan_minutes
AUTH_SESSION_DAYS = CONFIG.auth_session_days
DEFAULT_ADMIN_USERNAME = CONFIG.default_admin_username
DEFAULT_ADMIN_PASSWORD = CONFIG.default_admin_password
DEFAULT_ADMIN_DISPLAY_NAME = CONFIG.default_admin_display_name


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
