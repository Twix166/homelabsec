from __future__ import annotations

from dataclasses import dataclass

from urllib.parse import urlparse
import os


def env_str(name: str, default: str) -> str:
    value = os.environ.get(name, default).strip()
    return value or default


def env_int(name: str, default: int, minimum: int = 1) -> int:
    raw = os.environ.get(name, "").strip()
    value = int(raw) if raw else default
    if value < minimum:
        raise RuntimeError(f"{name} must be >= {minimum}")
    return value


def env_url(name: str, default: str) -> str:
    value = env_str(name, default).rstrip("/")
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise RuntimeError(f"{name} must be a valid http(s) URL")
    return value


@dataclass(frozen=True)
class LynisRunnerConfig:
    api_base: str
    poll_interval_seconds: int
    ssh_timeout_seconds: int
    lynis_audit_timeout_seconds: int
    lynis_repo_url: str
    log_level: str


def load_config() -> LynisRunnerConfig:
    return LynisRunnerConfig(
        api_base=env_url("API_BASE", "http://brain:8088"),
        poll_interval_seconds=env_int("LYNIS_POLL_INTERVAL_SECONDS", 10),
        ssh_timeout_seconds=env_int("LYNIS_SSH_TIMEOUT_SECONDS", 30),
        lynis_audit_timeout_seconds=env_int("LYNIS_AUDIT_TIMEOUT_SECONDS", 1800),
        lynis_repo_url=env_str("LYNIS_REPO_URL", "https://github.com/CISOfy/lynis.git"),
        log_level=env_str("LOG_LEVEL", "INFO"),
    )


CONFIG = load_config()
