import importlib.util
import os
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
BRAIN_CONFIG_PATH = REPO_ROOT / "brain" / "brainlib" / "config.py"
SCHEDULER_CONFIG_PATH = REPO_ROOT / "scheduler" / "config.py"


def _load_module(module_name: str, path: Path):
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def test_brain_config_validates_expected_values(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@localhost:5432/homelabsec")
    monkeypatch.setenv("OLLAMA_URL", "http://localhost:11434")
    monkeypatch.setenv("CLASSIFICATION_FALLBACK_CONFIDENCE", "0.55")
    monkeypatch.setenv("OBSERVATIONS_LIST_LIMIT", "25")
    monkeypatch.setenv("ADMIN_STALE_SCAN_MINUTES", "120")

    config_module = _load_module("brain_config_valid", BRAIN_CONFIG_PATH)
    config = config_module.load_brain_config(os.environ)

    assert config.database_url.endswith("/homelabsec")
    assert config.ollama_url == "http://localhost:11434"
    assert config.classification_fallback_confidence == 0.55
    assert config.observations_list_limit == 25
    assert config.admin_stale_scan_minutes == 120


def test_brain_config_rejects_invalid_confidence(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@localhost:5432/homelabsec")
    monkeypatch.setenv("OLLAMA_URL", "http://localhost:11434")
    monkeypatch.setenv("CLASSIFICATION_FALLBACK_CONFIDENCE", "1.5")

    with pytest.raises(Exception):
        _load_module("brain_config_invalid_confidence", BRAIN_CONFIG_PATH)


def test_scheduler_config_rejects_invalid_api_base(monkeypatch):
    monkeypatch.setenv("API_BASE", "ftp://brain:8088")

    with pytest.raises(Exception):
        _load_module("scheduler_config_invalid_api_base", SCHEDULER_CONFIG_PATH)


def test_scheduler_config_parses_booleans_and_ports(monkeypatch):
    monkeypatch.setenv("API_BASE", "http://127.0.0.1:8088")
    monkeypatch.setenv("STARTUP_DISCOVERY", "true")
    monkeypatch.setenv("REPORT_HOUR_UTC", "9")
    monkeypatch.setenv("SCHEDULER_METRICS_PORT", "9200")

    config_module = _load_module("scheduler_config_valid", SCHEDULER_CONFIG_PATH)
    config = config_module.load_scheduler_config(os.environ)

    assert config.api_base == "http://127.0.0.1:8088"
    assert config.startup_discovery is True
    assert config.report_hour_utc == 9
    assert config.scheduler_metrics_port == 9200
