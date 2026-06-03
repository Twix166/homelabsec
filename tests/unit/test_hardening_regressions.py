import importlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
BRAIN_DIR = REPO_ROOT / "brain"
BACKUP_SCRIPT = REPO_ROOT / "scripts" / "backup_db.sh"
PREFLIGHT_SCRIPT = REPO_ROOT / "scripts" / "preflight_exposed.sh"


def _reload_brainlib_module(module_name: str, monkeypatch):
    monkeypatch.syspath_prepend(str(BRAIN_DIR))
    for name in list(sys.modules):
        if name == module_name or name.startswith("brainlib.config") or name.startswith("brainlib.auth"):
            sys.modules.pop(name, None)
    return importlib.import_module(module_name)


class CookieRecorder:
    def __init__(self):
        self.cookies = []

    def set_cookie(self, **kwargs):
        self.cookies.append(kwargs)


def test_session_cookie_is_secure_when_configured(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@localhost:5432/homelabsec")
    monkeypatch.setenv("OLLAMA_URL", "http://localhost:11434")
    monkeypatch.setenv("AUTH_SECURE_COOKIES", "true")

    auth = _reload_brainlib_module("brainlib.auth", monkeypatch)
    response = CookieRecorder()

    auth._set_session_cookie(response, "session-token")

    assert response.cookies
    assert response.cookies[0]["secure"] is True
    assert response.cookies[0]["httponly"] is True
    assert response.cookies[0]["samesite"] == "lax"


def test_compose_smoke_tests_skip_cleanly_when_docker_is_missing(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda command: None if command == "docker" else f"/usr/bin/{command}")

    spec = importlib.util.spec_from_file_location(
        "compose_smoke_under_test",
        REPO_ROOT / "tests" / "smoke" / "test_compose_smoke.py",
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    with pytest.raises(pytest.skip.Exception):
        spec.loader.exec_module(module)


def test_exposed_preflight_rejects_default_basic_auth_password():
    result = subprocess.run(
        ["bash", str(PREFLIGHT_SCRIPT)],
        cwd=REPO_ROOT,
        env={
            **os.environ,
            "EDGE_AUTH_MODE": "basic",
            "EDGE_AUTH_USERNAME": "admin",
            "EDGE_AUTH_PASSWORD": "change-me-now",
            "EDGE_TLS_MODE": "self_signed",
        },
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "EDGE_AUTH_PASSWORD" in result.stderr
    assert "change-me-now" in result.stderr


def test_backup_status_reports_missing_docker_without_running_backup(monkeypatch):
    monkeypatch.setenv("PATH", "")
    result = subprocess.run(
        ["/bin/bash", str(BACKUP_SCRIPT), "--status"],
        cwd=REPO_ROOT,
        env={**os.environ, "PATH": ""},
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    status = json.loads(result.stdout)
    assert status["docker_available"] is False
    assert status["compose_file_exists"] is True
    assert status["ready"] is False
