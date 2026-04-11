from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path


def load_runner_module():
    config_module = types.ModuleType("config")
    config_module.CONFIG = types.SimpleNamespace(
        api_base="http://brain:8088",
        poll_interval_seconds=10,
        ssh_timeout_seconds=30,
        lynis_audit_timeout_seconds=1800,
        lynis_repo_url="https://github.com/CISOfy/lynis.git",
        log_level="INFO",
    )
    logging_utils = types.ModuleType("logging_utils")
    logging_utils.configure_logging = lambda name: object()
    logging_utils.log_event = lambda *args, **kwargs: None
    paramiko_module = types.ModuleType("paramiko")
    paramiko_module.SSHClient = object
    paramiko_module.AutoAddPolicy = object
    requests_module = types.ModuleType("requests")
    requests_module.get = lambda *args, **kwargs: None
    requests_module.post = lambda *args, **kwargs: None

    old_modules = {name: sys.modules.get(name) for name in ("config", "logging_utils", "paramiko", "requests")}
    sys.modules["config"] = config_module
    sys.modules["logging_utils"] = logging_utils
    sys.modules["paramiko"] = paramiko_module
    sys.modules["requests"] = requests_module

    try:
        module_path = Path(__file__).resolve().parents[2] / "lynis_runner" / "runner.py"
        spec = importlib.util.spec_from_file_location("test_lynis_runner_module", module_path)
        module = importlib.util.module_from_spec(spec)
        assert spec is not None and spec.loader is not None
        spec.loader.exec_module(module)
        return module
    finally:
        for name, original in old_modules.items():
            if original is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = original


runner = load_runner_module()


def test_format_exception_includes_type_for_blank_message():
    exc = TimeoutError()

    assert runner.format_exception(exc) == "TimeoutError"


def test_format_exception_includes_message_when_present():
    exc = RuntimeError("sudo failed")

    assert runner.format_exception(exc) == "RuntimeError: sudo failed"


def test_build_audit_command_without_sudo():
    command, password = runner.build_audit_command("/usr/bin/lynis", {"use_sudo": False}, "/tmp/report", "/tmp/log")

    assert command == "/usr/bin/lynis audit system --quick --report-file /tmp/report --logfile /tmp/log"
    assert password is None


def test_build_audit_command_with_sudo_and_password():
    command, password = runner.build_audit_command(
        "/home/rbalm/.local/share/homelabsec/lynis/lynis",
        {"use_sudo": True, "ssh_password": "secret", "ssh_username": "rbalm"},
        "/tmp/report",
        "/tmp/log",
    )

    assert command == (
        "printf '%s\\n' secret | sudo -S -p '' "
        "sh -lc 'cd /home/rbalm/.local/share/homelabsec/lynis && ./lynis audit system --quick "
        "--report-file /tmp/report --logfile /tmp/log'"
    )
    assert password == "secret"


def test_build_audit_command_with_sudo_and_no_password():
    command, password = runner.build_audit_command(
        "/home/rbalm/.local/share/homelabsec/lynis/lynis",
        {"use_sudo": True, "ssh_password": None, "ssh_username": "rbalm"},
        "/tmp/report",
        "/tmp/log",
    )

    assert command == (
        "sudo -n sh -lc 'cd /home/rbalm/.local/share/homelabsec/lynis && ./lynis audit system --quick "
        "--report-file /tmp/report --logfile /tmp/log'"
    )
    assert password is None


def test_install_dir_uses_remote_user_home():
    install_dir = runner._install_dir({"ssh_username": "rbalm"})

    assert install_dir == "/home/rbalm/.local/share/homelabsec/lynis"


def test_redact_secret_replaces_password_echoes():
    text = "sudo password is secret"

    assert runner.redact_secret(text, "secret") == "sudo password is [redacted]"


def test_strip_control_sequences_removes_terminal_noise():
    text = "\u001b]3008;start=session\u001b\\\\Fatal error\u001b]3008;end=session\u001b\\\\"

    assert runner.strip_control_sequences(text) == "Fatal error"
