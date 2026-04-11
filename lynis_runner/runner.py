from __future__ import annotations

import shlex
import time
import re
from socket import timeout as SocketTimeout

import paramiko
import requests

from config import CONFIG
from logging_utils import configure_logging, log_event


logger = configure_logging("homelabsec.lynis_runner")


def api_post(path: str, payload: dict | None = None) -> dict:
    response = requests.post(f"{CONFIG.api_base}{path}", json=payload or {}, timeout=60)
    response.raise_for_status()
    return response.json()


def api_get(path: str) -> dict:
    response = requests.get(f"{CONFIG.api_base}{path}", timeout=30)
    response.raise_for_status()
    return response.json()


def parse_report(report_text: str) -> dict:
    summary: dict[str, object] = {"warnings": [], "suggestions": []}
    for raw_line in report_text.splitlines():
        line = raw_line.strip()
        if not line or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key == "hardening_index":
            try:
                summary["hardening_index"] = int(value)
            except ValueError:
                summary["hardening_index"] = value
        elif key == "warning[]":
            summary["warnings"].append(value)
        elif key == "suggestion[]":
            summary["suggestions"].append(value)
        elif key in {"lynis_version", "hostid", "os_name", "os_version"}:
            summary[key] = value
    summary["warning_count"] = len(summary["warnings"])
    summary["suggestion_count"] = len(summary["suggestions"])
    return summary


def _connect(target: dict) -> paramiko.SSHClient:
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        hostname=target["ssh_host"],
        port=target["ssh_port"],
        username=target["ssh_username"],
        password=target.get("ssh_password"),
        timeout=CONFIG.ssh_timeout_seconds,
    )
    return ssh


def format_exception(exc: Exception) -> str:
    message = str(exc).strip()
    if message:
        return f"{type(exc).__name__}: {message}"
    return type(exc).__name__


def redact_secret(text: str, secret: str | None) -> str:
    if not text or not secret:
        return text
    return text.replace(secret, "[redacted]")


CONTROL_SEQUENCE_RE = re.compile(r"\x1b(?:\][^\x07\x1b]*(?:\x07|\x1b\\\\)|[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def strip_control_sequences(text: str) -> str:
    if not text:
        return text
    return CONTROL_SEQUENCE_RE.sub("", text)


def _run_command(
    ssh: paramiko.SSHClient,
    command: str,
    *,
    timeout: int | None = None,
) -> tuple[int, str, str]:
    stdin, stdout, stderr = ssh.exec_command(
        command,
        get_pty=True,
        timeout=CONFIG.ssh_timeout_seconds if timeout is None else timeout,
    )
    try:
        output = stdout.read().decode("utf-8", errors="replace")
        error = stderr.read().decode("utf-8", errors="replace")
    except SocketTimeout as exc:
        stdout.channel.close()
        raise RuntimeError(f"Remote command timed out after {timeout or CONFIG.ssh_timeout_seconds}s: {command}") from exc
    return stdout.channel.recv_exit_status(), strip_control_sequences(output), strip_control_sequences(error)


def _install_dir(target: dict) -> str:
    username = target["ssh_username"].strip()
    return f"/home/{username}/.local/share/homelabsec/lynis"


def ensure_lynis_command(ssh: paramiko.SSHClient, target: dict) -> tuple[str, str]:
    check_cmd = "command -v lynis || true"
    code, output, _ = _run_command(ssh, check_cmd)
    del code
    lynis_cmd = output.strip()
    if lynis_cmd:
        return lynis_cmd, ""

    install_dir = _install_dir(target)
    install_cmd = (
        "set -e; "
        "command -v git >/dev/null 2>&1 || { echo 'git is required on target'; exit 1; }; "
        f"install_dir='{install_dir}'; "
        "parent_dir=$(dirname \"$install_dir\"); "
        "mkdir -p \"$parent_dir\"; "
        "if [ -d \"$install_dir/.git\" ]; then "
        "  git -C \"$install_dir\" pull --ff-only; "
        "elif [ -d \"$install_dir\" ]; then "
        "  rm -rf \"$install_dir\"; "
        f"  git clone --depth 1 {CONFIG.lynis_repo_url} \"$install_dir\"; "
        "else "
        f"  git clone --depth 1 {CONFIG.lynis_repo_url} \"$install_dir\"; "
        "fi; "
        "[ -x \"$install_dir/lynis\" ] || { echo 'Lynis executable missing after installation'; exit 1; }; "
        "printf '%s\\n' \"$install_dir/lynis\""
    )
    code, install_output, install_error = _run_command(ssh, install_cmd)
    if code != 0:
        raise RuntimeError((install_output + "\n" + install_error).strip())
    return install_output.strip().splitlines()[-1], install_output


def build_audit_command(lynis_cmd: str, target: dict, report_path: str, log_path: str) -> tuple[str, str | None]:
    install_dir = _install_dir(target) if target.get("ssh_username") else None
    if install_dir and lynis_cmd.startswith(install_dir + "/"):
        install_dir = shlex.quote(install_dir)
        base_command = (
            f"sh -lc 'cd {install_dir} && ./lynis audit system --quick "
            f"--report-file {shlex.quote(report_path)} --logfile {shlex.quote(log_path)}'"
        )
    else:
        base_command = f"{lynis_cmd} audit system --quick --report-file {report_path} --logfile {log_path}"
    return wrap_with_sudo(base_command, target)


def wrap_with_sudo(command: str, target: dict) -> tuple[str, str | None]:
    if not target.get("use_sudo"):
        return command, None
    sudo_password = target.get("ssh_password") or None
    if sudo_password:
        return f"printf '%s\\n' {shlex.quote(sudo_password)} | sudo -S -p '' {command}", sudo_password
    return f"sudo -n {command}", None


def run_lynis_audit(run: dict) -> dict:
    target = run["target"]
    ssh = _connect(target)
    try:
        lynis_cmd, install_output = ensure_lynis_command(ssh, target)

        report_path = "/tmp/homelabsec-lynis-report.dat"
        log_path = "/tmp/homelabsec-lynis.log"
        audit_cmd, sudo_password = build_audit_command(
            lynis_cmd,
            target,
            report_path,
            log_path,
        )
        code, audit_output, audit_error = _run_command(
            ssh,
            audit_cmd,
            timeout=CONFIG.lynis_audit_timeout_seconds,
        )
        audit_output = redact_secret(audit_output, sudo_password)
        audit_error = redact_secret(audit_error, sudo_password)
        if code != 0:
            raise RuntimeError((audit_output + "\n" + audit_error).strip())

        report_cmd, report_password = wrap_with_sudo(f"cat {report_path}", target)
        _, report_text, report_error = _run_command(ssh, report_cmd)
        log_cmd, log_password = wrap_with_sudo(f"tail -n 200 {log_path}", target)
        _, log_text, log_error = _run_command(ssh, log_cmd)
        report_text = redact_secret(report_text, report_password)
        report_error = redact_secret(report_error, report_password)
        log_text = redact_secret(log_text, log_password)
        log_error = redact_secret(log_error, log_password)
        if report_error.strip():
            report_text = (report_text + "\n" + report_error).strip()
        if log_error.strip():
            log_text = (log_text + "\n" + log_error).strip()
        summary = parse_report(report_text)
        if install_output:
            summary["installation"] = install_output.strip()
        return {
            "status": "completed",
            "summary": summary,
            "report_text": report_text,
            "log_text": log_text,
        }
    finally:
        ssh.close()


def main() -> None:
    log_event(logger, "info", "lynis_runner_start", "Lynis runner starting", api_base=CONFIG.api_base)
    while True:
        try:
            claim = api_post("/lynis_runs/claim")
            if not claim.get("claimed"):
                time.sleep(CONFIG.poll_interval_seconds)
                continue

            run = claim["run"]
            log_event(logger, "info", "lynis_run_start", "Running Lynis audit", asset_id=run["asset_id"], run_id=run["run_id"])
            try:
                result = run_lynis_audit(run)
                api_post(
                    f"/lynis_runs/{run['run_id']}/complete",
                    {
                        "status": result["status"],
                        "summary": result["summary"],
                        "report_text": result["report_text"],
                        "log_text": result["log_text"],
                    },
                )
            except Exception as exc:
                error_text = format_exception(exc)
                api_post(
                    f"/lynis_runs/{run['run_id']}/complete",
                    {
                        "status": "failed",
                        "error_text": error_text,
                    },
                )
                log_event(logger, "error", "lynis_run_failed", "Lynis audit failed", run_id=run["run_id"], error=error_text)
        except Exception as exc:
            log_event(logger, "error", "lynis_runner_error", "Runner loop failed", error=format_exception(exc))
            time.sleep(CONFIG.poll_interval_seconds)


if __name__ == "__main__":
    main()
