#!/usr/bin/env python3
"""Validate HomelabSec secret-management guardrails.

This script is intentionally secret-safe: it validates paths, tool presence, and
SOPS decryptability, but never prints decrypted values.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import NoReturn, cast

REPO = Path(__file__).resolve().parents[2]
FORBIDDEN_TRACKED_PATH_PATTERNS = [
    re.compile(r"(^|/)secrets/runtime/"),
    re.compile(r"(^|/)\.env$"),
    re.compile(r"\.env$"),
    re.compile(r"(^|/)data\.json$"),
    re.compile(r"(^|/)keys\.txt$"),
]
PRIVATE_SECRET_MARKERS = [
    "AGE-SECRET" + "-KEY-",
    "-----BEGIN OPENSSH PRIVATE" + " KEY-----",
    "-----BEGIN RSA PRIVATE" + " KEY-----",
    "-----BEGIN EC PRIVATE" + " KEY-----",
    "-----BEGIN PRIVATE" + " KEY-----",
]
ASSIGNMENT_RE = re.compile(r"\b(BW_SESSION|GITHUB_TOKEN|CF_API_TOKEN|TELEGRAM_TOKEN|PASSWORD|SECRET|TOKEN)=([^\s'\"]+)")
SAFE_PLACEHOLDERS = {"change-me", "replace-me", "redacted", "example", "placeholder", "***", "<redacted>"}


def fail(message: str) -> NoReturn:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def run(args: list[str], *, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=REPO,
        input=input_text,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )


def require_tool(name: str) -> None:
    if not shutil.which(name):
        fail(f"required tool not found on PATH: {name}")


def tracked_files() -> list[str]:
    result = run(["git", "ls-files"])
    if result.returncode != 0:
        fail(result.stderr.strip() or "git ls-files failed")
    return [line for line in result.stdout.splitlines() if line]


def validate_tracked_paths(paths: list[str]) -> None:
    for rel in paths:
        if rel.endswith(".env.example"):
            continue
        if rel.startswith("docs/"):
            continue
        if rel.startswith("secrets/sops/") and ".enc." in rel:
            continue
        for pattern in FORBIDDEN_TRACKED_PATH_PATTERNS:
            if pattern.search(rel):
                fail(f"forbidden secret-like path is tracked: {rel}")


def validate_no_private_markers(paths: list[str]) -> None:
    for rel in paths:
        path = REPO / rel
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for marker in PRIVATE_SECRET_MARKERS:
            if marker in text:
                fail(f"private secret marker found in tracked file: {rel}")
        for match in ASSIGNMENT_RE.finditer(text):
            value = match.group(2).strip().strip('"').strip("'").lower()
            if value not in SAFE_PLACEHOLDERS and not value.startswith("<"):
                fail(f"real-looking secret assignment found in tracked file: {rel}: {match.group(1)}")


def validate_sops_config() -> None:
    config = REPO / ".sops.yaml"
    if not config.exists():
        fail(".sops.yaml is missing")
    text = config.read_text(encoding="utf-8")
    age_private_marker = "AGE-SECRET" + "-KEY-"
    if age_private_marker in text:
        fail(".sops.yaml contains an age private key")
    if "age1" not in text:
        fail(".sops.yaml does not contain an age recipient")


def validate_encrypted_files() -> None:
    encrypted = sorted((REPO / "secrets" / "sops").glob("*.enc.json"))
    if not encrypted:
        fail("no encrypted SOPS JSON files found under secrets/sops")
    for path in encrypted:
        result = run(["sops", "--decrypt", "--output-type", "json", str(path.relative_to(REPO))])
        if result.returncode != 0:
            fail(f"cannot decrypt {path.relative_to(REPO)}: {result.stderr.strip()}")
        data: object
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            fail(f"decrypted {path.relative_to(REPO)} is not JSON: {exc}")
        if not isinstance(data, dict):
            fail(f"decrypted {path.relative_to(REPO)} is not a JSON object")
        payload = cast(dict[str, object], data)
        keys = sorted(k for k in payload if k != "sops")
        if not keys:
            fail(f"decrypted {path.relative_to(REPO)} has no usable keys")
        print(f"OK decryptable: {path.relative_to(REPO)} ({len(keys)} keys)")


def main() -> int:
    require_tool("git")
    require_tool("sops")
    require_tool("age")
    paths = tracked_files()
    validate_tracked_paths(paths)
    validate_no_private_markers(paths)
    validate_sops_config()
    validate_encrypted_files()
    print("OK secret-management guardrails validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
