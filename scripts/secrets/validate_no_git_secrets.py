#!/usr/bin/env python3
"""Validate the HomelabSec zero-secret Git boundary.

This validator is intentionally conservative. It checks tracked and staged files
for secret-bearing paths and common secret markers, including encrypted secret
artifacts that Robert does not want in GitHub.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from typing import NoReturn

REPO = Path(__file__).resolve().parents[2]

FORBIDDEN_PATH_PATTERNS = [
    re.compile(r"(^|/)secrets/runtime/"),
    re.compile(r"(^|/)secrets/sops/"),
    re.compile(r"(^|/)secrets/plaintext/"),
    re.compile(r"(^|/)secrets/tmp/"),
    re.compile(r"(^|/)openbao/(data|raft|snapshots?|backups?|tokens?|unseal|recovery)(/|$)", re.I),
    re.compile(r"(^|/)vaultwarden/(data|db|exports?|backups?|attachments?)(/|$)", re.I),
    re.compile(r"(^|/)\.sops\.ya?ml$"),
    re.compile(r"(^|/)\.env$"),
    re.compile(r"\.env$"),
    re.compile(r"\.enc\.(json|ya?ml|env|txt)$", re.I),
    re.compile(r"\.(pem|key|p12|pfx|kdbx|vault)$", re.I),
    re.compile(r"(^|/)(id_rsa|id_ed25519|id_ecdsa|known_hosts|authorized_keys)$"),
    re.compile(r"(^|/)(vault|bao|openbao|bw|bitwarden|vaultwarden).*(token|session|export|snapshot|unseal|recovery|key)", re.I),
]

PRIVATE_MARKERS = [
    "AGE-SECRET" + "-KEY-",
    "-----BEGIN OPENSSH PRIVATE" + " KEY-----",
    "-----BEGIN RSA PRIVATE" + " KEY-----",
    "-----BEGIN EC PRIVATE" + " KEY-----",
    "-----BEGIN PRIVATE" + " KEY-----",
    "sops:",
    "ENC[AES256_GCM",
]

ASSIGNMENT_RE = re.compile(
    r"\b(BAO_TOKEN|VAULT_TOKEN|BW_SESSION|ADMIN_TOKEN|GITHUB_TOKEN|CF_API_TOKEN|TELEGRAM_TOKEN|PASSWORD|PASSWD|SECRET|TOKEN|PRIVATE_KEY)\s*=\s*([^\s'\"]+)",
)
SAFE_PLACEHOLDERS = {
    "change-me",
    "replace-me",
    "redacted",
    "example",
    "placeholder",
    "***",
    "<redacted>",
    "<set-outside-git>",
    "<vault-path>",
}

ALLOWLIST_TEXT_MARKERS = {
    "docs/operations/vaultwarden-openbao-secret-management.md",
    "docs/operations/homelab-secret-management-strategy.md",
    "secrets/README.md",
    "scripts/secrets/validate_no_git_secrets.py",
}


def fail(message: str) -> NoReturn:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def run_git(args: list[str]) -> list[str]:
    result = subprocess.run(
        ["git", *args],
        cwd=REPO,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        fail(result.stderr.strip() or f"git {' '.join(args)} failed")
    return [line for line in result.stdout.splitlines() if line]


def tracked_and_staged_files() -> list[str]:
    paths = set(run_git(["ls-files"]))
    paths.update(run_git(["diff", "--cached", "--name-only", "--diff-filter=ACMR"]))
    return sorted(paths)


def validate_paths(paths: list[str]) -> None:
    for rel in paths:
        if rel.endswith(".env.example"):
            continue
        for pattern in FORBIDDEN_PATH_PATTERNS:
            if pattern.search(rel):
                fail(f"forbidden secret-bearing path is tracked/staged: {rel}")


def validate_contents(paths: list[str]) -> None:
    for rel in paths:
        path = REPO / rel
        if not path.exists() or path.is_dir():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if rel not in ALLOWLIST_TEXT_MARKERS:
            for marker in PRIVATE_MARKERS:
                if marker in text:
                    fail(f"secret marker found in tracked/staged file: {rel}")
        for match in ASSIGNMENT_RE.finditer(text):
            value = match.group(2).strip().strip('"').strip("'").lower()
            if value not in SAFE_PLACEHOLDERS and not value.startswith("<"):
                fail(f"real-looking secret assignment found in {rel}: {match.group(1)}")


def main() -> int:
    paths = tracked_and_staged_files()
    validate_paths(paths)
    validate_contents(paths)
    print(f"OK zero-secret Git boundary validated for {len(paths)} tracked/staged files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
