#!/usr/bin/env python3
"""Render a SOPS-encrypted JSON object to a restrictive .env file.

The script intentionally does not print decrypted values. It expects the
encrypted file to decrypt to a JSON object whose keys are environment variable
names and whose values are scalars.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import NoReturn, cast

ENV_KEY_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")


def die(message: str, code: int = 1) -> NoReturn:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(code)


def decrypt_json(path: Path) -> dict[str, object]:
    result = subprocess.run(
        ["sops", "--decrypt", "--output-type", "json", str(path)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        die(f"sops decrypt failed for {path}: {result.stderr.strip()}")
    data: object
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        die(f"decrypted payload is not JSON: {exc}")
    if not isinstance(data, dict):
        die("decrypted payload must be a JSON object")
    return cast(dict[str, object], data)


def env_quote(value: object) -> str:
    if value is None:
        text = ""
    elif isinstance(value, bool):
        text = "true" if value else "false"
    elif isinstance(value, (int, float)):
        text = str(value)
    elif isinstance(value, str):
        text = value
    else:
        die(f"unsupported value type for env rendering: {type(value).__name__}")
    return "'" + text.replace("'", "'\\''") + "'"


def render(data: dict[str, object]) -> str:
    lines: list[str] = []
    for key in sorted(data):
        if key == "sops":
            continue
        if not ENV_KEY_RE.match(key):
            die(f"invalid env key {key!r}; use uppercase letters, numbers, and underscores")
        lines.append(f"{key}={env_quote(data[key])}")
    if not lines:
        die("no renderable env keys found")
    return "\n".join(lines) + "\n"


def write_restrictive(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
    finally:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("encrypted_json", type=Path)
    parser.add_argument("output_env", type=Path)
    args = parser.parse_args()

    if not args.encrypted_json.name.endswith(".enc.json"):
        die("input must be a .enc.json SOPS file")
    data = decrypt_json(args.encrypted_json)
    write_restrictive(args.output_env, render(data))
    print(f"rendered {args.output_env} with 0600 permissions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
