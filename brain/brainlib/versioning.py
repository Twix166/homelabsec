from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path


VERSION_PATH = Path(__file__).resolve().parents[1] / "VERSION"
SEMVER_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")


@lru_cache(maxsize=1)
def current_version() -> str:
    version = VERSION_PATH.read_text(encoding="utf-8").strip()
    if not SEMVER_RE.fullmatch(version):
        raise RuntimeError(f"Invalid semantic version in {VERSION_PATH}: {version!r}")
    return version
