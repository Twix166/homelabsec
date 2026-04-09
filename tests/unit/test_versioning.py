import importlib.util
import re
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
VERSION_PATH = REPO_ROOT / "brain" / "VERSION"
VERSIONING_PATH = REPO_ROOT / "brain" / "brainlib" / "versioning.py"


def _load_module(module_name: str, path: Path):
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def test_version_file_matches_semver():
    version = VERSION_PATH.read_text(encoding="utf-8").strip()
    assert re.fullmatch(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$", version)


def test_current_version_reads_version_file():
    versioning_module = _load_module("homelabsec_versioning", VERSIONING_PATH)
    assert versioning_module.current_version() == "0.2.0"
