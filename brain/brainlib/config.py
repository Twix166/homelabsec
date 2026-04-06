import os
from datetime import datetime, timezone


def env_int(name: str, default: int) -> int:
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def env_float(name: str, default: float) -> float:
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default


DATABASE_URL = os.environ["DATABASE_URL"]
OLLAMA_URL = os.environ["OLLAMA_URL"].rstrip("/")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "homelabsec-classifier")
OLLAMA_TIMEOUT_SECONDS = env_int("OLLAMA_TIMEOUT_SECONDS", 120)
OBSERVATIONS_LIST_LIMIT = env_int("OBSERVATIONS_LIST_LIMIT", 200)
FINGERPRINTS_LIST_LIMIT = env_int("FINGERPRINTS_LIST_LIMIT", 200)
NOTABLE_ASSET_LIMIT = env_int("NOTABLE_ASSET_LIMIT", 20)
CLASSIFICATION_FALLBACK_ROLE = os.environ.get("CLASSIFICATION_FALLBACK_ROLE", "unknown")
CLASSIFICATION_FALLBACK_CONFIDENCE = env_float("CLASSIFICATION_FALLBACK_CONFIDENCE", 0.10)
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
