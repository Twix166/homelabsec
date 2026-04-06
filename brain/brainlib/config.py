import os
from datetime import datetime, timezone


DATABASE_URL = os.environ["DATABASE_URL"]
OLLAMA_URL = os.environ["OLLAMA_URL"].rstrip("/")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "homelabsec-classifier")


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
