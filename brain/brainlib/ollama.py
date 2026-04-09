from __future__ import annotations

from typing import Any

import requests

from brainlib.config import OLLAMA_MODEL, OLLAMA_TIMEOUT_SECONDS, OLLAMA_URL


class OllamaError(RuntimeError):
    pass


def chat_json(messages: list[dict[str, str]]) -> dict[str, Any]:
    payload = {
        "model": OLLAMA_MODEL,
        "format": "json",
        "stream": False,
        "messages": messages,
    }

    try:
        response = requests.post(
            f"{OLLAMA_URL}/api/chat",
            json=payload,
            timeout=OLLAMA_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        raise OllamaError(f"Ollama request failed: {exc}") from exc

    try:
        data = response.json()
    except ValueError as exc:
        raise OllamaError("Ollama returned invalid JSON") from exc

    message = data.get("message")
    if not isinstance(message, dict) or not isinstance(message.get("content"), str):
        raise OllamaError("Ollama response did not include message content")

    return data
