from __future__ import annotations

import json
from typing import Any

from brainlib.metrics import render_metrics
from brainlib.ollama import OllamaError, chat_json
from brainlib.versioning import current_version


def health_status() -> dict[str, str]:
    return {"status": "ok"}


def version_status() -> dict[str, str]:
    return {"version": current_version()}


def metrics_payload() -> str:
    return render_metrics()


def ollama_test_payload() -> dict[str, Any]:
    data = chat_json(
        [
            {
                "role": "system",
                "content": "Return strict JSON only with keys role and confidence.",
            },
            {
                "role": "user",
                "content": "Classify a host with ports 22, 80, 443 and nginx detected.",
            },
        ]
    )

    content = data["message"]["content"]
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError:
        parsed = {"raw_content": content}
    return {"model": data.get("model"), "result": parsed}
