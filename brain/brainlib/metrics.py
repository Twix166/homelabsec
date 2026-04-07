from __future__ import annotations

import re
import threading
import time
from collections import defaultdict

_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)

_lock = threading.Lock()
_process_start_time = time.time()
_request_counts: dict[tuple[str, str, str], int] = defaultdict(int)
_request_duration_sum: dict[tuple[str, str], float] = defaultdict(float)
_request_duration_count: dict[tuple[str, str], int] = defaultdict(int)


def normalize_metrics_path(path: str) -> str:
    normalized = _UUID_RE.sub("{id}", path)
    if normalized.startswith("/classify/"):
        return "/classify/{id}"
    if normalized.startswith("/fingerprint/"):
        return "/fingerprint/{id}"
    if normalized.startswith("/detect_changes/"):
        return "/detect_changes/{id}"
    return normalized


def record_http_request(method: str, path: str, status_code: int, duration_seconds: float) -> None:
    normalized_path = normalize_metrics_path(path)
    with _lock:
        _request_counts[(method, normalized_path, str(status_code))] += 1
        _request_duration_sum[(method, normalized_path)] += duration_seconds
        _request_duration_count[(method, normalized_path)] += 1


def _escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _labels(**labels: str) -> str:
    if not labels:
        return ""
    rendered = ",".join(f'{key}="{_escape_label(value)}"' for key, value in labels.items())
    return f"{{{rendered}}}"


def render_metrics() -> str:
    lines = [
        "# HELP homelabsec_http_requests_total Total HTTP requests handled by brain.",
        "# TYPE homelabsec_http_requests_total counter",
    ]

    with _lock:
        for (method, path, status), value in sorted(_request_counts.items()):
            lines.append(
                f"homelabsec_http_requests_total{_labels(method=method, path=path, status=status)} {value}"
            )

        lines.extend(
            [
                "# HELP homelabsec_http_request_duration_seconds_sum Total request duration in seconds.",
                "# TYPE homelabsec_http_request_duration_seconds_sum counter",
            ]
        )
        for (method, path), value in sorted(_request_duration_sum.items()):
            lines.append(
                f"homelabsec_http_request_duration_seconds_sum{_labels(method=method, path=path)} {value}"
            )

        lines.extend(
            [
                "# HELP homelabsec_http_request_duration_seconds_count Total request count used for duration averages.",
                "# TYPE homelabsec_http_request_duration_seconds_count counter",
            ]
        )
        for (method, path), value in sorted(_request_duration_count.items()):
            lines.append(
                f"homelabsec_http_request_duration_seconds_count{_labels(method=method, path=path)} {value}"
            )

    lines.extend(
        [
            "# HELP homelabsec_process_start_time_seconds Start time of the current brain process.",
            "# TYPE homelabsec_process_start_time_seconds gauge",
            f"homelabsec_process_start_time_seconds {_process_start_time}",
            "# HELP homelabsec_app_info Static app metadata.",
            "# TYPE homelabsec_app_info gauge",
            'homelabsec_app_info{app="brain"} 1',
        ]
    )

    return "\n".join(lines) + "\n"
