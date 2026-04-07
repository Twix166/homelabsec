from __future__ import annotations

import re
import threading
import time
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)

_lock = threading.Lock()
_process_start_time = time.time()
_job_started: dict[str, int] = defaultdict(int)
_job_completed: dict[str, int] = defaultdict(int)
_job_failed: dict[str, int] = defaultdict(int)
_job_duration_sum: dict[str, float] = defaultdict(float)
_job_duration_count: dict[str, int] = defaultdict(int)
_job_last_success_timestamp: dict[str, float] = {}
_api_requests: dict[tuple[str, str, str], int] = defaultdict(int)
_api_request_failures: dict[tuple[str, str], int] = defaultdict(int)


def normalize_metrics_path(path: str) -> str:
    normalized = _UUID_RE.sub("{id}", path)
    if normalized.startswith("/classify/"):
        return "/classify/{id}"
    if normalized.startswith("/fingerprint/"):
        return "/fingerprint/{id}"
    if normalized.startswith("/detect_changes/"):
        return "/detect_changes/{id}"
    return normalized


def record_job_started(job: str) -> None:
    with _lock:
        _job_started[job] += 1


def record_job_completed(job: str, duration_seconds: float) -> None:
    with _lock:
        _job_completed[job] += 1
        _job_duration_sum[job] += duration_seconds
        _job_duration_count[job] += 1
        _job_last_success_timestamp[job] = time.time()


def record_job_failed(job: str, duration_seconds: float) -> None:
    with _lock:
        _job_failed[job] += 1
        _job_duration_sum[job] += duration_seconds
        _job_duration_count[job] += 1


def record_api_request(method: str, path: str, status_code: int) -> None:
    with _lock:
        _api_requests[(method, normalize_metrics_path(path), str(status_code))] += 1


def record_api_request_failure(method: str, path: str) -> None:
    with _lock:
        _api_request_failures[(method, normalize_metrics_path(path))] += 1


def _escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _labels(**labels: str) -> str:
    if not labels:
        return ""
    rendered = ",".join(f'{key}="{_escape_label(value)}"' for key, value in labels.items())
    return f"{{{rendered}}}"


def render_metrics() -> str:
    lines = [
        "# HELP homelabsec_scheduler_job_started_total Scheduler job starts.",
        "# TYPE homelabsec_scheduler_job_started_total counter",
    ]

    with _lock:
        for job, value in sorted(_job_started.items()):
            lines.append(f"homelabsec_scheduler_job_started_total{_labels(job=job)} {value}")

        lines.extend(
            [
                "# HELP homelabsec_scheduler_job_completed_total Scheduler job completions.",
                "# TYPE homelabsec_scheduler_job_completed_total counter",
            ]
        )
        for job, value in sorted(_job_completed.items()):
            lines.append(f"homelabsec_scheduler_job_completed_total{_labels(job=job)} {value}")

        lines.extend(
            [
                "# HELP homelabsec_scheduler_job_failed_total Scheduler job failures.",
                "# TYPE homelabsec_scheduler_job_failed_total counter",
            ]
        )
        for job, value in sorted(_job_failed.items()):
            lines.append(f"homelabsec_scheduler_job_failed_total{_labels(job=job)} {value}")

        lines.extend(
            [
                "# HELP homelabsec_scheduler_job_duration_seconds_sum Total job duration in seconds.",
                "# TYPE homelabsec_scheduler_job_duration_seconds_sum counter",
            ]
        )
        for job, value in sorted(_job_duration_sum.items()):
            lines.append(f"homelabsec_scheduler_job_duration_seconds_sum{_labels(job=job)} {value}")

        lines.extend(
            [
                "# HELP homelabsec_scheduler_job_duration_seconds_count Job count used for duration averages.",
                "# TYPE homelabsec_scheduler_job_duration_seconds_count counter",
            ]
        )
        for job, value in sorted(_job_duration_count.items()):
            lines.append(f"homelabsec_scheduler_job_duration_seconds_count{_labels(job=job)} {value}")

        lines.extend(
            [
                "# HELP homelabsec_scheduler_job_last_success_timestamp_seconds Last successful completion time per job.",
                "# TYPE homelabsec_scheduler_job_last_success_timestamp_seconds gauge",
            ]
        )
        for job, value in sorted(_job_last_success_timestamp.items()):
            lines.append(
                f"homelabsec_scheduler_job_last_success_timestamp_seconds{_labels(job=job)} {value}"
            )

        lines.extend(
            [
                "# HELP homelabsec_scheduler_api_requests_total API requests issued by the scheduler.",
                "# TYPE homelabsec_scheduler_api_requests_total counter",
            ]
        )
        for (method, path, status), value in sorted(_api_requests.items()):
            lines.append(
                f"homelabsec_scheduler_api_requests_total{_labels(method=method, path=path, status=status)} {value}"
            )

        lines.extend(
            [
                "# HELP homelabsec_scheduler_api_request_failures_total API request failures before success or exhaustion.",
                "# TYPE homelabsec_scheduler_api_request_failures_total counter",
            ]
        )
        for (method, path), value in sorted(_api_request_failures.items()):
            lines.append(
                f"homelabsec_scheduler_api_request_failures_total{_labels(method=method, path=path)} {value}"
            )

    lines.extend(
        [
            "# HELP homelabsec_scheduler_process_start_time_seconds Start time of the current scheduler process.",
            "# TYPE homelabsec_scheduler_process_start_time_seconds gauge",
            f"homelabsec_scheduler_process_start_time_seconds {_process_start_time}",
            "# HELP homelabsec_scheduler_info Static scheduler metadata.",
            "# TYPE homelabsec_scheduler_info gauge",
            'homelabsec_scheduler_info{app="scheduler"} 1',
        ]
    )

    return "\n".join(lines) + "\n"


def start_metrics_server(port: int) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            if self.path != "/metrics":
                self.send_response(404)
                self.end_headers()
                return
            payload = render_metrics().encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format, *args):  # noqa: A003
            return

    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
