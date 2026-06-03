#!/usr/bin/env python3
"""Validate HomelabSec Alertmanager delivery through a disposable webhook."""

from __future__ import annotations

import argparse
import json
import queue
import secrets
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


class DeliveryHandler(BaseHTTPRequestHandler):
    delivery_queue: "queue.Queue[dict[str, Any]]"
    validation_token: str

    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        try:
            payload = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            return
        alerts = payload.get("alerts", [])
        for alert in alerts:
            annotations = alert.get("annotations", {})
            if annotations.get("validation_token") == self.validation_token:
                self.delivery_queue.put(payload)
                break
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok\n")

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib signature name
        return


def _post_json(url: str, payload: Any, timeout_seconds: float) -> int:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        return int(response.status)


def _build_alert(alert_name: str, webhook_url: str, validation_token: str) -> list[dict[str, Any]]:
    now = datetime.now(timezone.utc).isoformat()
    return [
        {
            "labels": {
                "alertname": alert_name,
                "service": "homelabsec",
                "severity": "info",
                "source": "delivery-validation",
            },
            "annotations": {
                "summary": "HomelabSec alert delivery validation",
                "description": "Synthetic alert used to verify Alertmanager webhook delivery.",
                "webhook_url": webhook_url,
                "validation_token": validation_token,
            },
            "startsAt": now,
            "generatorURL": "https://github.com/Twix166/homelabsec",
        }
    ]


def validate_delivery(
    alertmanager_url: str,
    listen_host: str,
    listen_port: int,
    timeout_seconds: float,
    alert_name: str,
) -> dict[str, Any]:
    delivery_queue: "queue.Queue[dict[str, Any]]" = queue.Queue(maxsize=1)
    validation_token = secrets.token_urlsafe(16)

    handler_class = type(
        "HomelabSecDeliveryHandler",
        (DeliveryHandler,),
        {"delivery_queue": delivery_queue, "validation_token": validation_token},
    )
    server = ThreadingHTTPServer((listen_host, listen_port), handler_class)
    webhook_url = f"http://{listen_host}:{server.server_address[1]}/homelabsec-alert-validation"
    alerts_url = alertmanager_url.rstrip("/") + "/api/v2/alerts"
    result: dict[str, Any] = {
        "delivered": False,
        "alert_name": alert_name,
        "alertmanager_url": alertmanager_url,
        "webhook_url": webhook_url,
        "validation_token": validation_token,
    }

    try:
        import threading

        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            result["alertmanager_status"] = _post_json(
                alerts_url,
                _build_alert(alert_name, webhook_url, validation_token),
                timeout_seconds,
            )
            deadline = time.monotonic() + timeout_seconds
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    result["error"] = "Timed out waiting for Alertmanager to call disposable webhook"
                    return result
                try:
                    payload = delivery_queue.get(timeout=min(remaining, 0.25))
                    result["delivered"] = True
                    result["received_alert_count"] = len(payload.get("alerts", []))
                    return result
                except queue.Empty:
                    continue
        finally:
            server.shutdown()
            thread.join(timeout=2)
    except (OSError, urllib.error.URLError, TimeoutError) as exc:
        result["error"] = str(exc)
        return result
    finally:
        server.server_close()


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--alertmanager-url", default="http://127.0.0.1:9093")
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=0)
    parser.add_argument("--timeout-seconds", type=float, default=20)
    parser.add_argument("--alert-name", default="HomelabSecDeliveryValidation")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    result = validate_delivery(
        alertmanager_url=args.alertmanager_url,
        listen_host=args.listen_host,
        listen_port=args.listen_port,
        timeout_seconds=args.timeout_seconds,
        alert_name=args.alert_name,
    )
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        status = "delivered" if result["delivered"] else "not delivered"
        print(f"HomelabSec alert delivery validation: {status}")
        print(f"Alertmanager: {result['alertmanager_url']}")
        print(f"Disposable webhook: {result['webhook_url']}")
        if "error" in result:
            print(f"Error: {result['error']}", file=sys.stderr)
    return 0 if result["delivered"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
