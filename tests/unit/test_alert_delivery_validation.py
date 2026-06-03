import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "validate_alert_delivery.py"


class FakeAlertmanagerHandler(BaseHTTPRequestHandler):
    webhook_url = None
    received_alerts = []

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        FakeAlertmanagerHandler.received_alerts.append(json.loads(body.decode("utf-8")))
        alert = FakeAlertmanagerHandler.received_alerts[-1][0]
        FakeAlertmanagerHandler.webhook_url = alert["annotations"]["webhook_url"]
        webhook_payload = {
            "receiver": "webhook",
            "status": "firing",
            "alerts": [
                {
                    "status": "firing",
                    "labels": alert["labels"],
                    "annotations": alert.get("annotations", {}),
                }
            ],
        }
        import urllib.request

        request = urllib.request.Request(
            FakeAlertmanagerHandler.webhook_url,
            data=json.dumps(webhook_payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(request, timeout=5).read()
        self.send_response(202)
        self.end_headers()

    def log_message(self, *_args):
        return


def test_validate_alert_delivery_posts_watchdog_alert_and_confirms_webhook_delivery():
    FakeAlertmanagerHandler.received_alerts = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), FakeAlertmanagerHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--alertmanager-url",
                f"http://127.0.0.1:{port}",
                "--timeout-seconds",
                "5",
                "--json",
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
    finally:
        server.shutdown()
        thread.join(timeout=2)

    assert result.returncode == 0, result.stderr
    status = json.loads(result.stdout)
    assert status["delivered"] is True
    assert status["alertmanager_status"] == 202
    assert status["alert_name"] == "HomelabSecDeliveryValidation"
    assert FakeAlertmanagerHandler.received_alerts
    sent_alert = FakeAlertmanagerHandler.received_alerts[0][0]
    assert sent_alert["labels"]["alertname"] == "HomelabSecDeliveryValidation"
    assert sent_alert["labels"]["service"] == "homelabsec"
    assert sent_alert["annotations"]["webhook_url"] == status["webhook_url"]
    assert sent_alert["annotations"]["validation_token"] == status["validation_token"]


def test_validate_alert_delivery_fails_cleanly_when_alertmanager_is_unreachable():
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--alertmanager-url",
            "http://127.0.0.1:9",
            "--timeout-seconds",
            "1",
            "--json",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    status = json.loads(result.stdout)
    assert status["delivered"] is False
    assert "error" in status
