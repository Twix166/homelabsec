import json
import subprocess
import time
import uuid
import urllib.request
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SMOKE_COMPOSE = REPO_ROOT / "compose" / "compose.smoke.yaml"


def _run_compose(project_name, *args):
    cmd = [
        "docker",
        "compose",
        "-p",
        project_name,
        "-f",
        str(SMOKE_COMPOSE),
        *args,
    ]
    return subprocess.run(cmd, cwd=REPO_ROOT, check=True, capture_output=True, text=True)


def _wait_for_http(url: str, timeout_seconds: int = 120):
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                if response.status == 200:
                    return
        except Exception:
            time.sleep(2)
    raise AssertionError(f"Timed out waiting for HTTP 200 from {url}")


def _wait_for_services_healthy(project_name: str, timeout_seconds: int = 180):
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        result = _run_compose(project_name, "ps", "--format", "json")
        raw_output = result.stdout.strip()
        if raw_output.startswith("["):
            services = json.loads(raw_output)
        else:
            services = [json.loads(line) for line in raw_output.splitlines() if line.strip()]

        if services and all(service.get("Health") == "healthy" for service in services):
            return services

        time.sleep(3)

    raise AssertionError("Timed out waiting for all compose services to report healthy")


def test_compose_stack_reaches_healthy_state():
    project_name = f"homelabsec-smoke-{uuid.uuid4().hex[:8]}"

    try:
        _run_compose(project_name, "up", "-d", "--build")
        services = _wait_for_services_healthy(project_name)

        _wait_for_http("http://127.0.0.1:18088/health")
        _wait_for_http("http://127.0.0.1:18080/")

        service_names = {service["Service"] for service in services}
        assert {"postgres", "brain", "scheduler", "frontend"}.issubset(service_names)
    finally:
        subprocess.run(
            [
                "docker",
                "compose",
                "-p",
                project_name,
                "-f",
                str(SMOKE_COMPOSE),
                "down",
                "-v",
                "--remove-orphans",
            ],
            cwd=REPO_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
