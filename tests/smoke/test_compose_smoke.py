import json
import os
import socket
import subprocess
import time
import uuid
import urllib.request
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SMOKE_COMPOSE = REPO_ROOT / "compose" / "compose.smoke.yaml"


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _run_compose(project_name, env, *args):
    cmd = [
        "docker",
        "compose",
        "-p",
        project_name,
        "-f",
        str(SMOKE_COMPOSE),
        *args,
    ]
    return subprocess.run(cmd, cwd=REPO_ROOT, env=env, check=True, capture_output=True, text=True)


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


def _wait_for_services_healthy(project_name: str, env, timeout_seconds: int = 180):
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        result = _run_compose(project_name, env, "ps", "-a", "--format", "json")
        raw_output = result.stdout.strip()
        if raw_output.startswith("["):
            services = json.loads(raw_output)
        else:
            services = [json.loads(line) for line in raw_output.splitlines() if line.strip()]

        def service_ready(service):
            if service.get("Service") == "migrate":
                return service.get("State") == "exited" and service.get("ExitCode") == 0
            return service.get("Health") == "healthy"

        if services and all(service_ready(service) for service in services):
            return services

        time.sleep(3)

    raise AssertionError("Timed out waiting for all compose services to report healthy")


def test_compose_stack_reaches_healthy_state():
    project_name = f"homelabsec-smoke-{uuid.uuid4().hex[:8]}"
    api_port = _find_free_port()
    frontend_port = _find_free_port()
    postgres_port = _find_free_port()
    compose_env = {
        **os.environ,
        "SMOKE_API_PORT": str(api_port),
        "SMOKE_FRONTEND_PORT": str(frontend_port),
        "SMOKE_POSTGRES_PORT": str(postgres_port),
        "SCHEDULER_API_BASE": f"http://127.0.0.1:{api_port}",
    }

    try:
        _run_compose(project_name, compose_env, "up", "-d", "--build")
        services = _wait_for_services_healthy(project_name, compose_env)

        _wait_for_http(f"http://127.0.0.1:{api_port}/health")
        _wait_for_http(f"http://127.0.0.1:{frontend_port}/")

        service_names = {service["Service"] for service in services}
        assert {"postgres", "migrate", "brain", "scheduler", "frontend"}.issubset(service_names)
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
            env=compose_env,
            check=False,
            capture_output=True,
            text=True,
        )
