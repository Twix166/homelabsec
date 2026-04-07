import json
import os
import socket
import ssl
import subprocess
import time
import uuid
import urllib.request
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SMOKE_COMPOSE = REPO_ROOT / "compose" / "compose.smoke.yaml"
SMOKE_MONITORING_COMPOSE = REPO_ROOT / "compose" / "compose.smoke.monitoring.yaml"
SMOKE_EXPOSED_COMPOSE = REPO_ROOT / "compose" / "compose.smoke.exposed.yaml"


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _run_compose(project_name, env, *args, compose_files=None):
    compose_files = compose_files or [SMOKE_COMPOSE]
    cmd = [
        "docker",
        "compose",
        "-p",
        project_name,
    ]
    for compose_file in compose_files:
        cmd.extend(["-f", str(compose_file)])
    cmd.extend(args)
    return subprocess.run(cmd, cwd=REPO_ROOT, env=env, check=True, capture_output=True, text=True)


def _wait_for_http(url: str, timeout_seconds: int = 120, headers: dict[str, str] | None = None, insecure: bool = False):
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        try:
            request = urllib.request.Request(url, headers=headers or {})
            context = ssl._create_unverified_context() if insecure else None
            with urllib.request.urlopen(request, timeout=5, context=context) as response:
                if response.status == 200:
                    return response.read()
        except Exception:
            time.sleep(2)
    raise AssertionError(f"Timed out waiting for HTTP 200 from {url}")


def _wait_for_services_healthy(project_name: str, env, timeout_seconds: int = 180, compose_files=None):
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        result = _run_compose(project_name, env, "ps", "-a", "--format", "json", compose_files=compose_files)
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


def test_monitoring_and_secure_edge_overlays_reach_healthy_state():
    project_name = f"homelabsec-smoke-obs-{uuid.uuid4().hex[:8]}"
    api_port = _find_free_port()
    postgres_port = _find_free_port()
    prometheus_port = _find_free_port()
    alertmanager_port = _find_free_port()
    grafana_port = _find_free_port()
    edge_http_port = _find_free_port()
    edge_https_port = _find_free_port()
    scheduler_metrics_port = 19100
    compose_files = [SMOKE_COMPOSE, SMOKE_MONITORING_COMPOSE, SMOKE_EXPOSED_COMPOSE]
    compose_env = {
        **os.environ,
        "SMOKE_API_PORT": str(api_port),
        "SMOKE_POSTGRES_PORT": str(postgres_port),
        "SMOKE_PROMETHEUS_PORT": str(prometheus_port),
        "SMOKE_ALERTMANAGER_PORT": str(alertmanager_port),
        "SMOKE_GRAFANA_PORT": str(grafana_port),
        "SMOKE_EDGE_HTTP_PORT": str(edge_http_port),
        "SMOKE_EDGE_HTTPS_PORT": str(edge_https_port),
        "SMOKE_SCHEDULER_METRICS_PORT": str(scheduler_metrics_port),
        "SCHEDULER_API_BASE": f"http://127.0.0.1:{api_port}",
        "EDGE_SERVER_NAME": "localhost",
        "EDGE_TLS_MODE": "self_signed",
        "ALERTMANAGER_DEFAULT_RECEIVER": "null",
    }

    try:
        _run_compose(project_name, compose_env, "up", "-d", "--build", compose_files=compose_files)
        services = _wait_for_services_healthy(project_name, compose_env, compose_files=compose_files)

        prometheus_body = _wait_for_http(f"http://127.0.0.1:{prometheus_port}/api/v1/targets")
        alertmanager_body = _wait_for_http(f"http://127.0.0.1:{alertmanager_port}/api/v2/status")
        grafana_datasources = _wait_for_http(
            f"http://127.0.0.1:{grafana_port}/api/datasources",
            headers={"Authorization": "Basic YWRtaW46Y2hhbmdlLW1lLW5vdw=="},
        )
        dashboard_body = _wait_for_http(
            f"http://127.0.0.1:{grafana_port}/api/dashboards/uid/homelabsec-overview",
            headers={"Authorization": "Basic YWRtaW46Y2hhbmdlLW1lLW5vdw=="},
        )
        edge_health = _wait_for_http(f"https://127.0.0.1:{edge_https_port}/healthz", insecure=True)

        prometheus_data = json.loads(prometheus_body)
        grafana_datasource_data = json.loads(grafana_datasources)
        dashboard_data = json.loads(dashboard_body)

        active_targets = prometheus_data["data"]["activeTargets"]
        target_jobs = {target["labels"]["job"] for target in active_targets}
        service_names = {service["Service"] for service in services}

        assert {"prometheus", "grafana", "alertmanager", "edge"}.issubset(service_names)
        assert {"prometheus", "homelabsec-brain", "homelabsec-scheduler"}.issubset(target_jobs)
        assert any(ds["name"] == "Prometheus" for ds in grafana_datasource_data)
        assert dashboard_data["dashboard"]["uid"] == "homelabsec-overview"
        assert json.loads(alertmanager_body)["config"]["original"]
        assert edge_health == b"ok\n"
    finally:
        down_cmd = [
            "docker",
            "compose",
            "-p",
            project_name,
        ]
        for compose_file in compose_files:
            down_cmd.extend(["-f", str(compose_file)])
        down_cmd.extend(["down", "-v", "--remove-orphans"])
        subprocess.run(
            down_cmd,
            cwd=REPO_ROOT,
            env=compose_env,
            check=False,
            capture_output=True,
            text=True,
        )
