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
SMOKE_WORKFLOW_COMPOSE = REPO_ROOT / "compose" / "compose.smoke.workflow.yaml"
FIXTURE_PATH = REPO_ROOT / "tests" / "fixtures" / "nmap_single_host.xml"


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


def _request_json(
    method: str,
    url: str,
    payload: dict | None = None,
    headers: dict[str, str] | None = None,
    timeout_seconds: int = 10,
    insecure: bool = False,
):
    encoded_payload = None
    request_headers = {"Content-Type": "application/json"}
    if headers:
        request_headers.update(headers)
    if payload is not None:
        encoded_payload = json.dumps(payload).encode()
    request = urllib.request.Request(url, data=encoded_payload, headers=request_headers, method=method)
    context = ssl._create_unverified_context() if insecure else None
    with urllib.request.urlopen(request, timeout=timeout_seconds, context=context) as response:
        return response.status, json.loads(response.read().decode())


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


def test_api_workflow_smoke():
    project_name = f"homelabsec-smoke-api-{uuid.uuid4().hex[:8]}"
    api_port = _find_free_port()
    frontend_port = _find_free_port()
    postgres_port = _find_free_port()
    compose_files = [SMOKE_COMPOSE, SMOKE_WORKFLOW_COMPOSE]
    smoke_fixture_dir = REPO_ROOT / "discovery" / "raw"
    smoke_fixture_dir.mkdir(parents=True, exist_ok=True)
    smoke_fixture_path = smoke_fixture_dir / f"smoke-{uuid.uuid4().hex}.xml"
    smoke_fixture_path.write_text(FIXTURE_PATH.read_text())
    compose_env = {
        **os.environ,
        "SMOKE_API_PORT": str(api_port),
        "SMOKE_FRONTEND_PORT": str(frontend_port),
        "SMOKE_POSTGRES_PORT": str(postgres_port),
        "SCHEDULER_API_BASE": f"http://127.0.0.1:{api_port}",
    }

    try:
        _run_compose(project_name, compose_env, "up", "-d", "--build", compose_files=compose_files)
        services = _wait_for_services_healthy(project_name, compose_env, compose_files=compose_files)

        _wait_for_http(f"http://127.0.0.1:{api_port}/health")
        _wait_for_http(f"http://127.0.0.1:{frontend_port}/")

        ingest_status, ingest_payload = _request_json(
            "POST",
            f"http://127.0.0.1:{api_port}/ingest/nmap_xml",
            {"xml_path": f"/data/discovery/raw/{smoke_fixture_path.name}"},
        )
        assert ingest_status == 200
        assert ingest_payload["hosts_parsed"] == 1
        assert ingest_payload["observations_inserted"] == 1

        _, assets_payload = _request_json("GET", f"http://127.0.0.1:{api_port}/assets")
        assets = assets_payload["assets"]
        assert len(assets) == 1
        asset_id = assets[0]["asset_id"]

        classify_status, classify_payload = _request_json(
            "POST",
            f"http://127.0.0.1:{api_port}/classify/{asset_id}",
        )
        assert classify_status == 200
        assert classify_payload["classification"]["role"] == "web_server"

        detect_status, detect_payload = _request_json("GET", f"http://127.0.0.1:{api_port}/detect_changes")
        assert detect_status == 200
        assert detect_payload["assets_with_changes"] >= 1

        daily_status, daily_payload = _request_json("GET", f"http://127.0.0.1:{api_port}/report/daily")
        assert daily_status == 200
        assert daily_payload["recent_asset_count"] == 1

        summary_status, summary_payload = _request_json("GET", f"http://127.0.0.1:{api_port}/report/summary")
        assert summary_status == 200
        assert summary_payload["assets"] == 1
        assert summary_payload["network_observations"] >= 1

        service_names = {service["Service"] for service in services}
        assert {"postgres", "migrate", "brain", "scheduler", "frontend", "fake-ollama"}.issubset(service_names)
    finally:
        smoke_fixture_path.unlink(missing_ok=True)
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
