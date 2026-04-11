import importlib.util
import os
import socket
import subprocess
import sys
import types
import uuid
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
APP_PATH = REPO_ROOT / "brain" / "app.py"
MIGRATE_PATH = REPO_ROOT / "brain" / "migrate.py"
BRAIN_DIR = APP_PATH.parent
TEST_COMPOSE_PATH = REPO_ROOT / "compose" / "compose.test.yaml"


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        return int(sock.getsockname()[1])


def _reset_modules(module_names):
    for name in module_names:
        sys.modules.pop(name, None)


def _reset_project_modules(extra_names=None):
    extra_names = extra_names or []
    for name in list(sys.modules):
        if name == "app" or name.startswith("brainlib") or name.startswith("collectors"):
            sys.modules.pop(name, None)
    _reset_modules(extra_names)


def _install_stub_modules():
    _reset_project_modules(["psycopg", "requests", "fastapi", "pydantic"])

    psycopg_stub = types.ModuleType("psycopg")
    psycopg_stub.Connection = object
    psycopg_stub.connect = lambda *args, **kwargs: None

    requests_stub = types.ModuleType("requests")

    fastapi_stub = types.ModuleType("fastapi")

    class FastAPI:
        def __init__(self, *args, **kwargs):
            self.args = args
            self.kwargs = kwargs

        def middleware(self, *args, **kwargs):
            def decorator(func):
                return func

            return decorator

        def on_event(self, *args, **kwargs):
            def decorator(func):
                return func

            return decorator

        def get(self, *args, **kwargs):
            def decorator(func):
                return func

            return decorator

        def post(self, *args, **kwargs):
            def decorator(func):
                return func

            return decorator

        def patch(self, *args, **kwargs):
            def decorator(func):
                return func

            return decorator

        def put(self, *args, **kwargs):
            def decorator(func):
                return func

            return decorator

    class HTTPException(Exception):
        def __init__(self, status_code: int, detail: str):
            super().__init__(detail)
            self.status_code = status_code
            self.detail = detail

    class Request:
        def __init__(self, *args, **kwargs):
            self.args = args
            self.kwargs = kwargs

    class Response:
        def __init__(self, content=None, media_type=None, status_code=200):
            self.content = content
            self.media_type = media_type
            self.status_code = status_code

    fastapi_stub.FastAPI = FastAPI
    fastapi_stub.HTTPException = HTTPException
    fastapi_stub.Request = Request
    fastapi_stub.Response = Response

    pydantic_stub = types.ModuleType("pydantic")

    class BaseModel:
        def __init__(self, **kwargs):
            for key, value in kwargs.items():
                setattr(self, key, value)

    pydantic_stub.BaseModel = BaseModel

    sys.modules.setdefault("psycopg", psycopg_stub)
    sys.modules.setdefault("requests", requests_stub)
    sys.modules.setdefault("fastapi", fastapi_stub)
    sys.modules.setdefault("pydantic", pydantic_stub)


def _load_brain_module(module_name: str):
    _reset_project_modules([module_name])
    if str(BRAIN_DIR) not in sys.path:
        sys.path.insert(0, str(BRAIN_DIR))
    os.environ.setdefault("DATABASE_URL", "postgresql://test:test@localhost:5432/test")
    os.environ.setdefault("OLLAMA_URL", "http://ollama.test")
    os.environ.setdefault("OLLAMA_MODEL", "homelabsec-classifier")

    spec = importlib.util.spec_from_file_location(module_name, APP_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def brain_module():
    _install_stub_modules()
    return _load_brain_module("brain_app_unit_under_test")


@pytest.fixture(scope="session")
def integration_db_url():
    port = os.environ.get("TEST_DB_PORT")
    if not port:
        port = str(_find_free_port())
        os.environ["TEST_DB_PORT"] = port
    return f"postgresql://homelabsec:change-me@127.0.0.1:{port}/homelabsec"


@pytest.fixture(scope="session")
def postgres_test_env():
    project_name = f"homelabsec-test-{uuid.uuid4().hex[:8]}"
    test_db_port = os.environ.get("TEST_DB_PORT")
    if not test_db_port:
        test_db_port = str(_find_free_port())
        os.environ["TEST_DB_PORT"] = test_db_port
    return {
        "project_name": project_name,
        "env": {**os.environ, "TEST_DB_PORT": test_db_port},
        "compose_path": str(TEST_COMPOSE_PATH),
        "down_cmd": [
            "docker",
            "compose",
            "-p",
            project_name,
            "-f",
            str(TEST_COMPOSE_PATH),
            "down",
            "-v",
            "--remove-orphans",
        ],
        "up_cmd": [
            "docker",
            "compose",
            "-p",
            project_name,
            "-f",
            str(TEST_COMPOSE_PATH),
            "up",
            "-d",
            "postgres",
        ],
    }


@pytest.fixture(scope="session")
def postgres_test_stack(postgres_test_env):
    down_cmd = postgres_test_env["down_cmd"]
    up_cmd = postgres_test_env["up_cmd"]
    env = postgres_test_env["env"]

    subprocess.run(down_cmd, cwd=REPO_ROOT, check=False, capture_output=True, text=True, env=env)
    subprocess.run(up_cmd, cwd=REPO_ROOT, check=True, capture_output=True, text=True, env=env)

    try:
        yield
    finally:
        subprocess.run(down_cmd, cwd=REPO_ROOT, check=False, capture_output=True, text=True, env=env)


@pytest.fixture(scope="session")
def integration_brain_module(postgres_test_stack, integration_db_url):
    import psycopg

    _reset_modules(["psycopg", "fastapi", "pydantic"])
    os.environ["DATABASE_URL"] = integration_db_url
    os.environ["OLLAMA_URL"] = "http://ollama.test"
    os.environ["OLLAMA_MODEL"] = "homelabsec-classifier"

    for _ in range(30):
        try:
            with psycopg.connect(integration_db_url):
                break
        except psycopg.OperationalError:
            import time

            time.sleep(1)
    else:
        raise RuntimeError("Timed out waiting for test Postgres to become ready")

    subprocess.run(
        ["python3", str(MIGRATE_PATH)],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "DATABASE_URL": integration_db_url,
            "OLLAMA_URL": "http://ollama.test",
            "OLLAMA_MODEL": "homelabsec-classifier",
        },
    )

    return _load_brain_module("brain_app_integration_under_test")
