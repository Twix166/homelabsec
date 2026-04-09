import os
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def _run_compose_config(extra_env: dict[str, str]):
    env = {**os.environ, **extra_env}
    return subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            str(REPO_ROOT / "compose" / "compose.yaml"),
            "-f",
            str(REPO_ROOT / "compose" / "compose.exposed.yaml"),
            "-f",
            str(REPO_ROOT / "compose" / "compose.oidc.yaml"),
            "config",
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
    )


def test_oidc_overlay_config_renders_with_required_values():
    result = _run_compose_config(
        {
            "EDGE_OIDC_ISSUER_URL": "https://idp.example.com/application/o/homelabsec/",
            "EDGE_OIDC_CLIENT_ID": "homelabsec",
            "EDGE_OIDC_CLIENT_SECRET": "secret-value",
            "EDGE_OIDC_COOKIE_SECRET": "0123456789abcdef",
            "EDGE_OIDC_REDIRECT_URL": "https://localhost:8443/oauth2/callback",
        }
    )

    assert result.returncode == 0, result.stderr
    assert "oauth2-proxy" in result.stdout
    assert "EDGE_AUTH_MODE: oauth2_proxy" in result.stdout


def test_oidc_overlay_config_fails_clearly_when_required_value_is_missing():
    result = _run_compose_config(
        {
            "EDGE_OIDC_CLIENT_ID": "homelabsec",
            "EDGE_OIDC_CLIENT_SECRET": "secret-value",
            "EDGE_OIDC_COOKIE_SECRET": "0123456789abcdef",
            "EDGE_OIDC_REDIRECT_URL": "https://localhost:8443/oauth2/callback",
        }
    )

    assert result.returncode != 0
    combined_output = f"{result.stdout}\n{result.stderr}"
    assert "EDGE_OIDC_ISSUER_URL is required" in combined_output
