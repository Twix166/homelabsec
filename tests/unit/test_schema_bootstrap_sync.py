import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
RENDER_SCRIPT = REPO_ROOT / "brain" / "render_init_sql.py"


def test_init_sql_matches_versioned_migrations():
    result = subprocess.run(
        ["python3", str(RENDER_SCRIPT), "--check"],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
