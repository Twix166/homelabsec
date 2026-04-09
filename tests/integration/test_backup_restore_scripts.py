import os
import subprocess
from pathlib import Path

import psycopg


REPO_ROOT = Path(__file__).resolve().parents[2]
BACKUP_SCRIPT = REPO_ROOT / "scripts" / "backup_db.sh"
RESTORE_SCRIPT = REPO_ROOT / "scripts" / "restore_db.sh"


def test_backup_and_restore_scripts_round_trip(postgres_test_stack, postgres_test_env, integration_db_url, tmp_path):
    with psycopg.connect(integration_db_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO assets (preferred_name, role, role_confidence)
                VALUES ('backup-test-host', 'server', 0.95)
                """
            )
        conn.commit()

    backup_path = tmp_path / "homelabsec-test-backup.sql"
    backup_env = {
        "COMPOSE_FILE": postgres_test_env["compose_path"],
        "COMPOSE_PROJECT_NAME": postgres_test_env["project_name"],
        "POSTGRES_DB": "homelabsec",
        "POSTGRES_USER": "homelabsec",
    }

    subprocess.run(
        ["bash", str(BACKUP_SCRIPT), str(backup_path)],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, **backup_env},
    )

    with psycopg.connect(integration_db_url) as conn:
        with conn.cursor() as cur:
            cur.execute("TRUNCATE changes, fingerprints, network_observations, asset_identifiers, findings, assets, scan_runs CASCADE")
        conn.commit()

    subprocess.run(
        ["bash", str(RESTORE_SCRIPT), str(backup_path)],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, **backup_env},
    )

    with psycopg.connect(integration_db_url) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT preferred_name, role FROM assets WHERE preferred_name = 'backup-test-host'")
            restored = cur.fetchone()

    assert restored == ("backup-test-host", "server")
