from __future__ import annotations

from pathlib import Path

import psycopg

from brainlib.config import CONFIG
from brainlib.logging_utils import configure_logging, log_event

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"
logger = configure_logging("homelabsec.migrate")


def ensure_migrations_table(conn: psycopg.Connection) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version TEXT PRIMARY KEY,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
            """
        )
    conn.commit()


def applied_versions(conn: psycopg.Connection) -> set[str]:
    with conn.cursor() as cur:
        cur.execute("SELECT version FROM schema_migrations ORDER BY version")
        return {row[0] for row in cur.fetchall()}


def migration_files() -> list[Path]:
    return sorted(MIGRATIONS_DIR.glob("*.sql"))


def apply_migration(conn: psycopg.Connection, path: Path) -> None:
    version = path.stem
    sql = path.read_text(encoding="utf-8")

    with conn.cursor() as cur:
        cur.execute(sql)
        cur.execute(
            "INSERT INTO schema_migrations (version) VALUES (%s) ON CONFLICT (version) DO NOTHING",
            (version,),
        )
    conn.commit()
    log_event(logger, "info", "migration_applied", "Applied migration", version=version)


def main() -> None:
    with psycopg.connect(CONFIG.database_url) as conn:
        ensure_migrations_table(conn)
        existing_versions = applied_versions(conn)

        for path in migration_files():
            if path.stem in existing_versions:
                log_event(logger, "info", "migration_skipped", "Skipping migration", version=path.stem)
                continue
            apply_migration(conn, path)


if __name__ == "__main__":
    main()
