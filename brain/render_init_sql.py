from __future__ import annotations

import argparse
import sys
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent
INIT_SQL_PATH = ROOT_DIR / "init.sql"
MIGRATIONS_DIR = ROOT_DIR / "migrations"
HEADER = "-- Generated from brain/migrations via python3 brain/render_init_sql.py --write\n\n"


def migration_files() -> list[Path]:
    return sorted(MIGRATIONS_DIR.glob("*.sql"))


def render_init_sql() -> str:
    rendered_parts = [HEADER.rstrip()]
    for path in migration_files():
        rendered_parts.append(path.read_text(encoding="utf-8").strip())
    return "\n\n".join(rendered_parts).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Render init.sql from versioned migrations.")
    parser.add_argument("--write", action="store_true", help="Write the rendered schema into init.sql")
    parser.add_argument("--check", action="store_true", help="Fail if init.sql differs from rendered migrations")
    args = parser.parse_args()

    rendered = render_init_sql()

    if args.write:
        INIT_SQL_PATH.write_text(rendered, encoding="utf-8")
        return 0

    if args.check:
        current = INIT_SQL_PATH.read_text(encoding="utf-8")
        if current != rendered:
            print("init.sql is out of sync with brain/migrations. Run python3 brain/render_init_sql.py --write", file=sys.stderr)
            return 1
        return 0

    sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
