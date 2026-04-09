import psycopg

from brainlib.config import DATABASE_URL


def db():
    return psycopg.connect(DATABASE_URL)


def asset_exists(conn: psycopg.Connection, asset_id: str) -> bool:
    with conn.cursor() as cur:
        cur.execute("SELECT 1 FROM assets WHERE asset_id = %s", (asset_id,))
        return cur.fetchone() is not None
