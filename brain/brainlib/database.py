import psycopg

from brainlib.config import DATABASE_URL


def db():
    return psycopg.connect(DATABASE_URL)
