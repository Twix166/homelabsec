from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import psycopg
from fastapi import Request, Response

from brainlib.admin_console import ensure_admin_console_defaults
from brainlib.config import (
    AUTH_SESSION_DAYS,
    DEFAULT_ADMIN_DISPLAY_NAME,
    DEFAULT_ADMIN_PASSWORD,
    DEFAULT_ADMIN_USERNAME,
)
from brainlib.errors import forbidden, unauthorized


SESSION_COOKIE_NAME = "homelabsec_session"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _password_hash(password: str, *, salt: bytes | None = None, iterations: int = 600_000) -> str:
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "pbkdf2_sha256${iterations}${salt}${digest}".format(
        iterations=iterations,
        salt=base64.b64encode(salt).decode("ascii"),
        digest=base64.b64encode(digest).decode("ascii"),
    )


def verify_password(password: str, password_hash: str) -> bool:
    try:
        algorithm, raw_iterations, raw_salt, raw_digest = password_hash.split("$", 3)
    except ValueError:
        return False
    if algorithm != "pbkdf2_sha256":
        return False
    derived = _password_hash(
        password,
        salt=base64.b64decode(raw_salt.encode("ascii")),
        iterations=int(raw_iterations),
    )
    return hmac.compare_digest(derived, password_hash)


def hash_session_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def ensure_default_admin(conn: psycopg.Connection) -> None:
    ensure_admin_console_defaults(conn)
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM users")
        user_count = cur.fetchone()[0]
        if user_count == 0:
            cur.execute(
                """
                INSERT INTO users (username, password_hash, display_name, role, is_active)
                VALUES (%s, %s, %s, 'admin', TRUE)
                """,
                (
                    DEFAULT_ADMIN_USERNAME,
                    _password_hash(DEFAULT_ADMIN_PASSWORD),
                    DEFAULT_ADMIN_DISPLAY_NAME,
                ),
            )
            conn.commit()


def _serialize_user(row) -> dict[str, Any]:
    return {
        "user_id": str(row[0]),
        "username": row[1],
        "display_name": row[2],
        "email": row[3],
        "role": row[4],
        "is_active": bool(row[5]),
        "created_at": row[6].isoformat(),
        "updated_at": row[7].isoformat(),
        "last_login_at": row[8].isoformat() if row[8] else None,
    }


def current_user_from_request(conn: psycopg.Connection, request: Request) -> dict[str, Any] | None:
    ensure_default_admin(conn)
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return None

    token_hash = hash_session_token(token)
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT u.user_id,
                   u.username,
                   u.display_name,
                   u.email,
                   u.role,
                   u.is_active,
                   u.created_at,
                   u.updated_at,
                   u.last_login_at
            FROM user_sessions s
            JOIN users u ON u.user_id = s.user_id
            WHERE s.session_token_hash = %s
              AND s.expires_at > now()
              AND u.is_active = TRUE
            """,
            (token_hash,),
        )
        row = cur.fetchone()
        if row is None:
            return None
        cur.execute(
            """
            UPDATE user_sessions
            SET last_seen_at = now()
            WHERE session_token_hash = %s
            """,
            (token_hash,),
        )
        conn.commit()
    return _serialize_user(row)


def require_user(conn: psycopg.Connection, request: Request) -> dict[str, Any]:
    user = current_user_from_request(conn, request)
    if user is None:
        raise unauthorized("Authentication required")
    return user


def require_admin(conn: psycopg.Connection, request: Request) -> dict[str, Any]:
    user = require_user(conn, request)
    if user["role"] != "admin":
        raise forbidden("Admin access required")
    return user


def _set_session_cookie(response: Response, token: str) -> None:
    max_age = AUTH_SESSION_DAYS * 24 * 60 * 60
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        max_age=max_age,
        httponly=True,
        samesite="lax",
        secure=False,
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")


def login(conn: psycopg.Connection, response: Response, username: str, password: str) -> dict[str, Any]:
    ensure_default_admin(conn)
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT user_id,
                   username,
                   password_hash,
                   display_name,
                   email,
                   role,
                   is_active,
                   created_at,
                   updated_at,
                   last_login_at
            FROM users
            WHERE username = %s
            """,
            (username,),
        )
        row = cur.fetchone()

    if row is None or not bool(row[6]) or not verify_password(password, row[2]):
        raise unauthorized("Invalid username or password")

    token = secrets.token_urlsafe(32)
    token_hash = hash_session_token(token)
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO user_sessions (user_id, session_token_hash, expires_at)
            VALUES (%s, %s, %s)
            """,
            (
                row[0],
                token_hash,
                _utcnow() + timedelta(days=AUTH_SESSION_DAYS),
            ),
        )
        cur.execute(
            """
            UPDATE users
            SET last_login_at = now(),
                updated_at = now()
            WHERE user_id = %s
            """,
            (row[0],),
        )
        conn.commit()

    _set_session_cookie(response, token)
    return {"user": _serialize_user((row[0], row[1], row[3], row[4], row[5], row[6], row[7], row[8], _utcnow()))}


def logout(conn: psycopg.Connection, request: Request, response: Response) -> dict[str, Any]:
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if token:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM user_sessions WHERE session_token_hash = %s", (hash_session_token(token),))
            conn.commit()
    clear_session_cookie(response)
    return {"signed_out": True}


def auth_me(conn: psycopg.Connection, request: Request) -> dict[str, Any]:
    return {"user": require_user(conn, request)}


def update_profile(
    conn: psycopg.Connection,
    request: Request,
    *,
    display_name: str | None = None,
    email: str | None = None,
    current_password: str | None = None,
    new_password: str | None = None,
) -> dict[str, Any]:
    user = require_user(conn, request)
    assignments = []
    params: list[Any] = []

    if display_name is not None:
        assignments.append("display_name = %s")
        params.append(display_name.strip())
    if email is not None:
        assignments.append("email = %s")
        params.append(email.strip() or None)
    if new_password is not None:
        if not current_password:
            raise unauthorized("Current password is required to set a new password")
        with conn.cursor() as cur:
            cur.execute("SELECT password_hash FROM users WHERE user_id = %s", (user["user_id"],))
            stored_hash = cur.fetchone()[0]
        if not verify_password(current_password, stored_hash):
            raise unauthorized("Current password is incorrect")
        assignments.append("password_hash = %s")
        params.append(_password_hash(new_password))

    if not assignments:
        return {"user": user}

    assignments.append("updated_at = now()")
    params.append(user["user_id"])

    with conn.cursor() as cur:
        cur.execute(
            f"""
            UPDATE users
            SET {", ".join(assignments)}
            WHERE user_id = %s
            RETURNING user_id, username, display_name, email, role, is_active, created_at, updated_at, last_login_at
            """,
            params,
        )
        updated = cur.fetchone()
        conn.commit()

    return {"user": _serialize_user(updated)}


def list_users(conn: psycopg.Connection) -> dict[str, Any]:
    ensure_default_admin(conn)
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT user_id, username, display_name, email, role, is_active, created_at, updated_at, last_login_at
            FROM users
            ORDER BY username ASC
            """
        )
        rows = cur.fetchall()
    return {"users": [_serialize_user(row) for row in rows]}


def create_user(
    conn: psycopg.Connection,
    *,
    username: str,
    password: str,
    display_name: str,
    email: str | None,
    role: str,
) -> dict[str, Any]:
    ensure_default_admin(conn)
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO users (username, password_hash, display_name, email, role, is_active)
            VALUES (%s, %s, %s, %s, %s, TRUE)
            RETURNING user_id, username, display_name, email, role, is_active, created_at, updated_at, last_login_at
            """,
            (username.strip(), _password_hash(password), display_name.strip(), email.strip() if email else None, role),
        )
        row = cur.fetchone()
        conn.commit()
    return _serialize_user(row)


def update_user(
    conn: psycopg.Connection,
    user_id: str,
    *,
    display_name: str | None = None,
    email: str | None = None,
    role: str | None = None,
    is_active: bool | None = None,
    password: str | None = None,
) -> dict[str, Any]:
    ensure_default_admin(conn)
    assignments = []
    params: list[Any] = []

    if display_name is not None:
        assignments.append("display_name = %s")
        params.append(display_name.strip())
    if email is not None:
        assignments.append("email = %s")
        params.append(email.strip() or None)
    if role is not None:
        assignments.append("role = %s")
        params.append(role)
    if is_active is not None:
        assignments.append("is_active = %s")
        params.append(is_active)
    if password is not None:
        assignments.append("password_hash = %s")
        params.append(_password_hash(password))

    assignments.append("updated_at = now()")
    params.append(user_id)

    with conn.cursor() as cur:
        cur.execute(
            f"""
            UPDATE users
            SET {", ".join(assignments)}
            WHERE user_id = %s
            RETURNING user_id, username, display_name, email, role, is_active, created_at, updated_at, last_login_at
            """,
            params,
        )
        row = cur.fetchone()
        conn.commit()
    if row is None:
        raise KeyError(user_id)
    return _serialize_user(row)
