"""SQLite-backed authentication, authorization and CSRF helpers for ENCCA."""

from __future__ import annotations

import hmac
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from urllib.parse import urljoin, urlparse

from flask import abort, current_app, flash, g, redirect, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

LOCKOUT_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=15)
PASSWORD_PATTERN = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{12,}$")
# Used for a comparable password-hash operation when the account does not exist.
DUMMY_PASSWORD_HASH = generate_password_hash("not-a-real-password")


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_db() -> sqlite3.Connection:
    if "auth_db" not in g:
        path = Path(current_app.config["AUTH_DATABASE"])
        path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(path)
        connection.row_factory = sqlite3.Row
        g.auth_db = connection
    return g.auth_db


def close_db(_error=None):
    connection = g.pop("auth_db", None)
    if connection is not None:
        connection.close()


def initialize_database() -> None:
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL COLLATE NOCASE UNIQUE,
            email TEXT NOT NULL COLLATE NOCASE UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('admin', 'analyst')),
            is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
            failed_login_attempts INTEGER NOT NULL DEFAULT 0 CHECK (failed_login_attempts >= 0),
            locked_until TEXT,
            last_login_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_users_role_active ON users(role, is_active);
        CREATE INDEX IF NOT EXISTS idx_users_locked_until ON users(locked_until);
        """
    )
    db.commit()


def password_errors(password: str) -> list[str]:
    if not PASSWORD_PATTERN.match(password or ""):
        return [
            "Password must be at least 12 characters and include uppercase, lowercase, a number and a special character."
        ]
    return []


def normalize_username(value: str) -> str:
    return (value or "").strip()


def normalize_email(value: str) -> str:
    return (value or "").strip().lower()


def valid_identity(username: str, email: str) -> list[str]:
    errors = []
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,64}", username or ""):
        errors.append("Username must contain 3-64 letters, numbers, dots, underscores or hyphens.")
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email or "") or len(email) > 254:
        errors.append("Enter a valid email address.")
    return errors


def get_user(user_id: int):
    return get_db().execute(
        "SELECT id, username, email, password_hash, role, is_active, failed_login_attempts, "
        "locked_until, last_login_at, created_at, updated_at FROM users WHERE id = ?", (user_id,)
    ).fetchone()


def list_users():
    return get_db().execute(
        "SELECT id, username, email, role, is_active, failed_login_attempts, locked_until, "
        "last_login_at, created_at, updated_at FROM users ORDER BY username COLLATE NOCASE"
    ).fetchall()


def create_user(username: str, email: str, password: str, role: str = "analyst") -> tuple[bool, str]:
    username, email = normalize_username(username), normalize_email(email)
    errors = valid_identity(username, email) + password_errors(password)
    if role not in {"admin", "analyst"}:
        errors.append("Select a valid role.")
    if errors:
        return False, " ".join(errors)
    now = utcnow()
    try:
        get_db().execute(
            "INSERT INTO users (username, email, password_hash, role, is_active, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, 1, ?, ?)",
            (username, email, generate_password_hash(password), role, now, now),
        )
        get_db().commit()
    except sqlite3.IntegrityError:
        return False, "Username or email is already in use."
    return True, "User created."


def active_admin_count(exclude_user_id: int | None = None) -> int:
    sql = "SELECT COUNT(*) FROM users WHERE role = 'admin' AND is_active = 1"
    parameters: tuple = ()
    if exclude_user_id is not None:
        sql += " AND id != ?"
        parameters = (exclude_user_id,)
    return int(get_db().execute(sql, parameters).fetchone()[0])


def update_user(user_id: int, email: str, role: str, is_active: bool, actor_id: int) -> tuple[bool, str]:
    user = get_user(user_id)
    if user is None:
        return False, "User was not found."
    email = normalize_email(email)
    errors = valid_identity(user["username"], email)
    if role not in {"admin", "analyst"}:
        errors.append("Select a valid role.")
    if errors:
        return False, " ".join(errors)
    removes_last_admin = user["role"] == "admin" and user["is_active"] and (
        role != "admin" or not is_active
    ) and active_admin_count(exclude_user_id=user_id) == 0
    if removes_last_admin:
        return False, "At least one active administrator must remain."
    if user_id == actor_id and (role != "admin" or not is_active):
        return False, "You cannot remove your own administrator access or deactivate your account."
    try:
        get_db().execute(
            "UPDATE users SET email = ?, role = ?, is_active = ?, updated_at = ? WHERE id = ?",
            (email, role, int(is_active), utcnow(), user_id),
        )
        get_db().commit()
    except sqlite3.IntegrityError:
        return False, "Username or email is already in use."
    return True, "User updated."


def set_user_status(user_id: int, is_active: bool, actor_id: int) -> tuple[bool, str]:
    user = get_user(user_id)
    if user is None:
        return False, "User was not found."
    if user_id == actor_id and not is_active:
        return False, "You cannot deactivate your own account."
    if user["role"] == "admin" and user["is_active"] and not is_active and active_admin_count(exclude_user_id=user_id) == 0:
        return False, "At least one active administrator must remain."
    get_db().execute(
        "UPDATE users SET is_active = ?, updated_at = ? WHERE id = ?",
        (int(is_active), utcnow(), user_id),
    )
    get_db().commit()
    return True, "User status updated."


def reset_password(user_id: int, password: str) -> tuple[bool, str]:
    errors = password_errors(password)
    if errors:
        return False, " ".join(errors)
    if get_user(user_id) is None:
        return False, "User was not found."
    get_db().execute(
        "UPDATE users SET password_hash = ?, failed_login_attempts = 0, locked_until = NULL, updated_at = ? WHERE id = ?",
        (generate_password_hash(password), utcnow(), user_id),
    )
    get_db().commit()
    return True, "Password reset successfully."


def bootstrap_admin_from_environment() -> bool:
    db = get_db()
    if db.execute("SELECT 1 FROM users WHERE role = 'admin' LIMIT 1").fetchone():
        return False
    import os
    username = os.environ.get("ENCCA_ADMIN_USERNAME", "")
    email = os.environ.get("ENCCA_ADMIN_EMAIL", "")
    password = os.environ.get("ENCCA_ADMIN_PASSWORD", "")
    if not all((username, email, password)):
        return False
    created, message = create_user(username, email, password, role="admin")
    if not created:
        current_app.logger.warning("Initial administrator bootstrap was rejected: %s", message)
    return created


def authenticate(identity: str, password: str):
    identity = (identity or "").strip()
    user = get_db().execute(
        "SELECT id, username, email, password_hash, role, is_active, failed_login_attempts, locked_until "
        "FROM users WHERE username = ? COLLATE NOCASE OR email = ? COLLATE NOCASE LIMIT 1",
        (identity, identity),
    ).fetchone()
    if user is None:
        check_password_hash(DUMMY_PASSWORD_HASH, password or "")
        return None
    now = datetime.now(timezone.utc)
    locked_until = None
    if user["locked_until"]:
        try:
            locked_until = datetime.fromisoformat(user["locked_until"])
        except ValueError:
            locked_until = None
    if not user["is_active"] or (locked_until and locked_until > now):
        check_password_hash(user["password_hash"], password or "")
        return None
    if not check_password_hash(user["password_hash"], password or ""):
        attempts = user["failed_login_attempts"] + 1
        new_lock = (now + LOCKOUT_DURATION).isoformat(timespec="seconds") if attempts >= LOCKOUT_ATTEMPTS else None
        get_db().execute(
            "UPDATE users SET failed_login_attempts = ?, locked_until = ?, updated_at = ? WHERE id = ?",
            (0 if new_lock else attempts, new_lock, utcnow(), user["id"]),
        )
        get_db().commit()
        return None
    get_db().execute(
        "UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login_at = ?, updated_at = ? WHERE id = ?",
        (utcnow(), utcnow(), user["id"]),
    )
    get_db().commit()
    return user


def get_current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    user = get_user(user_id)
    if user is None or not user["is_active"]:
        session.clear()
        return None
    return user


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = get_current_user()
        if user is None:
            flash("Please sign in to access ENCCA.")
            return redirect(url_for("login", next=request.full_path if request.query_string else request.path))
        g.current_user = user
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if g.current_user["role"] != "admin":
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def validate_csrf() -> bool:
    submitted = request.form.get("csrf_token", "")
    stored = session.get("csrf_token", "")
    return bool(submitted and stored and hmac.compare_digest(submitted, stored))


def is_safe_url(target: str | None) -> bool:
    if not target:
        return False
    host_url = urlparse(request.host_url)
    target_url = urlparse(urljoin(request.host_url, target))
    return target_url.scheme in {"http", "https"} and target_url.netloc == host_url.netloc and target.startswith("/") and not target.startswith("//")


def init_auth(app, database_path: Path) -> None:
    app.config.setdefault("AUTH_DATABASE", str(database_path))
    app.teardown_appcontext(close_db)

    @app.before_request
    def _csrf_protection():
        if request.method == "POST" and not validate_csrf():
            abort(400, description="Invalid or missing request security token.")

    @app.context_processor
    def _auth_template_context():
        return {"current_user": get_current_user(), "csrf_token": csrf_token}

    with app.app_context():
        initialize_database()
        bootstrap_admin_from_environment()
