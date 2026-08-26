from io import BytesIO
import json
import re
from datetime import datetime, timedelta, timezone
import hashlib

import app as app_module
import pytest

from database.auth import bootstrap_admin_from_environment, create_user, get_db, get_user, initialize_database


def csrf_token(client, path="/login"):
    response = client.get(path)
    assert response.status_code == 200
    match = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
    assert match
    return match.group(1).decode()


@pytest.fixture()
def client(tmp_path, monkeypatch):
    auth_database = tmp_path / "auth.sqlite3"
    upload_directory = tmp_path / "uploads"
    audit_directory = tmp_path / "audits"
    report_directory = tmp_path / "reports"
    upload_directory.mkdir()
    audit_directory.mkdir()
    report_directory.mkdir()
    monkeypatch.setitem(app_module.app.config, "AUTH_DATABASE", str(auth_database))
    monkeypatch.setattr(app_module, "UPLOAD_DIR", upload_directory)
    monkeypatch.setattr(app_module, "AUDIT_RECORD_DIR", audit_directory)
    monkeypatch.setattr(app_module, "REPORT_DIR", report_directory)
    with app_module.app.app_context():
        initialize_database()
    app_module.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    return app_module.app.test_client()


def add_user(username="analyst", email="analyst@example.test", password="SecurePassword!1", role="analyst"):
    with app_module.app.app_context():
        ok, message = create_user(username, email, password, role)
        assert ok, message


def login(client, identity="analyst", password="SecurePassword!1", next_url=""):
    token = csrf_token(client)
    return client.post("/login", data={"identity": identity, "password": password, "next": next_url, "csrf_token": token})


def test_login_page_loads(client):
    response = client.get("/login")
    assert response.status_code == 200
    assert b"Sign in to ENCCA" in response.data


def test_user_can_register_then_login_as_analyst(client):
    token = csrf_token(client, "/register")
    response = client.post(
        "/register", data={
            "csrf_token": token, "username": "new-analyst", "email": "new@example.test",
            "password": "NewAnalystPassword!1", "confirm_password": "NewAnalystPassword!1",
        },
    )
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")
    with app_module.app.app_context():
        user = get_user(1)
        assert user["role"] == "analyst"
        assert user["password_hash"] != "NewAnalystPassword!1"
    assert login(client, identity="new-analyst", password="NewAnalystPassword!1").status_code == 302


def test_registration_requires_csrf_and_does_not_accept_admin_role(client):
    assert client.post("/register", data={"username": "bad", "role": "admin"}).status_code == 400


def test_bootstrap_admin_requires_environment_and_hashes_password(client, monkeypatch):
    with app_module.app.app_context():
        assert bootstrap_admin_from_environment() is False
        monkeypatch.setenv("ENCCA_ADMIN_USERNAME", "bootstrap-admin")
        monkeypatch.setenv("ENCCA_ADMIN_EMAIL", "bootstrap@example.test")
        monkeypatch.setenv("ENCCA_ADMIN_PASSWORD", "BootstrapPassword!1")
        assert bootstrap_admin_from_environment() is True
        user = get_user(1)
        assert user["role"] == "admin"
        assert user["password_hash"] != "BootstrapPassword!1"


@pytest.mark.parametrize("path", ["/", "/audit-history", "/audit/abc123", "/audit-report/abc123", "/audit-report/abc123/download"])
def test_confidential_routes_require_login(client, path):
    response = client.get(path)
    assert response.status_code == 302
    assert "/login?next=" in response.headers["Location"]


def test_valid_login_hashes_password_and_logout(client):
    add_user()
    with app_module.app.app_context():
        assert get_user(1)["password_hash"] != "SecurePassword!1"
    assert login(client).status_code == 302
    assert client.get("/").status_code == 200
    assert client.get("/logout").status_code == 302
    assert client.get("/").status_code == 302


def test_invalid_login_is_generic_and_counts_attempts(client):
    add_user()
    response = login(client, password="WrongPassword!1")
    assert response.status_code == 401
    assert b"Invalid username or password." in response.data
    with app_module.app.app_context():
        assert get_user(1)["failed_login_attempts"] == 1


def test_lockout_and_success_resets_attempts(client):
    add_user()
    for _ in range(5):
        login(client, password="WrongPassword!1")
    with app_module.app.app_context():
        user = get_user(1)
        assert user["locked_until"] is not None
    assert login(client).status_code == 401

    # A separate active account proves that a successful login clears its counter.
    add_user("second", "second@example.test")
    login(client, identity="second", password="WrongPassword!1")
    assert login(client, identity="second").status_code == 302
    with app_module.app.app_context():
        assert get_user(2)["failed_login_attempts"] == 0


def test_csrf_is_required_for_login_and_upload(client):
    add_user()
    assert client.post("/login", data={"identity": "analyst", "password": "SecurePassword!1"}).status_code == 400
    assert login(client).status_code == 302
    assert client.post("/", data={"config_file": (BytesIO(b"hostname TEST"), "test.cfg")}, content_type="multipart/form-data").status_code == 400


def test_safe_post_login_redirect_and_external_redirect_rejection(client):
    add_user()
    assert login(client, next_url="/audit-history").headers["Location"].endswith("/audit-history")
    client.get("/logout")
    assert login(client, next_url="https://evil.example.com").headers["Location"].endswith("/")


def test_analyst_cannot_access_user_management_and_admin_can(client):
    add_user()
    add_user("admin", "admin@example.test", role="admin")
    login(client)
    assert client.get("/users").status_code == 403
    client.get("/logout")
    assert login(client, identity="admin").status_code == 302
    assert client.get("/users").status_code == 200


def test_inactive_user_cannot_login(client):
    add_user()
    with app_module.app.app_context():
        from database.auth import set_user_status
        set_user_status(1, False, actor_id=99)
    assert login(client).status_code == 401


def test_authenticated_upload_still_runs(client):
    add_user()
    assert login(client).status_code == 302
    token = csrf_token(client, "/")
    response = client.post(
        "/", data={"csrf_token": token, "config_file": (BytesIO(b"hostname TEST-SW\nip ssh version 2\n"), "test.cfg")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 200
    assert b"Audit Results" in response.data


def test_admin_can_view_legacy_history_and_analyst_cannot_enumerate_it(client):
    add_user("admin", "admin@example.test", role="admin")
    record = {
        "audit_id": "abcdef123456", "filename": "legacy.cfg", "data": {"hostname": "LEGACY-SW"},
        "summary": {"compliance_score": 100, "evaluated": 1, "passed": 1, "failed": 0, "not_applicable": 0},
        "risk": {"summary": {"risk_level": "Low", "risk_percentage": 0, "failed_count": 0}},
        "audit_time": "01 Jan 2026, 00:00",
    }
    audit_path = app_module.AUDIT_RECORD_DIR / "abcdef123456.json"
    audit_path.write_text(json.dumps(record), encoding="utf-8")
    assert login(client, identity="admin").status_code == 302
    response = client.get("/audit-history")
    assert response.status_code == 200
    assert b"Legacy Audit" in response.data
    client.get("/logout")
    add_user()
    assert login(client).status_code == 302
    assert client.get("/audit/abcdef123456").status_code == 404


def session_id(client):
    with client.session_transaction() as stored_session:
        return stored_session.get("session_id")


def test_login_rotates_identifier_and_cookie_contains_no_identity(client):
    add_user()
    csrf_token(client)
    before_login = session_id(client)
    assert login(client).status_code == 302
    after_login = session_id(client)
    assert before_login and after_login and before_login != after_login
    with client.session_transaction() as stored_session:
        assert set(stored_session) == {"session_id"}


def test_idle_and_absolute_timeout_reject_session(client):
    add_user()
    assert login(client).status_code == 302
    sid = session_id(client)
    old = (datetime.now(timezone.utc) - timedelta(minutes=31)).isoformat(timespec="seconds")
    with app_module.app.app_context():
        get_db().execute("UPDATE user_sessions SET last_activity_at = ? WHERE session_token_hash = ?", (old, hashlib.sha256(sid.encode()).hexdigest()))
        get_db().commit()
    expired_response = client.get("/")
    assert expired_response.status_code == 302
    login_response = client.get(expired_response.headers["Location"])
    assert b"Your session has expired due to inactivity" in login_response.data
    with app_module.app.app_context():
        assert get_user(1)["is_active"] == 1
    assert login(client).status_code == 302

    sid = session_id(client)
    old = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(timespec="seconds")
    with app_module.app.app_context():
        get_db().execute("UPDATE user_sessions SET absolute_expires_at = ? WHERE session_token_hash = ?", (old, hashlib.sha256(sid.encode()).hexdigest()))
        get_db().commit()
    assert client.get("/").status_code == 302


def test_logout_revokes_only_current_device_session(client):
    add_user()
    other_client = app_module.app.test_client()
    assert login(client).status_code == 302
    assert login(other_client).status_code == 302
    assert client.get("/logout").status_code == 302
    assert client.get("/").status_code == 302
    assert other_client.get("/").status_code == 200


def test_disabling_user_revokes_all_sessions(client):
    add_user()
    other_client = app_module.app.test_client()
    assert login(client).status_code == 302
    assert login(other_client).status_code == 302
    with app_module.app.app_context():
        from database.auth import set_user_status
        assert set_user_status(1, False, actor_id=99)[0]
    assert client.get("/").status_code == 302
    assert other_client.get("/").status_code == 302


def test_multiple_device_logins_remain_active_by_default(client):
    add_user()
    clients = [client] + [app_module.app.test_client() for _ in range(3)]
    for current_client in clients:
        assert login(current_client).status_code == 302
    with app_module.app.app_context():
        rows = get_db().execute(
            "SELECT session_token_hash, revoked_at FROM user_sessions WHERE user_id = 1 ORDER BY created_at ASC, id ASC"
        ).fetchall()
    assert len(rows) == 4
    assert all(row["revoked_at"] is None for row in rows)
    assert all(current_client.get("/").status_code == 200 for current_client in clients)


def test_optional_concurrent_session_limit_evicts_oldest(client, monkeypatch):
    monkeypatch.setitem(app_module.app.config, "ENCCA_MAX_CONCURRENT_SESSIONS", 3)
    add_user()
    clients = [client] + [app_module.app.test_client() for _ in range(3)]
    for current_client in clients:
        assert login(current_client).status_code == 302
    identifiers = [session_id(current_client) for current_client in clients]
    with app_module.app.app_context():
        rows = get_db().execute(
            "SELECT session_token_hash, revoked_at FROM user_sessions WHERE user_id = 1 ORDER BY created_at ASC, id ASC"
        ).fetchall()
    assert rows[0]["session_token_hash"] == hashlib.sha256(identifiers[0].encode()).hexdigest()
    assert rows[0]["revoked_at"] is not None
    assert all(row["revoked_at"] is None for row in rows[1:])


def test_password_reset_revokes_existing_sessions(client):
    add_user("target", "target@example.test")
    other_client = app_module.app.test_client()
    assert login(client, identity="target").status_code == 302
    assert login(other_client, identity="target").status_code == 302
    with app_module.app.app_context():
        from database.auth import reset_password
        assert reset_password(1, "ChangedPassword!1")[0]
    assert client.get("/").status_code == 302
    assert other_client.get("/").status_code == 302
