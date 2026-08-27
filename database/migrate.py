"""Idempotent migration helpers for legacy SQLite users and JSON audits."""

from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path
from flask import current_app

from database.auth import get_db, initialize_database
from database.audits import get_audit, initialize_audit_schema, save_audit


def migrate_users(source_path: Path) -> tuple[int, int, dict[int, int]]:
    source = sqlite3.connect(source_path)
    source.row_factory = sqlite3.Row
    migrated = skipped = 0
    user_id_map = {}
    try:
        for user in source.execute("SELECT * FROM users ORDER BY id"):
            try:
                get_db().execute(
                    "INSERT INTO users (id, username, email, password_hash, role, is_active, failed_login_attempts, locked_until, last_login_at, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING",
                    tuple(user[column] for column in (
                        "id", "username", "email", "password_hash", "role", "is_active",
                        "failed_login_attempts", "locked_until", "last_login_at", "created_at", "updated_at",
                    )),
                )
                migrated += 1
            except Exception:
                get_db().rollback()
                skipped += 1
            target = get_db().execute("SELECT id FROM users WHERE LOWER(username) = LOWER(?)", (user["username"],)).fetchone()
            if target:
                user_id_map[int(user["id"])] = int(target["id"])
        get_db().commit()
        if current_app.config.get("AUTH_DATABASE_URL"):
            get_db().execute(
                "SELECT setval(pg_get_serial_sequence('users', 'id'), COALESCE((SELECT MAX(id) FROM users), 1), true)"
            )
            get_db().commit()
    finally:
        source.close()
    return migrated, skipped, user_id_map


def migrate_audits(source_dir: Path, user_id_map: dict[int, int] | None = None) -> tuple[int, int]:
    migrated = skipped = 0
    for path in sorted(source_dir.glob("*.json")):
        try:
            audit = json.loads(path.read_text(encoding="utf-8"))
            audit_id = audit.get("audit_id") or path.stem
            if get_audit(audit_id):
                skipped += 1
                continue
            user_id = (audit.get("performed_by") or {}).get("user_id") or audit.get("user_id")
            user_id = (user_id_map or {}).get(int(user_id), user_id) if user_id is not None else None
            if user_id is None:
                skipped += 1
                continue
            audit["audit_id"] = audit_id
            save_audit(audit, int(user_id), f"uploads/{audit_id}_{audit.get('filename', '')}")
            migrated += 1
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            skipped += 1
    return migrated, skipped


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-db", type=Path, default=Path("private/encca_auth.sqlite3"))
    parser.add_argument("--audit-dir", type=Path, default=Path("audit_records"))
    args = parser.parse_args()
    from app import app
    with app.app_context():
        initialize_database()
        initialize_audit_schema()
        users = migrate_users(args.source_db) if args.source_db.exists() else (0, 0)
        audits = migrate_audits(args.audit_dir)
        print(f"Users migrated: {users[0]}, skipped: {users[1]}")
        print(f"Audits migrated: {audits[0]}, skipped: {audits[1]}")


if __name__ == "__main__":
    main()
