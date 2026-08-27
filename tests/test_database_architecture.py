import json

import app as app_module
from database.audits import get_db
from database.migrate import migrate_audits
from database.auth import create_user


def test_legacy_audit_migration_is_idempotent(tmp_path, monkeypatch):
    database_path = tmp_path / "auth.sqlite3"
    monkeypatch.setitem(app_module.app.config, "AUTH_DATABASE", str(database_path))
    with app_module.app.app_context():
        from database.auth import initialize_database
        from database.audits import initialize_audit_schema
        initialize_database()
        initialize_audit_schema()
        assert create_user("migrator", "migrator@example.test", "MigratorPassword!1")[0]
        audit_dir = tmp_path / "audit_records"
        audit_dir.mkdir()
        audit = {
            "audit_id": "abcdef123456", "filename": "legacy.cfg",
            "data": {"hostname": "LEGACY-SW"},
            "summary": {"compliance_score": 100, "evaluated": 1, "passed": 1, "failed": 0, "not_applicable": 0},
            "risk": {"summary": {"risk_percentage": 0, "security_score": 100, "risk_level": "Low", "failed_count": 0}},
            "findings": [], "audit_time": "2026-08-27T04:15:00+00:00",
            "performed_by": {"user_id": 1, "username": "migrator"}, "user_id": 1,
        }
        (audit_dir / "abcdef123456.json").write_text(json.dumps(audit), encoding="utf-8")
        assert migrate_audits(audit_dir) == (1, 0)
        assert migrate_audits(audit_dir) == (0, 1)
        assert get_db().execute("SELECT COUNT(*) FROM audits").fetchone()[0] == 1
        assert get_db().execute("SELECT COUNT(*) FROM configurations").fetchone()[0] == 1
