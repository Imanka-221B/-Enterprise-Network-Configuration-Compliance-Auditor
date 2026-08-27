"""Relational audit persistence shared by local SQLite and production PostgreSQL."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from flask import current_app, g, request

from database.auth import get_db


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def initialize_audit_schema() -> None:
    postgres = bool(current_app.config.get("AUTH_DATABASE_URL"))
    user_id_type = "BIGINT" if postgres else "INTEGER"
    primary_id = "BIGSERIAL PRIMARY KEY" if postgres else "INTEGER PRIMARY KEY AUTOINCREMENT"
    get_db().executescript(
        f"""
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version TEXT PRIMARY KEY,
            applied_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS configurations (
            id TEXT PRIMARY KEY,
            user_id {user_id_type} NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
            device_name TEXT,
            hostname TEXT,
            filename TEXT NOT NULL,
            file_hash TEXT,
            file_size INTEGER,
            storage_key TEXT,
            uploaded_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            version INTEGER NOT NULL DEFAULT 1,
            status TEXT NOT NULL DEFAULT 'completed'
        );
        CREATE INDEX IF NOT EXISTS idx_configurations_user ON configurations(user_id);
        CREATE INDEX IF NOT EXISTS idx_configurations_hash ON configurations(file_hash);
        CREATE INDEX IF NOT EXISTS idx_configurations_uploaded ON configurations(uploaded_at);
        CREATE TABLE IF NOT EXISTS audits (
            audit_id TEXT PRIMARY KEY,
            configuration_id TEXT NOT NULL REFERENCES configurations(id) ON DELETE RESTRICT,
            user_id {user_id_type} NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
            device_name TEXT,
            parser_version TEXT,
            rule_set_version TEXT,
            engine_version TEXT,
            risk_model_version TEXT,
            compliance_score REAL,
            risk_percentage REAL,
            security_score REAL,
            risk_level TEXT,
            total_checks INTEGER,
            passed_checks INTEGER,
            failed_checks INTEGER,
            not_applicable_checks INTEGER,
            started_at TEXT,
            completed_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            payload_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_audits_user ON audits(user_id);
        CREATE INDEX IF NOT EXISTS idx_audits_configuration ON audits(configuration_id);
        CREATE INDEX IF NOT EXISTS idx_audits_completed ON audits(completed_at);
        CREATE INDEX IF NOT EXISTS idx_audits_risk ON audits(risk_level);
        CREATE TABLE IF NOT EXISTS audit_findings (
            id {primary_id},
            audit_id TEXT NOT NULL REFERENCES audits(audit_id) ON DELETE RESTRICT,
            rule_id TEXT,
            status TEXT,
            severity TEXT,
            category TEXT,
            title TEXT,
            description TEXT,
            target TEXT,
            evidence TEXT,
            expected TEXT,
            recommendation TEXT,
            remediation TEXT,
            reference TEXT,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_findings_audit ON audit_findings(audit_id);
        CREATE INDEX IF NOT EXISTS idx_findings_rule ON audit_findings(rule_id);
        CREATE INDEX IF NOT EXISTS idx_findings_severity ON audit_findings(severity);
        CREATE INDEX IF NOT EXISTS idx_findings_status ON audit_findings(status);
        CREATE TABLE IF NOT EXISTS security_events (
            id {primary_id},
            user_id {user_id_type} REFERENCES users(id) ON DELETE RESTRICT,
            event_type TEXT NOT NULL,
            event_result TEXT NOT NULL,
            resource_type TEXT,
            resource_id TEXT,
            ip_address TEXT,
            user_agent TEXT,
            created_at TEXT NOT NULL,
            metadata TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_events_user ON security_events(user_id);
        CREATE INDEX IF NOT EXISTS idx_events_type ON security_events(event_type);
        CREATE INDEX IF NOT EXISTS idx_events_created ON security_events(created_at);
        CREATE TABLE IF NOT EXISTS reports (
            id {primary_id},
            audit_id TEXT NOT NULL REFERENCES audits(audit_id) ON DELETE RESTRICT,
            user_id {user_id_type} NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
            report_type TEXT NOT NULL,
            storage_key TEXT,
            created_at TEXT NOT NULL,
            status TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_reports_audit ON reports(audit_id);
        CREATE INDEX IF NOT EXISTS idx_reports_user ON reports(user_id);
        """
    )
    get_db().execute(
        "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?) ON CONFLICT(version) DO NOTHING",
        ("audit-relational-v1", _utc_now()),
    )
    get_db().commit()
    g.audit_schema_ready = True


def _ensure_audit_schema() -> None:
    if not getattr(g, "audit_schema_ready", False):
        initialize_audit_schema()


def save_audit(audit: dict, user_id: int, storage_key: str | None = None) -> None:
    _ensure_audit_schema()
    db = get_db()
    now = _utc_now()
    audit_id = audit["audit_id"]
    data = audit.get("data", {})
    summary = audit.get("summary", {})
    risk_summary = audit.get("risk", {}).get("summary", {})
    try:
        db.execute(
            "INSERT INTO configurations (id, user_id, device_name, hostname, filename, file_hash, file_size, storage_key, uploaded_at, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (audit_id, user_id, data.get("hostname"), data.get("hostname"), audit.get("filename", "-"), audit.get("file_hash"), audit.get("file_size"), storage_key, audit["audit_time"], now),
        )
        db.execute(
        "INSERT INTO audits (audit_id, configuration_id, user_id, device_name, parser_version, rule_set_version, "
        "engine_version, risk_model_version, compliance_score, risk_percentage, security_score, risk_level, total_checks, "
        "passed_checks, failed_checks, not_applicable_checks, started_at, completed_at, created_at, payload_json) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (audit_id, audit_id, user_id, data.get("hostname"), "v2", "v2.1", "v2.1", "v1.0",
         summary.get("compliance_score"), risk_summary.get("risk_percentage"), risk_summary.get("security_score"),
         risk_summary.get("risk_level"), summary.get("total", summary.get("evaluated")), summary.get("passed"),
         summary.get("failed"), summary.get("not_applicable", 0), audit["audit_time"], audit["audit_time"], now,
             json.dumps(audit, default=str)),
        )
        for finding in audit.get("findings", []):
            db.execute(
              "INSERT INTO audit_findings (audit_id, rule_id, status, severity, category, title, description, target, evidence, expected, recommendation, remediation, reference, created_at) "
              "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (audit_id, finding.get("rule_id"), finding.get("status"), finding.get("severity"), finding.get("category"),
             finding.get("title"), finding.get("description"), finding.get("target"), finding.get("evidence"),
                 finding.get("expected"), finding.get("recommendation"), finding.get("remediation"), finding.get("reference"), now),
            )
        db.commit()
    except Exception:
        db.rollback()
        raise


def get_audit(audit_id: str):
    _ensure_audit_schema()
    row = get_db().execute("SELECT payload_json FROM audits WHERE audit_id = ?", (audit_id,)).fetchone()
    return json.loads(row["payload_json"]) if row else None


def list_audits(user_id: int, is_admin: bool = False):
    _ensure_audit_schema()
    sql = "SELECT payload_json FROM audits" if is_admin else "SELECT payload_json FROM audits WHERE user_id = ?"
    rows = get_db().execute(sql, () if is_admin else (user_id,)).fetchall()
    return [json.loads(row["payload_json"]) for row in rows]


def record_report(audit_id: str, user_id: int, storage_key: str, report_type: str = "pdf") -> None:
    _ensure_audit_schema()
    get_db().execute(
        "INSERT INTO reports (audit_id, user_id, report_type, storage_key, created_at, status) VALUES (?, ?, ?, ?, ?, ?)",
        (audit_id, user_id, report_type, storage_key, _utc_now(), "generated"),
    )
    get_db().commit()


def record_security_event(event_type: str, event_result: str, user_id: int | None = None,
                          resource_type: str | None = None, resource_id: str | None = None,
                          metadata: dict | None = None) -> None:
    _ensure_audit_schema()
    get_db().execute(
        "INSERT INTO security_events (user_id, event_type, event_result, resource_type, resource_id, ip_address, user_agent, created_at, metadata) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (user_id, event_type, event_result, resource_type, resource_id, request.remote_addr,
         request.user_agent.string[:512], _utc_now(), json.dumps(metadata or {})),
    )
    get_db().commit()
