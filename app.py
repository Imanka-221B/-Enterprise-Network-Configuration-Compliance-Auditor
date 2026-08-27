from flask import Flask, Response, render_template, request, redirect, url_for, flash, send_file, abort, g, session
from pathlib import Path
from datetime import datetime
import json
import os
import secrets
import tempfile
import uuid
import re
from werkzeug.utils import secure_filename
from parser.cisco_parser import parse_cisco_config
from audit.compliance_engine import audit_configuration, summarize_findings, load_rules
from scoring.risk_engine import assess_findings
from database.auth import (
    admin_required, authenticate, create_user, csrf_token, get_current_user,
    init_auth, is_safe_url, list_users, login_required, reset_password,
    revoke_session, set_user_status, update_user, create_session,
)


BASE_DIR = Path(__file__).resolve().parent
# Vercel Functions deploy application files on an immutable filesystem. Runtime
# audit artifacts remain temporary there; account data uses the durable database
# configured below and never falls back to a temporary SQLite file.
RUNTIME_DIR = (
    Path(tempfile.gettempdir()) / "encca"
    if os.environ.get("VERCEL")
    else BASE_DIR
)
UPLOAD_DIR = RUNTIME_DIR / "uploads"
AUDIT_RECORD_DIR = RUNTIME_DIR / "audit_records"
REPORT_DIR = RUNTIME_DIR / "reports" / "generated"
ALLOWED_EXTENSIONS = {".txt", ".cfg", ".conf"}

app = Flask(__name__)
secret_key = os.environ.get("FLASK_SECRET_KEY")
if not secret_key and os.environ.get("VERCEL"):
    app.logger.warning(
        "FLASK_SECRET_KEY is not configured; using a temporary key for this function instance."
    )
    secret_key = secrets.token_urlsafe(32)
app.config["SECRET_KEY"] = secret_key or "encca-local-development-only-key"
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("VERCEL", "").lower() in {"1", "true", "yes"}
    or os.environ.get("FLASK_HTTPS", "").lower() in {"1", "true", "yes"}
)
app.config["SESSION_COOKIE_PATH"] = "/"
app.config["SESSION_COOKIE_NAME"] = "encca_session"
app.config["ENCCA_SESSION_IDLE_TIMEOUT_MINUTES"] = int(os.environ.get("ENCCA_SESSION_IDLE_TIMEOUT_MINUTES", "15"))
app.config["ENCCA_SESSION_ABSOLUTE_TIMEOUT_HOURS"] = int(os.environ.get("ENCCA_SESSION_ABSOLUTE_TIMEOUT_HOURS", "8"))
app.config["ENCCA_MAX_CONCURRENT_SESSIONS"] = int(os.environ.get("ENCCA_MAX_CONCURRENT_SESSIONS", "0"))
app.config["ENCCA_SESSION_TOUCH_MINUTES"] = 1
for directory in (UPLOAD_DIR, AUDIT_RECORD_DIR, REPORT_DIR):
    directory.mkdir(parents=True, exist_ok=True)
database_url = (
    os.environ.get("ENCCA_DATABASE_URL")
    or os.environ.get("DATABASE_URL")
    or os.environ.get("POSTGRES_URL_NON_POOLING")
    or os.environ.get("POSTGRES_URL")
    or os.environ.get("POSTGRES_PRISMA_URL")
)
database_configuration_error = bool(os.environ.get("VERCEL") and not database_url)
app.config["AUTH_DATABASE_URL"] = database_url
if not database_configuration_error:
    init_auth(app, RUNTIME_DIR / "private" / "encca_auth.sqlite3")
else:
    @app.before_request
    def _database_configuration_required():
        return Response(
            "ENCCA requires ENCCA_DATABASE_URL, DATABASE_URL, or a Vercel PostgreSQL URL to point to a durable PostgreSQL database.",
            status=503,
            mimetype="text/plain",
        )

AUDIT_ID_PATTERN = re.compile(r"^[a-f0-9]{12}$")


def allowed_file(filename):
    return Path(filename).suffix.lower() in ALLOWED_EXTENSIONS


def audit_access_allowed(audit):
    """Admins can see all records; analysts can only see their own records."""
    user = get_current_user()
    if user is None:
        return False
    if user["role"] == "admin":
        return True
    performed_by = audit.get("performed_by") or {}
    return performed_by.get("user_id") == user["id"]


def get_audit_record(audit_id):
    if not AUDIT_ID_PATTERN.fullmatch(audit_id):
        abort(404)
    record_path = AUDIT_RECORD_DIR / f"{audit_id}.json"
    if not record_path.exists():
        abort(404)
    try:
        audit = json.loads(record_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        abort(404)
    if not audit_access_allowed(audit):
        # Use 404 so authenticated users cannot enumerate another user's audits.
        abort(404)
    return audit


def load_audit_history():
    """Load persisted audits for the Audit History view, newest first."""
    records = []
    for path in AUDIT_RECORD_DIR.glob("*.json"):
        try:
            audit = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not audit_access_allowed(audit):
            continue

        summary = audit.get("summary", {})
        risk_summary = audit.get("risk", {}).get("summary", {})
        data = audit.get("data", {})
        records.append({
            "audit_id": audit.get("audit_id") or path.stem,
            "filename": audit.get("filename", "-"),
            "hostname": data.get("hostname") or "Unknown device",
            "audit_time": audit.get("audit_time", ""),
            "compliance_score": summary.get("compliance_score", 0),
            "applicable": summary.get("evaluated", summary.get("total", 0)),
            "passed": summary.get("passed", 0),
            "failed": summary.get("failed", 0),
            "not_applicable": summary.get("not_applicable", 0),
            "risk_level": risk_summary.get("risk_level", "Low"),
            "risk_percentage": risk_summary.get("risk_percentage", 0),
            "finding_count": risk_summary.get("failed_count", summary.get("failed", 0)),
            "performed_by": (audit.get("performed_by") or {}).get("username", "Legacy Audit"),
        })

    def history_sort_key(item):
        try:
            return datetime.strptime(item.get("audit_time", ""), "%d %b %Y, %H:%M")
        except (TypeError, ValueError):
            return datetime.min

    records.sort(key=history_sort_key, reverse=True)
    return records


@app.route("/", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        file = request.files.get("config_file")

        if not file or not file.filename:
            flash("Please select a Cisco configuration file.")
            return redirect(url_for("upload"))

        if not allowed_file(file.filename):
            flash("Only .txt, .cfg and .conf files are supported.")
            return redirect(url_for("upload"))

        safe_name = secure_filename(Path(file.filename).name)
        if not safe_name:
            flash("Please select a valid Cisco configuration file.")
            return redirect(url_for("upload"))
        audit_id = uuid.uuid4().hex[:12]
        # Keep each upload separate. This prevents two users uploading a file
        # with the same name from overwriting each other's configuration.
        destination = UPLOAD_DIR / f"{audit_id}_{safe_name}"
        try:
            file.save(destination)
        except OSError:
            app.logger.exception("Could not save uploaded configuration")
            flash("The configuration could not be processed. Please try again.")
            return redirect(url_for("upload"))

        parsed = parse_cisco_config(destination)
        findings = audit_configuration(parsed)
        summary = summarize_findings(findings)
        rule_catalogue = {r["id"]: r for r in load_rules()}
        risk = assess_findings(findings, rule_catalogue)

        # Presentation-only analytics for the dashboard. Compliance and risk
        # calculations remain authoritative in their existing engines.
        category_risk = {}
        for item in risk.get("prioritized_findings", []):
            category = item.get("category", "Other")
            bucket = category_risk.setdefault(category, {"weight": 0, "count": 0, "severity": item.get("severity", "Low")})
            bucket["weight"] += item.get("weight", 0)
            bucket["count"] += 1
            severity_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
            if severity_rank.get(item.get("severity", "Low"), 0) > severity_rank.get(bucket["severity"], 0):
                bucket["severity"] = item.get("severity", "Low")

        total_failed_weight = risk["summary"].get("failed_weight", 0)
        for bucket in category_risk.values():
            bucket["contribution"] = round((bucket["weight"] / total_failed_weight) * 100, 2) if total_failed_weight else 0

        category_risk = dict(sorted(
            category_risk.items(),
            key=lambda item: (-item[1]["weight"], item[0])
        ))

        # Presentation-only security statistics derived from authoritative outputs.
        interface_inventory = {"total": len(parsed.get("interfaces", [])), "access": 0, "trunk": 0, "unused": 0, "other": 0}
        for interface in parsed.get("interfaces", []):
            role = str(interface.get("role", "")).lower()
            if role == "access_port":
                interface_inventory["access"] += 1
            elif role == "approved_uplink" or str(interface.get("mode", "")).lower() == "trunk":
                interface_inventory["trunk"] += 1
            elif role == "unused_port":
                interface_inventory["unused"] += 1
            else:
                interface_inventory["other"] += 1

        statistics = {
            "compliance": {
                "passed": summary.get("passed", 0),
                "failed": summary.get("failed", 0),
                "not_applicable": summary.get("not_applicable", 0),
                "applicable": summary.get("evaluated", 0),
                "score": summary.get("compliance_score", 0),
            },
            "risk": {
                "critical": risk["summary"].get("severity_counts", {}).get("Critical", 0),
                "high": risk["summary"].get("severity_counts", {}).get("High", 0),
                "medium": risk["summary"].get("severity_counts", {}).get("Medium", 0),
                "low": risk["summary"].get("severity_counts", {}).get("Low", 0),
                "percentage": risk["summary"].get("risk_percentage", 0),
                "level": risk["summary"].get("risk_level", "Low"),
            },
            "interfaces": interface_inventory,
        }

        audit_record = {
            "audit_id": audit_id,
            "filename": safe_name,
            "data": parsed,
            "findings": findings,
            "summary": summary,
            "risk": risk,
            "category_risk": category_risk,
            "statistics": statistics,
            "audit_time": datetime.now().strftime("%d %b %Y, %H:%M"),
            "user_id": g.current_user["id"],
            "username": g.current_user["username"],
            "performed_by": {
                "user_id": g.current_user["id"],
                "username": g.current_user["username"],
            },
        }
        try:
            (AUDIT_RECORD_DIR / f"{audit_id}.json").write_text(
                json.dumps(audit_record, default=str, indent=2), encoding="utf-8"
            )
        except OSError:
            app.logger.exception("Could not save audit record %s", audit_id)
            flash("The audit completed but its confidential result could not be saved. Please try again.")
            return redirect(url_for("upload"))

        return render_template(
            "result.html",
            audit_id=audit_id,
            filename=safe_name,
            data=parsed,
            findings=findings,
            summary=summary,
            risk=risk,
            category_risk=category_risk,
            statistics=statistics,
            audit_time=datetime.now().strftime("%d %b %Y, %H:%M")
        )

    return render_template("upload.html")



@app.route("/audit-history")
@login_required
def audit_history():
    records = load_audit_history()
    query = request.args.get("q", "").strip().lower()
    severity = request.args.get("severity", "all").strip().lower()

    filtered = []
    for record in records:
        searchable = " ".join([
            str(record.get("hostname", "")),
            str(record.get("filename", "")),
            str(record.get("audit_id", "")),
        ]).lower()
        if query and query not in searchable:
            continue
        if severity != "all" and str(record.get("risk_level", "")).lower() != severity:
            continue
        filtered.append(record)

    total = len(records)
    avg_compliance = round(sum(float(r.get("compliance_score", 0) or 0) for r in records) / total, 1) if total else 0
    critical_count = sum(1 for r in records if str(r.get("risk_level", "")).lower() == "critical")
    failed_total = sum(int(r.get("failed", 0) or 0) for r in records)

    return render_template(
        "history.html",
        records=filtered,
        total=total,
        visible_count=len(filtered),
        avg_compliance=avg_compliance,
        critical_count=critical_count,
        failed_total=failed_total,
        query=request.args.get("q", ""),
        severity=severity,
    )


@app.route("/audit/<audit_id>")
@login_required
def audit_result(audit_id):
    """Re-open a completed audit using its persisted audit record."""
    audit = get_audit_record(audit_id)
    return render_template(
        "result.html",
        audit_id=audit_id,
        filename=audit.get("filename", "-"),
        data=audit.get("data", {}),
        findings=audit.get("findings", []),
        summary=audit.get("summary", {}),
        risk=audit.get("risk", {}),
        category_risk=audit.get("category_risk", {}),
        statistics=audit.get("statistics", {}),
        audit_time=audit.get("audit_time", ""),
    )


@app.route("/audit-report/<audit_id>")
@login_required
def audit_report(audit_id):
    audit = get_audit_record(audit_id)
    return render_template("report.html", audit=audit)


@app.route("/audit-report/<audit_id>/download")
@login_required
def download_audit_report(audit_id):
    audit = get_audit_record(audit_id)
    pdf_path = REPORT_DIR / f"ENCCA_Audit_Report_{audit_id}.pdf"

    try:
        from reports.audit_report import build_pdf
        build_pdf(audit, pdf_path)
    except Exception as exc:
        app.logger.exception("Audit PDF generation failed for %s", audit_id)
        return (
            "ENCCA could not generate the PDF report. "
            "Please install the project requirements with "
            "`python -m pip install -r requirements.txt` and try again. "
            f"Generation error: {type(exc).__name__}",
            500,
        )

    if not pdf_path.exists() or pdf_path.stat().st_size == 0:
        return "ENCCA generated an empty PDF report. Please try the audit again.", 500

    return send_file(
        pdf_path,
        as_attachment=True,
        download_name=f"ENCCA_Audit_Report_{audit_id}.pdf",
        mimetype="application/pdf"
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if get_current_user() is not None:
        return redirect(url_for("upload"))
    provisioning_required = not any(user["role"] == "admin" for user in list_users())
    if request.method == "POST":
        user = authenticate(request.form.get("identity", ""), request.form.get("password", ""))
        if user is None:
            flash("Invalid username or password.")
            return render_template("login.html", provisioning_required=provisioning_required), 401
        # Revoke the anonymous session and issue a fresh authenticated token.
        revoke_session()
        create_session(user["id"])
        destination = request.form.get("next") or request.args.get("next")
        return redirect(destination if is_safe_url(destination) else url_for("upload"))
    return render_template("login.html", provisioning_required=provisioning_required)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Public self-registration creates analyst accounts only, never admins."""
    if get_current_user() is not None:
        return redirect(url_for("upload"))
    if request.method == "POST":
        if request.form.get("password") != request.form.get("confirm_password"):
            flash("Password confirmation does not match.")
        else:
            ok, message = create_user(
                request.form.get("username", ""),
                request.form.get("email", ""),
                request.form.get("password", ""),
                role="analyst",
            )
            flash(message)
            if ok:
                return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/logout")
@login_required
def logout():
    revoke_session()
    session.clear()
    flash("You have been signed out.")
    return redirect(url_for("login"))


@app.route("/users")
@admin_required
def users():
    return render_template("users.html", users=list_users())


@app.route("/users/create", methods=["GET", "POST"])
@admin_required
def create_user_route():
    if request.method == "POST":
        if request.form.get("password") != request.form.get("confirm_password"):
            flash("Password confirmation does not match.")
        else:
            ok, message = create_user(
                request.form.get("username", ""), request.form.get("email", ""),
                request.form.get("password", ""), request.form.get("role", "analyst"),
            )
            flash(message)
            if ok:
                return redirect(url_for("users"))
    return render_template("user_form.html", user=None, mode="create")


@app.route("/users/<int:user_id>/edit", methods=["GET", "POST"])
@admin_required
def edit_user(user_id):
    from database.auth import get_user
    user = get_user(user_id)
    if user is None:
        abort(404)
    if request.method == "POST":
        ok, message = update_user(
            user_id, request.form.get("email", ""), request.form.get("role", ""),
            request.form.get("is_active") == "1", g.current_user["id"],
        )
        flash(message)
        if ok:
            return redirect(url_for("users"))
        user = get_user(user_id)
    return render_template("user_form.html", user=user, mode="edit")


@app.route("/users/<int:user_id>/toggle-status", methods=["POST"])
@admin_required
def toggle_user_status(user_id):
    from database.auth import get_user
    user = get_user(user_id)
    if user is None:
        abort(404)
    ok, message = set_user_status(user_id, not bool(user["is_active"]), g.current_user["id"])
    flash(message)
    return redirect(url_for("users"))


@app.route("/users/<int:user_id>/reset-password", methods=["POST"])
@admin_required
def reset_user_password(user_id):
    if request.form.get("password") != request.form.get("confirm_password"):
        flash("Password confirmation does not match.")
    else:
        _ok, message = reset_password(user_id, request.form.get("password", ""))
        flash(message)
    return redirect(url_for("edit_user", user_id=user_id))


@app.errorhandler(400)
def bad_request(_error):
    return "The request could not be processed.", 400


@app.errorhandler(403)
def forbidden(_error):
    return "You are not authorized to access this resource.", 403


if __name__ == "__main__":
    app.run(debug=True)
