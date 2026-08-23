from flask import Flask, render_template, request, redirect, url_for, flash, send_file, abort
from pathlib import Path
from datetime import datetime
import json
import uuid
from parser.cisco_parser import parse_cisco_config
from audit.compliance_engine import audit_configuration, summarize_findings, load_rules
from scoring.risk_engine import assess_findings
import os
from werkzeug.utils import secure_filename
import os
import json
import uuid

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    send_file,
    abort
)

from werkzeug.utils import secure_filename

IS_VERCEL = os.environ.get("VERCEL") == "1"

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
AUDIT_RECORD_DIR = BASE_DIR / "audit_records"
REPORT_DIR = BASE_DIR / "reports" / "generated"
ALLOWED_EXTENSIONS = {".txt", ".cfg", ".conf"}

app = Flask(__name__)
app.config["SECRET_KEY"] = "encca-development-key"
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024
UPLOAD_DIR.mkdir(exist_ok=True)
AUDIT_RECORD_DIR.mkdir(exist_ok=True)
REPORT_DIR.mkdir(exist_ok=True)


def allowed_file(filename):
    return Path(filename).suffix.lower() in ALLOWED_EXTENSIONS


def load_audit_history():
    """Load persisted audits for the Audit History view, newest first."""
    records = []
    for path in AUDIT_RECORD_DIR.glob("*.json"):
        try:
            audit = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
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
        })

    def history_sort_key(item):
        try:
            return datetime.strptime(item.get("audit_time", ""), "%d %b %Y, %H:%M")
        except (TypeError, ValueError):
            return datetime.min

    records.sort(key=history_sort_key, reverse=True)
    return records


@app.route("/", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        file = request.files.get("config_file")

        if not file or not file.filename:
            flash("Please select a Cisco configuration file.")
            return redirect(url_for("upload"))

        if not allowed_file(file.filename):
            flash("Only .txt, .cfg and .conf files are supported.")
            return redirect(url_for("upload"))

        safe_name = Path(file.filename).name
        destination = UPLOAD_DIR / safe_name
        file.save(destination)

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

        audit_id = uuid.uuid4().hex[:12]
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
        }
        (AUDIT_RECORD_DIR / f"{audit_id}.json").write_text(
            json.dumps(audit_record, default=str, indent=2),
            encoding="utf-8"
        )

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
def audit_result(audit_id):
    """Re-open a completed audit using its persisted audit record."""
    record_path = AUDIT_RECORD_DIR / f"{audit_id}.json"
    if not record_path.exists():
        abort(404)
    audit = json.loads(record_path.read_text(encoding="utf-8"))
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
def audit_report(audit_id):
    record_path = AUDIT_RECORD_DIR / f"{audit_id}.json"
    if not record_path.exists():
        abort(404)
    audit = json.loads(record_path.read_text(encoding="utf-8"))
    return render_template("report.html", audit=audit)


@app.route("/audit-report/<audit_id>/download")
def download_audit_report(audit_id):
    record_path = AUDIT_RECORD_DIR / f"{audit_id}.json"
    if not record_path.exists():
        abort(404)

    audit = json.loads(record_path.read_text(encoding="utf-8"))
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


if __name__ == "__main__":
    app.run(debug=True)
