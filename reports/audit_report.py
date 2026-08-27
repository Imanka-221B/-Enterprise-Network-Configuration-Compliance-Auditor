from pathlib import Path
from xml.sax.saxutils import escape
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, LongTable
from utils.timezone import format_datetime_local

PAGE_BLUE = colors.HexColor("#0B3A60")
ACCENT = colors.HexColor("#087EB7")
LINE = colors.HexColor("#CBD5E1")
LIGHT = colors.HexColor("#F5F8FA")
TEXT = colors.HexColor("#243B4A")
MUTED = colors.HexColor("#64748B")


def _p(value, style):
    return Paragraph(escape(str(value if value is not None else "-")), style)


def _severity_color(value):
    return {
        "Critical": colors.HexColor("#B42318"),
        "High": colors.HexColor("#C9372C"),
        "Medium": colors.HexColor("#9A6700"),
        "Low": colors.HexColor("#2E7D4F"),
    }.get(str(value), TEXT)


def _base_table(data, widths, header=True, font=7.8, repeat_rows=1):
    table = LongTable(data, colWidths=widths, repeatRows=repeat_rows if header else 0, hAlign="LEFT")
    commands = [
        ("GRID", (0, 0), (-1, -1), 0.35, LINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTSIZE", (0, 0), (-1, -1), font),
        ("LEADING", (0, 0), (-1, -1), font + 2),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]),
    ]
    if header:
        commands += [
            ("BACKGROUND", (0, 0), (-1, 0), PAGE_BLUE),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ]
    table.setStyle(TableStyle(commands))
    return table


def build_pdf(audit, output_path):
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    data = audit.get("data", {})
    summary = audit.get("summary", {})
    risk = audit.get("risk", {})
    statistics = audit.get("statistics", {})
    findings = audit.get("findings", [])
    category_risk = audit.get("category_risk", {})
    audit_time = format_datetime_local(audit.get("audit_time"))
    hostname = data.get("hostname") or audit.get("filename") or "Unknown Device"

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="TitleENCCA", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=23, leading=27, textColor=PAGE_BLUE, alignment=TA_CENTER, spaceAfter=5))
    styles.add(ParagraphStyle(name="SubtitleENCCA", parent=styles["Normal"], fontSize=9, leading=12, textColor=MUTED, alignment=TA_CENTER, spaceAfter=12))
    styles.add(ParagraphStyle(name="SectionENCCA", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=14, leading=18, textColor=PAGE_BLUE, spaceBefore=12, spaceAfter=7))
    styles.add(ParagraphStyle(name="BodyENCCA", parent=styles["BodyText"], fontSize=8.5, leading=12, textColor=TEXT))
    styles.add(ParagraphStyle(name="SmallENCCA", parent=styles["BodyText"], fontSize=7.2, leading=9.5, textColor=TEXT))
    styles.add(ParagraphStyle(name="TinyENCCA", parent=styles["BodyText"], fontSize=6.5, leading=8.0, textColor=TEXT))
    styles.add(ParagraphStyle(name="HeaderENCCA", parent=styles["BodyText"], fontName="Helvetica-Bold", fontSize=7.2, leading=9, textColor=colors.white))
    styles.add(ParagraphStyle(name="Metric", parent=styles["BodyText"], fontName="Helvetica-Bold", fontSize=14, leading=16, textColor=PAGE_BLUE, alignment=TA_CENTER))

    story = [
        Spacer(1, 5 * mm),
        Paragraph("ENCCA", styles["TitleENCCA"]),
        Paragraph("Enterprise Network Configuration Compliance Auditor", styles["SubtitleENCCA"]),
        Paragraph("PROFESSIONAL SECURITY AUDIT REPORT", styles["SectionENCCA"]),
    ]

    meta = [
        [_p("Configuration", styles["SmallENCCA"]), _p(audit.get("filename", "-"), styles["SmallENCCA"])],
        [_p("Hostname", styles["SmallENCCA"]), _p(hostname, styles["SmallENCCA"])],
        [_p("Audit Time", styles["SmallENCCA"]), _p(audit_time, styles["SmallENCCA"])],
        [_p("Compliance Engine", styles["SmallENCCA"]), _p("v2.1", styles["SmallENCCA"])],
        [_p("Risk Assessment Engine", styles["SmallENCCA"]), _p("v1.0", styles["SmallENCCA"])],
        [_p("Audit ID", styles["SmallENCCA"]), _p(audit.get("audit_id", "-"), styles["SmallENCCA"])],
    ]
    meta_table = Table(meta, colWidths=[48 * mm, 125 * mm])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EAF2F8")),
        ("TEXTCOLOR", (0, 0), (0, -1), PAGE_BLUE),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), .35, LINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]))
    story += [meta_table, Spacer(1, 7 * mm)]

    story.append(Paragraph("Executive Security Summary", styles["SectionENCCA"]))
    score = summary.get("compliance_score", 0)
    security_score = risk.get("summary", {}).get("security_score", 0)
    risk_pct = risk.get("summary", {}).get("risk_percentage", 0)
    risk_level = risk.get("summary", {}).get("risk_level", "Low")
    metrics = [[
        _p("COMPLIANCE\n" + f"{score}%", styles["Metric"]),
        _p("SECURITY SCORE\n" + f"{security_score}/100", styles["Metric"]),
        _p("FAILED CONTROLS\n" + str(summary.get("failed", 0)), styles["Metric"]),
        _p("RISK EXPOSURE\n" + f"{risk_pct}%", styles["Metric"]),
    ]]
    metric_table = Table(metrics, colWidths=[43.25 * mm] * 4, rowHeights=[24 * mm])
    metric_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F7FAFC")),
        ("BOX", (0, 0), (-1, -1), .5, LINE),
        ("INNERGRID", (0, 0), (-1, -1), .35, LINE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story += [metric_table, Spacer(1, 3 * mm), Paragraph(f"Overall risk level: <b>{escape(str(risk_level))}</b>. Compliance decisions are deterministic and authoritative; the Risk Engine interprets failed findings using severity weights.", styles["BodyENCCA"])]

    story.append(Paragraph("Compliance & Risk Statistics", styles["SectionENCCA"]))
    comp = statistics.get("compliance", {})
    rs = statistics.get("risk", {})
    inv = statistics.get("interfaces", {})
    stats = [
        [_p("Statistic", styles["HeaderENCCA"]), _p("Value", styles["HeaderENCCA"]), _p("Statistic", styles["HeaderENCCA"]), _p("Value", styles["HeaderENCCA"])],
        [_p("Applicable Controls", styles["SmallENCCA"]), _p(comp.get("applicable", 0), styles["SmallENCCA"]), _p("Critical Findings", styles["SmallENCCA"]), _p(rs.get("critical", 0), styles["SmallENCCA"])],
        [_p("Passed Controls", styles["SmallENCCA"]), _p(comp.get("passed", 0), styles["SmallENCCA"]), _p("High Findings", styles["SmallENCCA"]), _p(rs.get("high", 0), styles["SmallENCCA"])],
        [_p("Failed Controls", styles["SmallENCCA"]), _p(comp.get("failed", 0), styles["SmallENCCA"]), _p("Medium Findings", styles["SmallENCCA"]), _p(rs.get("medium", 0), styles["SmallENCCA"])],
        [_p("Not Applicable", styles["SmallENCCA"]), _p(comp.get("not_applicable", 0), styles["SmallENCCA"]), _p("Low Findings", styles["SmallENCCA"]), _p(rs.get("low", 0), styles["SmallENCCA"])],
        [_p("Total Interfaces", styles["SmallENCCA"]), _p(inv.get("total", 0), styles["SmallENCCA"]), _p("Access / Trunk / Unused", styles["SmallENCCA"]), _p(f"{inv.get('access', 0)} / {inv.get('trunk', 0)} / {inv.get('unused', 0)}", styles["SmallENCCA"])],
    ]
    story.append(_base_table(stats, [38 * mm, 20 * mm, 68 * mm, 48 * mm], font=7.5))

    if category_risk:
        story.append(Paragraph("Risk Contribution by Category", styles["SectionENCCA"]))
        rows = [[_p("Category", styles["HeaderENCCA"]), _p("Findings", styles["HeaderENCCA"]), _p("Weight", styles["HeaderENCCA"]), _p("Contribution", styles["HeaderENCCA"])]]
        for category, item in category_risk.items():
            rows.append([_p(category, styles["SmallENCCA"]), _p(item.get("count", 0), styles["SmallENCCA"]), _p(item.get("weight", 0), styles["SmallENCCA"]), _p(f"{item.get('contribution', 0)}%", styles["SmallENCCA"])])
        story.append(_base_table(rows, [58 * mm, 28 * mm, 30 * mm, 58 * mm], font=7.5))

    story.append(PageBreak())
    story.append(Paragraph("Prioritized Risk Findings", styles["SectionENCCA"]))
    prioritized = risk.get("prioritized_findings", [])
    if prioritized:
        # Keep this table aligned with the Audit Report UI: Rule, Risk,
        # Category, Target, Evidence, Contribution and Recommendation.
        rows = [[_p(x, styles["HeaderENCCA"]) for x in [
            "Rule", "Risk", "Category", "Target", "Evidence",
            "Contribution", "Recommendation"
        ]]]
        for item in prioritized:
            rows.append([
                _p(item.get("rule_id", ""), styles["TinyENCCA"]),
                _p(item.get("severity", ""), styles["TinyENCCA"]),
                _p(item.get("category", ""), styles["TinyENCCA"]),
                _p(item.get("target", "Global"), styles["TinyENCCA"]),
                _p(item.get("evidence", ""), styles["TinyENCCA"]),
                _p(f"{item.get('risk_contribution', item.get('contribution', 0))}%", styles["TinyENCCA"]),
                _p(item.get("recommendation", ""), styles["TinyENCCA"]),
            ])
        # Total width = 174 mm, exactly matching the A4 printable area
        # (210 mm - 18 mm left - 18 mm right). This prevents clipping.
        rt = _base_table(
            rows,
            [17 * mm, 17 * mm, 25 * mm, 29 * mm, 36 * mm, 16 * mm, 34 * mm],
            font=6.3
        )
        story += [rt, Spacer(1, 5 * mm)]
    else:
        story.append(Paragraph("No failed risk findings were identified. All applicable controls passed.", styles["BodyENCCA"]))

    story.append(Paragraph("Compliance Findings & Remediation", styles["SectionENCCA"]))
    failed = [f for f in findings if str(f.get("status", "")).upper() == "FAIL"]
    if failed:
        for f in failed:
            title = f"{f.get('rule_id', '')} · {f.get('severity', '-')} · {f.get('target', 'Global')}"
            detail = [
                [_p("Category", styles["TinyENCCA"]), _p(f.get("category", ""), styles["TinyENCCA"])],
                [_p("Check", styles["TinyENCCA"]), _p(f.get("title", ""), styles["TinyENCCA"])],
                [_p("Evidence", styles["TinyENCCA"]), _p(f.get("evidence", ""), styles["TinyENCCA"])],
                [_p("Expected", styles["TinyENCCA"]), _p(f.get("expected", ""), styles["TinyENCCA"])],
                [_p("Recommendation", styles["TinyENCCA"]), _p(f.get("recommendation", ""), styles["TinyENCCA"])],
                [_p("Remediation", styles["TinyENCCA"]), _p(f.get("remediation", ""), styles["TinyENCCA"])],
                [_p("Reference", styles["TinyENCCA"]), _p(f.get("reference", ""), styles["TinyENCCA"])],
            ]
            dt = Table(detail, colWidths=[35 * mm, 138 * mm], hAlign="LEFT")
            dt.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F1F5F9")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), .3, LINE),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            story += [Paragraph(escape(title), styles["BodyENCCA"]), dt, Spacer(1, 5 * mm)]
    else:
        story.append(Paragraph("All applicable compliance controls passed.", styles["BodyENCCA"]))

    # Full authoritative control appendix: PASS, FAIL and N/A results.
    story.append(PageBreak())
    story.append(Paragraph("Control Results Appendix", styles["SectionENCCA"]))
    story.append(Paragraph("The following table contains the complete set of Compliance Engine v2.1 decisions for this audit.", styles["BodyENCCA"]))
    rows = [[_p(x, styles["HeaderENCCA"]) for x in ["Rule", "Category", "Check", "Target", "Status", "Severity", "Evidence"]]]
    for f in findings:
        rows.append([
            _p(f.get("rule_id", ""), styles["TinyENCCA"]),
            _p(f.get("category", ""), styles["TinyENCCA"]),
            _p(f.get("title", ""), styles["TinyENCCA"]),
            _p(f.get("target", "Global"), styles["TinyENCCA"]),
            _p(f.get("status", ""), styles["TinyENCCA"]),
            _p(f.get("severity", "-"), styles["TinyENCCA"]),
            _p(f.get("evidence", ""), styles["TinyENCCA"]),
        ])
    # Total width = 174 mm, matching the A4 printable area. Use compact
    # typography so evidence wraps inside the page instead of being clipped.
    story.append(_base_table(
        rows,
        [16 * mm, 22 * mm, 34 * mm, 27 * mm, 19 * mm, 18 * mm, 38 * mm],
        font=5.8
    ))

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setStrokeColor(LINE)
        canvas.line(18 * mm, 14 * mm, 192 * mm, 14 * mm)
        canvas.setFont("Helvetica", 6.8)
        canvas.setFillColor(MUTED)
        canvas.drawString(18 * mm, 9 * mm, "ENCCA · Enterprise Network Configuration Compliance Auditor · Compliance v2.1 · Risk v1.0")
        canvas.drawRightString(192 * mm, 9 * mm, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(
        str(output_path), pagesize=A4, rightMargin=18 * mm, leftMargin=18 * mm,
        topMargin=16 * mm, bottomMargin=18 * mm,
        title=f"ENCCA Audit Report - {hostname}", author="ENCCA"
    )
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return output_path
