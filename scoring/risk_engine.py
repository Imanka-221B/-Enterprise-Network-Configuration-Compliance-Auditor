"""Deterministic Risk Assessment Engine v1 for ENCCA.

The Compliance Engine remains authoritative for PASS/FAIL decisions.
This module converts applicable compliance findings into a weighted risk
posture using the project's Critical/High/Medium/Low severity model.
"""
from typing import Any, Dict, Iterable, List

SEVERITY_WEIGHTS = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}


def classify_risk(risk_percentage: float) -> str:
    if risk_percentage > 50:
        return "Critical"
    if risk_percentage > 25:
        return "High"
    if risk_percentage > 10:
        return "Medium"
    return "Low"


def _severity(value: Any) -> str:
    text = str(value or "").strip().title()
    return text if text in SEVERITY_WEIGHTS else ""


def assess_findings(findings: Iterable[Dict[str, Any]], rule_catalogue: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Assess Compliance Engine findings using the authoritative rule catalogue.

    The UI may intentionally display '-' for severity on PASS rows. For risk
    calculation, the rule catalogue supplies the severity for both PASS and
    FAIL rows, preventing the denominator from being artificially reduced.
    """
    applicable = 0
    failed_weight = 0
    rows: List[Dict[str, Any]] = []

    for finding in findings:
        status = str(finding.get("status", "")).upper()
        if status in {"NOT_APPLICABLE", "N/A", "NA"}:
            continue

        rule = rule_catalogue.get(finding.get("rule_id"), {})
        severity = _severity(rule.get("severity")) or _severity(finding.get("severity"))
        weight = SEVERITY_WEIGHTS.get(severity, 0)
        if weight == 0:
            continue

        applicable += weight
        if status == "FAIL":
            failed_weight += weight
            rows.append({
                "rule_id": finding.get("rule_id", ""),
                "category": finding.get("category", ""),
                "check": finding.get("title", ""),
                "target": finding.get("target", "Global"),
                "severity": severity,
                "weight": weight,
                "evidence": finding.get("evidence", ""),
                "recommendation": finding.get("recommendation", ""),
                "remediation": finding.get("remediation", ""),
                "reference": finding.get("reference", ""),
            })

    risk_percentage = round((failed_weight / applicable) * 100, 2) if applicable else 0.0
    security_score = round(100 - risk_percentage, 2)

    for row in rows:
        row["risk_contribution"] = round((row["weight"] / failed_weight) * risk_percentage, 2) if failed_weight else 0.0

    rows.sort(key=lambda x: (-x["weight"], x["rule_id"], x["target"]))
    severity_counts = {name: 0 for name in SEVERITY_WEIGHTS}
    for row in rows:
        severity_counts[row["severity"]] += 1

    return {
        "engine": "Risk Assessment Engine",
        "version": "1.0",
        "summary": {
            "applicable_weight": applicable,
            "failed_weight": failed_weight,
            "risk_percentage": risk_percentage,
            "security_score": security_score,
            "risk_level": classify_risk(risk_percentage),
            "failed_count": len(rows),
            "severity_counts": severity_counts,
        },
        "prioritized_findings": rows,
        "scoring_model": {
            "severity_weights": SEVERITY_WEIGHTS,
            "risk_formula": "Failed Severity Weight / Applicable Severity Weight × 100",
            "security_score_formula": "100 - Risk Percentage",
            "thresholds": {
                "Low": "0-10%",
                "Medium": ">10-25%",
                "High": ">25-50%",
                "Critical": ">50-100%",
            },
        },
    }
