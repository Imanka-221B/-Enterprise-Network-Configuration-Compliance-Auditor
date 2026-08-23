from pathlib import Path
import re

from reports.audit_report import build_pdf


def test_report_pdf_builds_with_ui_aligned_risk_table(tmp_path):
    audit = {
        "audit_id": "layout-test",
        "filename": "sample.cfg",
        "data": {"hostname": "BRANCH-SW01"},
        "audit_time": "23 Aug 2026, 14:12",
        "summary": {
            "compliance_score": 94.87,
            "passed": 37,
            "failed": 2,
            "total": 39,
        },
        "risk": {
            "summary": {
                "security_score": 96.55,
                "risk_percentage": 3.45,
                "risk_level": "Low",
                "failed_count": 2,
                "severity_counts": {"Critical": 0, "High": 0, "Medium": 1, "Low": 1},
            },
            "prioritized_findings": [
                {
                    "rule_id": "STORM-001",
                    "severity": "Medium",
                    "category": "Layer 2",
                    "target": "GigabitEthernet1/0/2",
                    "evidence": "broadcast storm control = False",
                    "risk_contribution": 2.3,
                    "recommendation": "Configure broadcast storm control.",
                },
                {
                    "rule_id": "STORM-002",
                    "severity": "Low",
                    "category": "Layer 2",
                    "target": "GigabitEthernet1/0/2",
                    "evidence": "multicast storm control = False",
                    "risk_contribution": 1.15,
                    "recommendation": "Configure multicast storm control.",
                },
            ],
        },
        "statistics": {
            "compliance": {"applicable": 39, "passed": 37, "failed": 2, "not_applicable": 0},
            "risk": {"critical": 0, "high": 0, "medium": 1, "low": 1},
            "interfaces": {"total": 6, "access": 2, "trunk": 1, "unused": 2},
        },
        "category_risk": {
            "Layer 2": {"count": 2, "weight": 3, "contribution": 100.0}
        },
        "findings": [
            {
                "rule_id": "STORM-001", "category": "Layer 2",
                "title": "Broadcast storm control on active access ports",
                "target": "GigabitEthernet1/0/2", "status": "FAIL",
                "severity": "Medium", "evidence": "broadcast storm control = False",
                "expected": "Broadcast storm control configured.",
                "recommendation": "Configure broadcast storm control.",
                "remediation": "storm-control broadcast level 1.00 0.50",
                "reference": "Project Layer-2 Security Baseline",
            },
            {
                "rule_id": "STORM-002", "category": "Layer 2",
                "title": "Multicast storm control on active access ports",
                "target": "GigabitEthernet1/0/2", "status": "FAIL",
                "severity": "Low", "evidence": "multicast storm control = False",
                "expected": "Multicast storm control configured.",
                "recommendation": "Configure multicast storm control.",
                "remediation": "storm-control multicast level 1.00 0.50",
                "reference": "Project Layer-2 Security Baseline",
            },
        ],
    }
    output = tmp_path / "report.pdf"
    build_pdf(audit, output)
    assert output.exists()
    assert output.stat().st_size > 0
