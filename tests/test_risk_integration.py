import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from parser.cisco_parser import parse_cisco_config
from audit.compliance_engine import audit_configuration, load_rules
from scoring.risk_engine import assess_findings


def test_parser_v2_risk():
    sample = ROOT / "tests/sample_configs/parser_v2_sample.txt"
    findings = audit_configuration(parse_cisco_config(sample))
    rules = {r["id"]: r for r in load_rules()}
    risk = assess_findings(findings, rules)

    assert len(findings) == 39
    assert sum(f["status"] == "FAIL" for f in findings) == 2
    assert risk["summary"]["failed_weight"] == 3
    assert risk["summary"]["applicable_weight"] == 87
    assert risk["summary"]["risk_percentage"] == 3.45
    assert risk["summary"]["security_score"] == 96.55
    assert risk["summary"]["risk_level"] == "Low"
    assert [x["rule_id"] for x in risk["prioritized_findings"]] == ["STORM-001", "STORM-002"]


if __name__ == "__main__":
    test_parser_v2_risk()
    print("Risk integration test PASSED")
