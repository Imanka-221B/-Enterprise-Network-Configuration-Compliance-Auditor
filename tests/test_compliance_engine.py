import sys
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from parser.cisco_parser import parse_cisco_config
from audit.compliance_engine import audit_configuration, summarize_findings

SECURE = ROOT / "tests" / "sample_configs" / "parser_v2_sample.txt"
INSECURE = ROOT / "tests" / "sample_configs" / "insecure_config.txt"


def test_secure_configuration_baseline():
    data = parse_cisco_config(SECURE)
    findings = audit_configuration(data)
    summary = summarize_findings(findings)

    assert summary["total"] == 39, summary
    assert summary["passed"] == 37, summary
    assert summary["failed"] == 2, summary
    assert summary["not_applicable"] == 0, summary
    assert summary["compliance_score"] == 94.87, summary

    failed = {(f["rule_id"], f["target"]) for f in findings if f["status"] == "FAIL"}
    assert failed == {
        ("STORM-001", "GigabitEthernet1/0/2"),
        ("STORM-002", "GigabitEthernet1/0/2"),
    }


def test_insecure_configuration_is_fully_failed():
    data = parse_cisco_config(INSECURE)
    findings = audit_configuration(data)
    summary = summarize_findings(findings)

    assert summary["passed"] == 0, summary
    assert summary["failed"] == 38, summary
    assert summary["not_applicable"] == 6, summary
    assert summary["evaluated"] == 44, summary
    assert summary["compliance_score"] == 0.0, summary


def test_rule_applicability_excludes_untrusted_trunk_from_trust_controls():
    data = parse_cisco_config(SECURE)
    data = deepcopy(data)
    data["interfaces"].append({
        "name": "GigabitEthernet1/1/2",
        "description": "TRUNK-TO-ACCESS-SWITCH",
        "role": "trunk",
        "shutdown": False,
        "mode": "trunk",
        "access_vlan": None,
        "voice_vlan": None,
        "native_vlan": "999",
        "allowed_vlans": "10,20,30,40,99",
        "port_security": False,
        "port_security_maximum": None,
        "port_security_violation": None,
        "portfast": False,
        "bpdu_guard": False,
        "storm_control": {"broadcast": False, "multicast": False, "unicast": False},
        "dhcp_snooping_trust": False,
        "dhcp_snooping_rate_limit": None,
        "arp_inspection_trust": False,
        "ip_source_guard": False,
        "cdp_enabled": True,
        "lldp_enabled": False,
    })

    findings = audit_configuration(data)
    target_findings = [f for f in findings if f["target"] == "GigabitEthernet1/1/2"]
    ids = {f["rule_id"]: f for f in target_findings}

    assert ids["TRK-001"]["status"] == "PASS"
    assert ids["TRK-002"]["status"] == "PASS"
    assert ids["TRK-003"]["status"] == "NOT_APPLICABLE"
    assert ids["TRK-004"]["status"] == "NOT_APPLICABLE"


def test_interface_roles_are_parsed_from_context():
    data = parse_cisco_config(SECURE)
    roles = {i["name"]: i["role"] for i in data["interfaces"]}

    assert roles["GigabitEthernet1/0/1"] == "access_port"
    assert roles["GigabitEthernet1/1/1"] == "approved_uplink"
    assert roles["GigabitEthernet1/0/23"] == "unused_port"


if __name__ == "__main__":
    test_secure_configuration_baseline()
    test_insecure_configuration_is_fully_failed()
    test_rule_applicability_excludes_untrusted_trunk_from_trust_controls()
    test_interface_roles_are_parsed_from_context()
    print("Compliance Engine v2.1 tests PASSED")
