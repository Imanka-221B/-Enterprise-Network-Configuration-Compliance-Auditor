import json
from pathlib import Path


STATUS_PASS = "PASS"
STATUS_FAIL = "FAIL"
STATUS_NA = "NOT_APPLICABLE"


def load_rules():
    return json.loads(
        (Path(__file__).resolve().parents[1] / "rules" / "rules.json").read_text(
            encoding="utf-8"
        )
    )


def rule_map():
    return {r["id"]: r for r in load_rules()}


def finding(rule, passed, evidence, target="Global", status=None, applicability=None):
    if status is None:
        status = STATUS_PASS if passed else STATUS_FAIL

    is_pass = status == STATUS_PASS
    is_na = status == STATUS_NA

    return {
        "rule_id": rule["id"],
        "category": rule["category"],
        "title": rule["title"],
        "target": target,
        "status": status,
        "severity": "-" if (is_pass or is_na) else rule["severity"],
        "evidence": evidence,
        "expected": rule["expected"],
        "recommendation": (
            "No action required." if is_pass
            else "Not applicable to this target." if is_na
            else rule["recommendation"]
        ),
        "remediation": "" if (is_pass or is_na) else rule.get("remediation", ""),
        "reference": rule.get("reference", ""),
        "applicability": applicability or rule.get("applicability", ""),
    }


def _scope_applies(rule, interface=None):
    """Centralized rule applicability logic.

    This prevents controls from being evaluated against targets where the
    control has no security meaning. In particular, DHCP Snooping/DAI trust
    rules apply only to interfaces classified as approved uplinks.
    """
    scope = rule.get("scope", "global")

    if scope == "global":
        return True
    if interface is None:
        return False
    if scope == "vty":
        return False
    if scope == "access_port":
        return interface.get("mode") == "access" and not interface.get("shutdown")
    if scope == "access_port_dhcp":
        return (
            interface.get("mode") == "access"
            and not interface.get("shutdown")
            and bool(interface.get("dhcp_snooping_rate_limit"))
        )
    if scope == "port_security":
        return (
            interface.get("mode") == "access"
            and not interface.get("shutdown")
            and bool(interface.get("port_security"))
        )
    if scope == "trunk":
        return interface.get("mode") == "trunk"
    if scope == "approved_uplink":
        return interface.get("role") == "approved_uplink"
    if scope == "unused_port":
        return "unused" in (interface.get("description") or "").lower()
    return True


def _add_interface_finding(out, rules, rid, interface, ok, evidence, status=None):
    rule = rules[rid]
    if not _scope_applies(rule, interface):
        out.append(
            finding(
                rule,
                False,
                evidence,
                interface["name"],
                status=STATUS_NA,
                applicability=rule.get("applicability"),
            )
        )
        return
    out.append(
        finding(
            rule,
            ok,
            evidence,
            interface["name"],
            status=status,
            applicability=rule.get("applicability"),
        )
    )


def audit_configuration(data):
    rules = rule_map()
    out = []
    g = data["global_security"]
    vtys = data["vty_lines"]
    ints = data["interfaces"]

    checks = [
        ("SSH-001", g.get("ssh_configured", False), f'SSH configured = {g.get("ssh_configured", False)}'),
        ("SSH-002", g.get("ssh_version") == 2, f'SSH version = {g.get("ssh_version")}'),
        ("SSH-003", g.get("ssh_auth_retries") is not None, f'SSH authentication retries = {g.get("ssh_auth_retries")}'),
        ("SSH-004", g.get("ssh_timeout") is not None, f'SSH timeout = {g.get("ssh_timeout")}'),
        ("TEL-001", not data["telnet"]["enabled"], f'Telnet allowed = {data["telnet"]["enabled"]}'),
        ("AAA-001", g["aaa_new_model"], f'aaa new-model = {g["aaa_new_model"]}'),
        ("AAA-002", any((u.get("privilege") or 0) >= 15 for u in g["users"]), f'Local users = {g["users"]}'),
        ("PWD-001", g["enable_secret_present"], f'enable secret present = {g["enable_secret_present"]}'),
        ("MGMT-001", bool(vtys) and all(v["access_class"] for v in vtys), f'VTY access classes = {[v["access_class"] for v in vtys]}'),
        ("MGMT-002", not g["http_server"], f'HTTP server enabled = {g["http_server"]}'),
        ("MGMT-003", any(x.get("ip_address") and not x.get("shutdown") for x in g.get("management_svis", [])), f'Management SVIs = {g.get("management_svis", [])}'),
        ("SNMP-001", (not g["snmp_configured"]) or g["snmp_version"] == "v3", f'SNMP configured = {g["snmp_configured"]}; version = {g["snmp_version"]}'),
        ("SNMP-002", not g["insecure_snmp_community"], f'Insecure community detected = {g["insecure_snmp_community"]}'),
        ("LOG-001", g["logging_configured"], f'Logging servers = {g["syslog_servers"]}'),
        ("NTP-001", g["ntp_configured"], f'NTP servers = {g["ntp_servers"]}'),
        ("DHCP-001", g["dhcp_snooping_enabled"] and bool(g["dhcp_snooping_vlans"]), f'enabled = {g["dhcp_snooping_enabled"]}; VLANs = {g["dhcp_snooping_vlans"]}'),
        ("DAI-001", bool(g["arp_inspection_vlans"]), f'DAI VLANs = {g["arp_inspection_vlans"]}'),
    ]

    for rid, ok, evidence in checks:
        out.append(finding(rules[rid], ok, evidence))

    for n, v in enumerate(vtys or [], 1):
        t = v.get("exec_timeout")
        ok = False
        if t:
            try:
                a, b = t.split()
                ok = int(a) > 0 or int(b) > 0
            except (ValueError, AttributeError):
                ok = False
        out.append(finding(rules["VTY-001"], ok, f'exec-timeout = {t}', f"VTY block {n}"))

    for i in ints:
        if i["mode"] == "access" and not i["shutdown"]:
            target = i["name"]
            _add_interface_finding(out, rules, "L2-001", i, i["port_security"], f'port_security = {i["port_security"]}')
            _add_interface_finding(
                out,
                rules,
                "L2-002",
                i,
                i["port_security_maximum"] is not None,
                f'port-security maximum = {i["port_security_maximum"]}',
            )
            _add_interface_finding(
                out,
                rules,
                "L2-003",
                i,
                (i["port_security_violation"] or "").lower() in {"restrict", "protect", "shutdown"},
                f'violation mode = {i["port_security_violation"]}',
            )
            _add_interface_finding(out, rules, "STP-001", i, i["portfast"], f'PortFast = {i["portfast"]}')
            _add_interface_finding(out, rules, "STP-002", i, i["bpdu_guard"], f'BPDU Guard = {i["bpdu_guard"]}')
            _add_interface_finding(out, rules, "STORM-001", i, i["storm_control"]["broadcast"], f'broadcast storm control = {i["storm_control"]["broadcast"]}')
            _add_interface_finding(out, rules, "STORM-002", i, i["storm_control"]["multicast"], f'multicast storm control = {i["storm_control"]["multicast"]}')

            if i["dhcp_snooping_rate_limit"]:
                _add_interface_finding(
                    out,
                    rules,
                    "IPSG-001",
                    i,
                    i["ip_source_guard"],
                    f'IP Source Guard = {i["ip_source_guard"]}; DHCP rate limit = {i["dhcp_snooping_rate_limit"]}',
                )

    for i in ints:
        if i["mode"] == "trunk":
            _add_interface_finding(out, rules, "TRK-001", i, bool(i["allowed_vlans"]), f'allowed VLANs = {i["allowed_vlans"]}')
            _add_interface_finding(out, rules, "TRK-002", i, i["native_vlan"] is not None and str(i["native_vlan"]) != "1", f'native VLAN = {i["native_vlan"]}')
            _add_interface_finding(out, rules, "TRK-003", i, i["dhcp_snooping_trust"], f'DHCP Snooping trust = {i["dhcp_snooping_trust"]}')
            _add_interface_finding(out, rules, "TRK-004", i, i["arp_inspection_trust"], f'DAI trust = {i["arp_inspection_trust"]}')

    for i in ints:
        if "unused" in (i["description"] or "").lower():
            _add_interface_finding(out, rules, "INT-001", i, i["shutdown"], f'description = {i["description"]}; shutdown = {i["shutdown"]}')

    return out


def summarize_findings(findings):
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    category_counts = {}
    passed = failed = not_applicable = 0

    for f in findings:
        category_counts.setdefault(f["category"], {"passed": 0, "failed": 0, "not_applicable": 0})
        status = f["status"]
        if status == STATUS_PASS:
            passed += 1
            category_counts[f["category"]]["passed"] += 1
        elif status == STATUS_FAIL:
            failed += 1
            severity_counts[f["severity"]] += 1
            category_counts[f["category"]]["failed"] += 1
        elif status == STATUS_NA:
            not_applicable += 1
            category_counts[f["category"]]["not_applicable"] += 1

    applicable = passed + failed
    score = round((passed / applicable) * 100, 2) if applicable else 100.0

    return {
        "total": applicable,
        "evaluated": len(findings),
        "passed": passed,
        "failed": failed,
        "not_applicable": not_applicable,
        "compliance_score": score,
        "severity_counts": severity_counts,
        "category_counts": category_counts,
    }
