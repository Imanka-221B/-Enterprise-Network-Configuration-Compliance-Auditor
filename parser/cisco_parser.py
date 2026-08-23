from pathlib import Path
import re


def _interface_blocks(text):
    """Return (interface_name, block_text) pairs for Cisco interface sections."""
    pattern = r"(?ms)^interface\s+(\S+)\s*\n(.*?)(?=^interface\s+|\Z)"
    return [(name, block) for name, block in re.findall(pattern, text)]


def _parse_interfaces(text):
    interfaces = []

    for name, block in _interface_blocks(text):
        def has(pattern):
            return bool(re.search(pattern, block, re.MULTILINE | re.IGNORECASE))

        def one(pattern):
            m = re.search(pattern, block, re.MULTILINE | re.IGNORECASE)
            return m.group(1) if m else None

        mode = "trunk" if has(r"^\s*switchport\s+mode\s+trunk\b") else (
            "access" if has(r"^\s*switchport\s+mode\s+access\b") else "unknown"
        )

        allowed = one(r"^\s*switchport\s+trunk\s+allowed\s+vlan\s+(.+)$")
        access_vlan = one(r"^\s*switchport\s+access\s+vlan\s+(\S+)")
        voice_vlan = one(r"^\s*switchport\s+voice\s+vlan\s+(\S+)")
        native_vlan = one(r"^\s*switchport\s+trunk\s+native\s+vlan\s+(\S+)")

        port_security_max = one(
            r"^\s*switchport\s+port-security\s+maximum\s+(\d+)"
        )
        violation = one(
            r"^\s*switchport\s+port-security\s+violation\s+(\S+)"
        )

        description = one(r"^\s*description\s+(.+)$")
        description_upper = (description or "").upper()

        # Interface role is derived from explicit configuration context rather
        # than assuming that every trunk is a trusted uplink. The role is used
        # by compliance-rule applicability checks.
        if "UNUSED" in description_upper:
            role = "unused_port"
        elif mode == "trunk" and "UPLINK" in description_upper:
            role = "approved_uplink"
        elif mode == "trunk":
            role = "trunk"
        elif mode == "access":
            role = "access_port"
        else:
            role = "unknown"

        interfaces.append({
            "name": name,
            "description": description,
            "role": role,
            "shutdown": has(r"^\s*shutdown\s*$"),
            "mode": mode,
            "access_vlan": access_vlan,
            "voice_vlan": voice_vlan,
            "native_vlan": native_vlan,
            "allowed_vlans": allowed.strip() if allowed else None,
            "port_security": has(r"^\s*switchport\s+port-security\s*$"),
            "port_security_maximum": int(port_security_max) if port_security_max else None,
            "port_security_violation": violation,
            "portfast": has(r"^\s*spanning-tree\s+portfast\b"),
            "bpdu_guard": has(r"^\s*spanning-tree\s+bpduguard\s+enable\b"),
            "storm_control": {
                "broadcast": has(r"^\s*storm-control\s+broadcast\b"),
                "multicast": has(r"^\s*storm-control\s+multicast\b"),
                "unicast": has(r"^\s*storm-control\s+unicast\b")
            },
            "dhcp_snooping_trust": has(r"^\s*ip\s+dhcp\s+snooping\s+trust\b"),
            "dhcp_snooping_rate_limit": one(
                r"^\s*ip\s+dhcp\s+snooping\s+limit\s+rate\s+(\d+)"
            ),
            "arp_inspection_trust": has(r"^\s*ip\s+arp\s+inspection\s+trust\b"),
            "ip_source_guard": has(r"^\s*ip\s+verify\s+source\b"),
            "cdp_enabled": not has(r"^\s*no\s+cdp\s+enable\b"),
            "lldp_enabled": has(r"^\s*lldp\s+(transmit|receive)\b")
        })

    return interfaces


def _parse_vlans(text):
    """Parse Cisco VLAN configuration blocks safely.

    Important: do not use a greedy DOTALL pattern here because Cisco
    configuration sections continue until the next top-level command.
    A VLAN name belongs only to the immediate indented `name` line
    following the VLAN declaration.
    """
    vlans = []
    lines = text.splitlines()

    for index, raw_line in enumerate(lines):
        vlan_match = re.match(r"^vlan\s+(\d+)\s*$", raw_line.strip(), re.IGNORECASE)
        if not vlan_match:
            continue

        vlan_id = int(vlan_match.group(1))
        vlan_name = None

        # Only inspect the immediately following indented configuration
        # line(s), and stop as soon as the next top-level command begins.
        j = index + 1
        while j < len(lines):
            line = lines[j]

            if not line.strip():
                j += 1
                continue

            # A non-indented line starts a new top-level configuration
            # section/command, so this VLAN block is finished.
            if not line[0].isspace():
                break

            name_match = re.match(r"^\s+name\s+(.+?)\s*$", line, re.IGNORECASE)
            if name_match:
                vlan_name = name_match.group(1)
                break

            j += 1

        vlans.append({
            "id": vlan_id,
            "name": vlan_name
        })

    return vlans


def _parse_global_security(text):
    def has(pattern):
        return bool(re.search(pattern, text, re.MULTILINE | re.IGNORECASE))

    def one(pattern):
        m = re.search(pattern, text, re.MULTILINE | re.IGNORECASE)
        return m.group(1) if m else None

    users = []
    for username, privilege in re.findall(
        r"^\s*username\s+(\S+)(?:\s+privilege\s+(\d+))?",
        text,
        re.MULTILINE
    ):
        users.append({
            "username": username,
            "privilege": int(privilege) if privilege else None
        })

    syslog_servers = re.findall(
        r"^\s*logging\s+host\s+(\S+)",
        text,
        re.MULTILINE
    )
    ntp_servers = re.findall(
        r"^\s*ntp\s+server\s+(\S+)",
        text,
        re.MULTILINE
    )

    communities = re.findall(
        r"^\s*snmp-server\s+community\s+(\S+)",
        text,
        re.MULTILINE | re.IGNORECASE
    )

    snmp_v3_users = re.findall(
        r"^\s*snmp-server\s+user\s+(\S+)\s+\S+\s+v3\b",
        text,
        re.MULTILINE | re.IGNORECASE
    )

    # Management SVI information.
    management_svis = []
    for name, block in _interface_blocks(text):
        if not name.lower().startswith("vlan"):
            continue
        ip = one_from_block(block, r"^\s*ip\s+address\s+(\S+\s+\S+)")
        management_svis.append({
            "interface": name,
            "ip_address": ip,
            "shutdown": bool(re.search(r"^\s*shutdown\s*$", block, re.MULTILINE))
        })

    return {
        "aaa_new_model": has(r"^\s*aaa\s+new-model\b"),
        "enable_secret_present": has(r"^\s*enable\s+secret\b"),
        "username_count": len(users),
        "users": users,
        "login_block_for": one(
            r"^\s*login\s+block-for\s+(\d+)\s+attempts\s+(\d+)\s+within\s+(\d+)"
        ),
        "ssh_configured": has(r"^\s*ip\s+ssh\s+\S+"),
        "ssh_version": int(one(r"^\s*ip\s+ssh\s+version\s+(\d+)")) if one(
            r"^\s*ip\s+ssh\s+version\s+(\d+)"
        ) else None,
        "ssh_auth_retries": int(one(r"^\s*ip\s+ssh\s+authentication-retries\s+(\d+)")) if one(
            r"^\s*ip\s+ssh\s+authentication-retries\s+(\d+)"
        ) else None,
        "ssh_timeout": int(one(r"^\s*ip\s+ssh\s+time-out\s+(\d+)")) if one(
            r"^\s*ip\s+ssh\s+time-out\s+(\d+)"
        ) else None,
        "http_server": has(r"^\s*ip\s+http\s+server\b"),
        "https_server": has(r"^\s*ip\s+http\s+secure-server\b"),
        "snmp_communities": communities,
        "snmp_v3_users": snmp_v3_users,
        "snmp_configured": has(r"^\s*snmp-server\b"),
        "snmp_version": "v3" if snmp_v3_users else (
            "v1/v2c" if communities else None
        ),
        "insecure_snmp_community": any(
            c.lower() in {"public", "private"} for c in communities
        ),
        "syslog_servers": syslog_servers,
        "logging_configured": bool(syslog_servers) or has(
            r"^\s*logging\s+(buffered|console|monitor)\b"
        ),
        "ntp_servers": ntp_servers,
        "ntp_configured": bool(ntp_servers),
        "dhcp_snooping_enabled": has(r"^\s*ip\s+dhcp\s+snooping\s*$"),
        "dhcp_snooping_vlans": one(
            r"^\s*ip\s+dhcp\s+snooping\s+vlan\s+(.+)$"
        ),
        "arp_inspection_vlans": one(
            r"^\s*ip\s+arp\s+inspection\s+vlan\s+(.+)$"
        ),
        "ip_routing": has(r"^\s*ip\s+routing\s*$"),
        "default_gateway": one(r"^\s*ip\s+default-gateway\s+(\S+)"),
        "management_svis": management_svis
    }


def one_from_block(block, pattern):
    m = re.search(pattern, block, re.MULTILINE | re.IGNORECASE)
    return m.group(1) if m else None


def _parse_vty(text):
    blocks = re.findall(
        r"(?ms)^line\s+vty\s+.*?(?=^line\s+|\Z)",
        text
    )

    result = []
    for block in blocks:
        transports = []
        for match in re.findall(
            r"^\s*transport\s+input\s+(.+)$",
            block,
            re.MULTILINE | re.IGNORECASE
        ):
            transports.extend(match.strip().split())

        result.append({
            "transport_input": transports,
            "ssh_only": bool(transports) and set(transports) <= {"ssh"},
            "telnet_allowed": "telnet" in transports or "all" in transports,
            "exec_timeout": one_from_block(
                block, r"^\s*exec-timeout\s+(\S+\s+\S+)"
            ),
            "access_class": one_from_block(
                block, r"^\s*access-class\s+(\S+)\s+in"
            ),
            "login_authentication": one_from_block(
                block, r"^\s*login\s+authentication\s+(\S+)"
            )
        })
    return result


def parse_cisco_config(file_path):
    text = Path(file_path).read_text(encoding="utf-8", errors="ignore")
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    hostname_match = re.search(
        r"^\s*hostname\s+(\S+)", text, re.MULTILINE | re.IGNORECASE
    )
    hostname = hostname_match.group(1) if hostname_match else None

    global_security = _parse_global_security(text)
    vtys = _parse_vty(text)
    interfaces = _parse_interfaces(text)
    vlans = _parse_vlans(text)

    return {
        "hostname": hostname,
        "global_security": global_security,
        "vty_lines": vtys,
        "interfaces": interfaces,
        "vlans": vlans,

        # Backward-compatible summary fields used by the v1 UI.
        "ssh": {
            "enabled": global_security["ssh_configured"] or any(
                v["ssh_only"] for v in vtys
            ),
            "version": global_security["ssh_version"]
        },
        "telnet": {
            "enabled": any(v["telnet_allowed"] for v in vtys)
        },
        "aaa": {
            "enabled": global_security["aaa_new_model"]
        },
        "snmp": {
            "configured": global_security["snmp_configured"],
            "version": global_security["snmp_version"],
            "insecure_community": global_security["insecure_snmp_community"]
        },
        "logging": {
            "configured": global_security["logging_configured"],
            "syslog_servers": global_security["syslog_servers"]
        },
        "ntp": {
            "configured": global_security["ntp_configured"],
            "servers": global_security["ntp_servers"]
        }
    }
