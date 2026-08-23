from parser.cisco_parser import parse_cisco_config

def test_vlan_parsing():
    data = parse_cisco_config("tests/sample_configs/parser_v2_sample.txt")
    expected = {
        10: "INFRA",
        20: "MANAGER",
        30: "USER",
        40: "VOICE",
        99: "MANAGEMENT",
        999: "UNUSED-NATIVE",
    }

    actual = {v["id"]: v["name"] for v in data["vlans"]}
    assert actual == expected, f"Unexpected VLAN result: {actual}"

if __name__ == "__main__":
    test_vlan_parsing()
    print("VLAN parser test PASSED")
