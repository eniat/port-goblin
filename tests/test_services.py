from conftest import NMAP_FIXTURES
from portgoblin.analysis.services import group_services, open_filtered_udp
from portgoblin.core.nmap_parser import parse_file, parse_many


def groups_by_name(groups):
    return {g.name: g.entries for g in groups}


def test_grouping_and_urls():
    result = parse_file(NMAP_FIXTURES / "services_mixed.xml")
    groups = groups_by_name(group_services(result))
    assert groups["SMB"] == ["10.0.0.20:445"]
    assert groups["RDP"] == ["10.0.0.20:3389"]
    assert groups["SSH"] == ["10.0.0.20:22"]
    assert groups["File sharing"] == ["10.0.0.20:21"]
    assert groups["RPC"] == ["10.0.0.20:135"]
    # The nmap XML records the tester's hostname (type user), so URLs use it.
    assert groups["Web"] == [
        "http://files.example.test",
        "https://files.example.test",
        "https://files.example.test:8443",
    ]
    assert groups["Other (unidentified)"] == ["10.0.0.20:9999"]
    # Filtered ports are never listed.
    assert all("8080" not in e for entries in groups.values() for e in entries)


def test_web_uses_ip_without_hostname_and_tls_from_tunnel():
    result = parse_file(NMAP_FIXTURES / "tcp_svc_real.xml")
    groups = groups_by_name(group_services(result))
    assert groups["Web"] == ["http://127.0.0.1:8080", "https://127.0.0.1:8443"]


def test_scan_hostname_map_wins():
    result = parse_file(NMAP_FIXTURES / "tcp_svc_real.xml")
    groups = groups_by_name(group_services(result, {"127.0.0.1": ["app.example.test"]}))
    assert groups["Web"][0] == "http://app.example.test:8080"


def test_only_confirmed_open_udp_in_service_lists():
    result = parse_file(NMAP_FIXTURES / "udp.xml")
    groups = groups_by_name(group_services(result))
    assert groups["DNS"] == ["10.0.0.5:53/udp"]
    assert groups["SNMP"] == ["10.0.0.5:161/udp"]
    assert "VPN" not in groups and "File sharing" not in groups
    assert open_filtered_udp(result) == ["10.0.0.5:123/udp", "10.0.0.5:500/udp", "10.0.0.6:69/udp"]


def test_display_order_is_stable():
    result = parse_many([NMAP_FIXTURES / "services_mixed.xml", NMAP_FIXTURES / "udp.xml"])
    names = [g.name for g in group_services(result)]
    assert names.index("SMB") < names.index("Web") < names.index("DNS")
    assert names[-1].startswith("Other")
