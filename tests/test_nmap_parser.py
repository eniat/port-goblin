import pytest

from conftest import NMAP_FIXTURES
from portgoblin.core.models import Host, Port, ScanResult, Service
from portgoblin.core.nmap_parser import (
    NmapParseError,
    is_complete,
    parse_file,
    parse_many,
    parse_xml_text,
    repair_truncated,
)


def test_real_tcp_service_scan():
    result = parse_file(NMAP_FIXTURES / "tcp_svc_real.xml")
    host = result.hosts["127.0.0.1"]
    assert result.nmap_versions == ["7.94SVN"]
    assert host.status == "up" and host.hostnames == ["localhost"]
    ports = {p.portid: p for p in host.ports}
    assert ports[8080].service.product == "SimpleHTTPServer"
    assert ports[8080].service.cpes == ["cpe:/a:python:simplehttpserver:0.6"]
    assert ports[8080].service.tunnel is None
    assert ports[8443].service.tunnel == "ssl"
    assert any(s.script_id == "ssl-cert" for s in ports[8443].scripts)


def test_real_discovery():
    result = parse_file(NMAP_FIXTURES / "discovery_real.xml")
    assert [h.address for h in result.live_hosts()] == ["127.0.0.1", "127.0.0.2", "127.0.0.3"]


def test_udp_open_and_open_filtered_kept_apart():
    result = parse_file(NMAP_FIXTURES / "udp.xml")
    assert result.count_ports("udp", "open") == 2
    assert result.count_ports("udp", "open|filtered") == 3
    host = result.hosts["10.0.0.5"]
    assert [p.portid for p in host.ports_in_state("udp", "open")] == [53, 161]
    assert [p.portid for p in host.ports_in_state("udp", "closed")] == [623]


def test_pn_hosts_without_open_ports_are_not_live():
    result = parse_file(NMAP_FIXTURES / "udp.xml")
    # 10.0.0.6 is only "up" because of -Pn (user-set) and has no confirmed open port.
    assert [h.address for h in result.live_hosts()] == ["10.0.0.5"]


def test_missing_versions_and_multiple_cpes():
    result = parse_file(NMAP_FIXTURES / "services_mixed.xml")
    host = result.hosts["10.0.0.20"]
    ports = {p.portid: p for p in host.ports}
    assert ports[21].service.product is None and ports[21].service.version is None
    assert ports[21].service.cpes == []
    assert ports[9999].service is None
    assert ports[80].service.cpes == [
        "cpe:/a:microsoft:internet_information_services:10.0",
        "cpe:/o:microsoft:windows",
    ]
    assert host.user_hostnames == ["files.example.test"]
    assert host.mac == "00:11:22:33:44:55"
    assert host.scripts[0].script_id == "smb2-security-mode"


def test_old_nmap_version():
    result = parse_file(NMAP_FIXTURES / "old_nmap.xml")
    host = result.hosts["192.168.1.10"]
    assert result.nmap_versions == ["5.21"]
    assert host.status_reason == "arp-response"
    ports = {p.portid: p for p in host.ports}
    assert ports[21].service.product == "vsftpd" and ports[21].service.version == "2.3.4"
    assert ports[21].service.cpes == []


def test_malformed_xml():
    with pytest.raises(NmapParseError, match="could not parse nmap output"):
        parse_file(NMAP_FIXTURES / "malformed.xml")


def test_entity_expansion_refused():
    with pytest.raises(NmapParseError):
        parse_file(NMAP_FIXTURES / "entity_attack.xml")


def test_not_nmap_xml():
    with pytest.raises(NmapParseError, match="not an nmap XML file"):
        parse_file(NMAP_FIXTURES / "not_nmap.xml")


def test_missing_file():
    with pytest.raises(NmapParseError, match="could not read"):
        parse_file(NMAP_FIXTURES / "nope.xml")


def test_real_truncated_file_needs_tolerant_mode():
    path = NMAP_FIXTURES / "truncated_real.xml"
    assert not is_complete(path)
    with pytest.raises(NmapParseError):
        parse_file(path)
    result = parse_file(path, tolerant=True)
    assert len(result.hosts) == 2


def test_repair_drops_partial_host():
    text = (
        '<nmaprun version="7.94SVN"><host><status state="up" reason="x"/>'
        '<address addr="10.0.0.1" addrtype="ipv4"/></host><host><status state="up"'
    )
    repaired = repair_truncated(text)
    assert parse_xml_text(repaired).hosts.keys() == {"10.0.0.1"}
    assert repair_truncated("<nmaprun></nmaprun>") is None


def test_parse_many_records_failures():
    result = parse_many([NMAP_FIXTURES / "udp.xml", NMAP_FIXTURES / "malformed.xml"])
    assert "10.0.0.5" in result.hosts
    assert len(result.parse_errors) == 1


def test_merge_prefers_detailed_port_and_real_status():
    bare = ScanResult(
        hosts={
            "10.0.0.1": Host(
                address="10.0.0.1",
                status="up",
                status_reason="user-set",
                ports=[Port(protocol="tcp", portid=22, state="open")],
            )
        }
    )
    detailed = ScanResult(
        hosts={
            "10.0.0.1": Host(
                address="10.0.0.1",
                status="up",
                status_reason="syn-ack",
                ports=[
                    Port(
                        protocol="tcp",
                        portid=22,
                        state="open",
                        service=Service(name="ssh", product="OpenSSH", method="probed"),
                    )
                ],
            )
        }
    )
    bare.merge(detailed)
    host = bare.hosts["10.0.0.1"]
    assert host.status_reason == "syn-ack"
    assert host.ports[0].service.product == "OpenSSH"
    # A later scan with less detail does not overwrite the better record.
    bare.merge(
        ScanResult(
            hosts={
                "10.0.0.1": Host(
                    address="10.0.0.1", ports=[Port(protocol="tcp", portid=22, state="open")]
                )
            }
        )
    )
    assert bare.hosts["10.0.0.1"].ports[0].service.product == "OpenSSH"
