import pytest

from conftest import NMAP_FIXTURES
from portgoblin.core import preflight
from portgoblin.core.engine import Mode, ScanOptions
from portgoblin.core.nmap_parser import parse_file, parse_xml_text
from portgoblin.core.targets import build_target_set


def test_root_check(monkeypatch):
    monkeypatch.setattr(preflight.os, "geteuid", lambda: 1000)
    assert preflight.is_root() is False
    monkeypatch.setattr(preflight.os, "geteuid", lambda: 0)
    assert preflight.is_root() is True


@pytest.mark.parametrize(
    ("answer", "expected"),
    [("y", True), ("YES", True), ("", False), ("n", False), ("maybe", False)],
)
def test_confirm_blocks_until_yes(answer, expected):
    assert preflight.confirm(False, lambda _: answer) is expected


def test_confirm_eof_is_no():
    def eof(_):
        raise EOFError

    assert preflight.confirm(False, eof) is False


def test_assume_yes_skips_prompt():
    def never(_):
        raise AssertionError("should not ask")

    assert preflight.confirm(True, never) is True


def test_estimate_tcp_worst_case():
    opts = ScanOptions(mode=Mode.EXTERNAL, rate=100, top_udp=200, udp=False)
    est = preflight.estimate(256, opts, udp_parallel=True)
    assert est.tcp_seconds == pytest.approx(256 * 65535 / 100)
    assert preflight.format_duration(est.total_seconds) == "1d 22h"


def test_estimate_parallel_udp_only_adds_overflow():
    opts = ScanOptions(mode=Mode.INTERNAL, rate=300, top_udp=200)
    parallel = preflight.estimate(10, opts, udp_parallel=True)
    sequential = preflight.estimate(10, opts, udp_parallel=False)
    assert parallel.udp_seconds == 0
    assert sequential.udp_seconds == 200


def test_external_hostname_scope_warning(fake_resolver):
    ts = build_target_set(["web.example.test"], [], 65536, fake_resolver)
    plan = preflight.build_plan(
        ts, ScanOptions(mode=Mode.EXTERNAL, rate=100, top_udp=200), [], True
    )
    assert "10.0.0.10, 10.0.0.11" in plan.warnings[0]


def test_reachability_tries_up_to_five_hosts():
    hosts = "".join(
        f'<host><status state="up" reason="syn-ack"/><address addr="10.0.0.{i}" addrtype="ipv4"/>'
        f'<ports><port protocol="tcp" portid="22"><state state="open"/></port></ports></host>'
        for i in range(1, 9)
    )
    result = parse_xml_text(f'<nmaprun version="7.94SVN">{hosts}</nmaprun>')
    tried = []

    def unreachable(host, port, timeout):
        tried.append((host, port))
        return False

    ok, attempts = preflight.check_reachability(result, 1, unreachable)
    assert ok is False
    assert len(tried) == 5 and len(attempts) == 5


def test_reachability_true_if_any_host_answers():
    result = parse_file(NMAP_FIXTURES / "services_mixed.xml")
    ok, attempts = preflight.check_reachability(result, 1, lambda h, p, t: True)
    assert ok is True and attempts == [("10.0.0.20", 21, True)]


def test_reachability_with_udp_only_import_has_nothing_to_try():
    result = parse_file(NMAP_FIXTURES / "udp.xml")
    ok, attempts = preflight.check_reachability(result, 1, lambda h, p, t: True)
    assert ok is False and attempts == []


def test_searchsploit_version_from_header(tmp_path):
    script = tmp_path / "searchsploit"
    script.write_text("#!/usr/bin/env bash\n#    Version: 4.2.1 (2022-11-11)\n")
    assert preflight.searchsploit_version(str(script)) == "4.2.1"


def test_missing_tools_listed(monkeypatch):
    monkeypatch.setattr(preflight.shutil, "which", lambda name: None)
    monkeypatch.setattr(preflight, "find_msf_metadata", lambda: None)
    tools = preflight.detect_tools()
    assert all(not t.found for t in tools)
    assert {t.name for t in tools} == {
        "nmap",
        "searchsploit",
        "Metasploit metadata",
        "netexec",
        "smbclient",
    }
    assert all(t.install.startswith("sudo apt install") for t in tools)
