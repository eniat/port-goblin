import pytest

from portgoblin.core.targets import (
    TargetError,
    build_target_set,
    chunk_ips,
    parse_target,
    read_target_file,
)

MAX = 65536


def test_single_ip():
    assert parse_target("10.0.0.1", MAX).ips == ["10.0.0.1"]


def test_cidr_excludes_network_and_broadcast():
    ips = parse_target("10.0.0.0/24", MAX).ips
    assert len(ips) == 254
    assert ips[0] == "10.0.0.1" and ips[-1] == "10.0.0.254"


def test_cidr_32_and_31_keep_every_address():
    assert parse_target("10.0.0.7/32", MAX).ips == ["10.0.0.7"]
    assert parse_target("10.0.0.6/31", MAX).ips == ["10.0.0.6", "10.0.0.7"]


def test_last_octet_range():
    assert parse_target("10.0.0.1-5", MAX).ips == [f"10.0.0.{n}" for n in range(1, 6)]


def test_full_range():
    ips = parse_target("10.0.0.250-10.0.1.2", MAX).ips
    assert ips == [
        "10.0.0.250",
        "10.0.0.251",
        "10.0.0.252",
        "10.0.0.253",
        "10.0.0.254",
        "10.0.0.255",
        "10.0.1.0",
        "10.0.1.1",
        "10.0.1.2",
    ]


@pytest.mark.parametrize(
    "bad", ["10.0.0.300", "10.0.0.5-2", "10.0.0", "not a target!", "10.0.0.1-300"]
)
def test_invalid_targets(bad):
    with pytest.raises(TargetError):
        parse_target(bad, MAX)


def test_ipv6_rejected():
    with pytest.raises(TargetError, match="IPv6"):
        parse_target("2001:db8::1", MAX)


def test_max_hosts_enforced():
    with pytest.raises(TargetError, match="over the limit"):
        parse_target("10.0.0.0/8", MAX)


def test_hostname_resolved_once_to_all_ips(fake_resolver):
    calls = []

    def counting(name):
        calls.append(name)
        return fake_resolver(name)

    ts = build_target_set(["web.example.test"], [], MAX, counting)
    assert ts.ips == ["10.0.0.10", "10.0.0.11"]
    assert calls == ["web.example.test"]
    assert ts.hostnames == {"10.0.0.10": ["web.example.test"], "10.0.0.11": ["web.example.test"]}


def test_unresolvable_hostname(fake_resolver):
    with pytest.raises(TargetError, match="resolve"):
        build_target_set(["missing.example.test"], [], MAX, fake_resolver)


def test_exclusions_respected(fake_resolver):
    ts = build_target_set(
        ["10.0.0.0/28", "web.example.test"], ["10.0.0.1-3", "10.0.0.11"], MAX, fake_resolver
    )
    for ip in ("10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.11"):
        assert ip not in ts.ips
    assert "10.0.0.4" in ts.ips and "10.0.0.10" in ts.ips
    assert ts.excluded_count == 4
    assert "10.0.0.11" not in ts.hostnames


def test_everything_excluded_is_an_error():
    with pytest.raises(TargetError, match="No targets left"):
        build_target_set(["10.0.0.1"], ["10.0.0.0/24"], MAX)


def test_duplicates_removed():
    ts = build_target_set(["10.0.0.1", "10.0.0.1-2"], [], MAX)
    assert ts.ips == ["10.0.0.1", "10.0.0.2"]


def test_target_file(tmp_path):
    path = tmp_path / "targets.txt"
    path.write_text("# scope\n10.0.0.1, 10.0.0.2\n\n10.0.1.0/30  # second\n")
    assert read_target_file(path) == ["10.0.0.1", "10.0.0.2", "10.0.1.0/30"]


def test_chunking_by_24():
    ips = ["10.0.1.5", "10.0.0.1", "10.0.0.200", "192.168.1.1", "10.0.1.6"]
    assert chunk_ips(ips, 24) == [
        ["10.0.0.1", "10.0.0.200"],
        ["10.0.1.5", "10.0.1.6"],
        ["192.168.1.1"],
    ]


def test_chunking_large_range_splits_per_24():
    ips = parse_target("10.0.0.0/22", MAX).ips
    chunks = chunk_ips(ips, 24)
    assert len(chunks) == 4
    assert sum(len(c) for c in chunks) == len(ips)
