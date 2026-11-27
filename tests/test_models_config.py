import tomllib

import pytest

from portgoblin.core.config import REPO_CONFIG, Config, ConfigError, load_config
from portgoblin.core.models import Finding, Status, group_findings


def finding(host, fid="SMB-001", status=Status.ISSUE):
    return Finding(
        finding_id=fid,
        check="smb-signing",
        title="SMB signing not required",
        status=status,
        hosts=[host],
        why_it_matters="Allows NTLM relay attacks against these hosts.",
        reproduce=[f"nmap -p445 --script smb2-security-mode {host.split(':')[0]}"],
    )


def test_findings_grouped_across_hosts():
    items = [finding(f"10.0.0.{i}:445") for i in range(1, 41)]
    items.append(finding("10.0.0.99:3389", fid="RDP-001"))
    items.append(finding("10.0.0.1:445"))
    grouped = group_findings(items)
    assert [g.finding_id for g in grouped] == ["SMB-001", "RDP-001"]
    assert len(grouped[0].hosts) == 40
    assert len(grouped[0].reproduce) == 40


def test_different_status_not_merged():
    grouped = group_findings([finding("a:1"), finding("b:1", status=Status.OK)])
    assert len(grouped) == 2


def test_grouping_does_not_mutate_input():
    first = finding("a:1")
    group_findings([first, finding("b:1")])
    assert first.hosts == ["a:1"]


def test_repo_config_matches_built_in_defaults():
    data = tomllib.loads(REPO_CONFIG.read_text())
    assert Config.model_validate(data) == Config()


def test_config_rejects_unknown_keys(tmp_path):
    path = tmp_path / "bad.toml"
    path.write_text("[rates]\ninternl = 5\n")
    with pytest.raises(ConfigError):
        load_config(path)


def test_config_override(tmp_path):
    path = tmp_path / "c.toml"
    path.write_text("[rates]\ninternal = 500\n[scan]\nudp_parallel = false\n")
    config, used = load_config(path)
    assert used == path
    assert config.rates.internal == 500 and config.rates.external == 100
    assert config.scan.udp_parallel is False


def test_missing_explicit_config(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "nope.toml")
