import re

import pytest
from typer.testing import CliRunner

from conftest import NMAP_FIXTURES, FakeRunner
from portgoblin import __version__, cli
from portgoblin.core import preflight
from portgoblin.core.preflight import ToolStatus

runner = CliRunner()


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.setenv("PORTGOBLIN_CONFIG", str(cli.load_config.__globals__["REPO_CONFIG"]))
    monkeypatch.setattr(
        preflight, "detect_tools", lambda: [ToolStatus("nmap", True, "/usr/bin/nmap", "7.94SVN")]
    )


@pytest.fixture(autouse=True)
def offline_intel(monkeypatch):
    """CLI tests never reach NVD, KEV, EPSS or endoflife.date."""
    from portgoblin.analysis.versions import Sources, VersionIntel
    from portgoblin.intelligence.cache import FetchError

    def offline(*args, **kwargs):
        raise FetchError("offline in tests")

    class OfflineNvd:
        has_key = False

        def lookup(self, cpe):
            raise FetchError("offline in tests")

    def make(config, progress=None):
        return VersionIntel(
            Sources(nvd=OfflineNvd(), kev=offline, epss=offline, eol=offline), progress
        )

    monkeypatch.setattr(cli, "make_intel", make)


@pytest.fixture
def as_root(monkeypatch):
    monkeypatch.setattr(preflight, "is_root", lambda: True)


@pytest.fixture
def no_engine(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("no scan should start")

    monkeypatch.setattr(cli.Engine, "create", refuse)


def plain(text):
    return re.sub(r"\s+", " ", text)


def test_version():
    result = runner.invoke(cli.app, ["--version"])
    assert result.exit_code == 0 and __version__ in result.output


@pytest.mark.parametrize("flags", [[], ["--internal", "--external"]])
def test_mode_is_required(flags, as_root, no_engine):
    result = runner.invoke(cli.app, ["scan", "10.0.0.1", *flags])
    assert result.exit_code == 2
    assert "--internal or --external" in plain(result.output)


def test_root_required(monkeypatch, no_engine):
    monkeypatch.setattr(preflight, "is_root", lambda: False)
    result = runner.invoke(cli.app, ["scan", "10.0.0.1", "--internal"])
    assert result.exit_code == 1
    assert "needs root" in plain(result.output)


def test_preflight_blocks_until_confirmed(as_root, no_engine):
    result = runner.invoke(cli.app, ["scan", "10.0.0.0/30", "--internal"], input="n\n")
    assert result.exit_code == 1
    out = plain(result.output)
    assert "Pre-flight" in out and "2 after exclusions" in out
    assert "No traffic was sent" in out


def test_preflight_shows_exclusions_and_mode(as_root, no_engine):
    result = runner.invoke(
        cli.app,
        ["scan", "10.0.0.0/29", "--external", "--exclude", "10.0.0.1,10.0.0.2", "--tcp-only"],
        input="\n",
    )
    out = plain(result.output)
    assert "4 after exclusions, 2 excluded" in out
    assert "External" in out and "min-rate 100" in out
    assert "UDP" not in out.split("Phases", 1)[1].split("Follow-up", 1)[0]


def test_tcp_only_and_udp_only_conflict(as_root, no_engine):
    result = runner.invoke(cli.app, ["scan", "10.0.0.1", "--internal", "--tcp-only", "--udp-only"])
    assert result.exit_code == 2


def test_save_existing_with_yes_exits_before_scan(tmp_path, as_root, no_engine):
    existing = tmp_path / "out.txt"
    existing.write_text("old")
    result = runner.invoke(
        cli.app, ["scan", "10.0.0.1", "--internal", "--yes", "--save", str(existing)]
    )
    assert result.exit_code == 2
    assert "already exists" in plain(result.output)
    assert existing.read_text() == "old"


def test_save_existing_declined(tmp_path, as_root, no_engine):
    existing = tmp_path / "out.txt"
    existing.write_text("old")
    result = runner.invoke(
        cli.app, ["scan", "10.0.0.1", "--internal", "--save", str(existing)], input="n\n"
    )
    assert result.exit_code == 2 and existing.read_text() == "old"


def test_bad_target(as_root, no_engine):
    result = runner.invoke(cli.app, ["scan", "10.0.0.999", "--internal", "--yes"])
    assert result.exit_code == 2 and "Invalid" in result.output


def test_full_scan_saves_and_cleans_up(tmp_path, monkeypatch, as_root):
    fake = FakeRunner()
    monkeypatch.setattr(cli, "NmapRunner", lambda *a, **k: fake)
    save = tmp_path / "results.txt"
    result = runner.invoke(
        cli.app, ["scan", "10.0.0.1-2", "--internal", "--yes", "--save", str(save), "--no-color"]
    )
    assert result.exit_code == 0, result.output
    text = save.read_text()
    assert "\x1b[" not in text
    assert "http://10.0.0.1" in text and "10.0.0.1:22" in text
    assert "UDP open|filtered" in text
    runs_dir = tmp_path / "data" / "portgoblin" / "runs"
    assert list(runs_dir.iterdir()) == []


def test_interrupted_scan_keeps_workdir_and_prints_results(tmp_path, monkeypatch, as_root):
    fake = FakeRunner(interrupt_on="tcp_svc")
    monkeypatch.setattr(cli, "NmapRunner", lambda *a, **k: fake)
    result = runner.invoke(cli.app, ["scan", "10.0.0.1", "--internal", "--yes", "--no-color"])
    assert result.exit_code == cli.EXIT_INTERRUPTED
    out = plain(result.output)
    assert "Interrupted" in out and "portgoblin resume" in out
    assert "10.0.0.1:22" in out
    runs_dir = tmp_path / "data" / "portgoblin" / "runs"
    (run_dir,) = list(runs_dir.iterdir())

    listing = runner.invoke(cli.app, ["runs", "--no-color"])
    assert run_dir.name[:8] in listing.output

    resumed = runner.invoke(cli.app, ["resume", run_dir.name, "--yes", "--no-color"])
    assert resumed.exit_code == 0, resumed.output
    assert not run_dir.exists()


def test_resume_unknown_run(as_root):
    result = runner.invoke(cli.app, ["resume", "nope"])
    assert result.exit_code == 2


def test_import_without_root(monkeypatch):
    monkeypatch.setattr(preflight, "is_root", lambda: False)
    result = runner.invoke(
        cli.app,
        [
            "import",
            str(NMAP_FIXTURES / "services_mixed.xml"),
            str(NMAP_FIXTURES / "udp.xml"),
            "--no-color",
        ],
    )
    assert result.exit_code == 0, result.output
    out = result.output
    assert "https://files.example.test:8443" in out
    assert "10.0.0.5:161/udp" in out
    assert "UDP open|filtered" in out


def test_import_reports_parse_failures(monkeypatch):
    result = runner.invoke(
        cli.app,
        [
            "import",
            str(NMAP_FIXTURES / "udp.xml"),
            str(NMAP_FIXTURES / "malformed.xml"),
            "--no-color",
        ],
    )
    assert result.exit_code == 0
    assert "could not parse nmap output" in plain(result.output)


def test_import_all_failed():
    result = runner.invoke(cli.app, ["import", str(NMAP_FIXTURES / "malformed.xml")])
    assert result.exit_code == 1


def test_doctor_runs(monkeypatch):
    result = runner.invoke(cli.app, ["doctor", "--no-color"])
    assert result.exit_code == 0
    assert "nmap" in result.output and "Running as root" in result.output


class NoTraffic:
    def __init__(self, calls):
        self.calls = calls

    async def run(self, cmd, on_line=None):
        self.calls.append(cmd)
        raise AssertionError("no checks should run")


def test_import_checks_need_confirmation(monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "NmapRunner", lambda *a, **k: NoTraffic(calls))
    monkeypatch.setattr(preflight, "tcp_connect", lambda *a: calls.append(a) or True)
    result = runner.invoke(
        cli.app, ["import", str(NMAP_FIXTURES / "services_mixed.xml"), "--no-color"], input="n\n"
    )
    assert result.exit_code == 0
    out = plain(result.output)
    assert "Follow-up checks for imported hosts" in out and "10.0.0.20" in out
    assert "No traffic was sent" in out and "skipped at the Proceed? prompt" in out
    assert calls == []


def test_import_unreachable_hosts_skip_checks(monkeypatch):
    nmap_calls = []

    class Recorder:
        async def run(self, cmd, on_line=None):
            nmap_calls.append(cmd)
            raise AssertionError("no checks should run")

    monkeypatch.setattr(cli, "NmapRunner", lambda *a, **k: Recorder())
    monkeypatch.setattr(preflight, "tcp_connect", lambda host, port, timeout: False)
    result = runner.invoke(
        cli.app, ["import", str(NMAP_FIXTURES / "services_mixed.xml"), "--yes", "--no-color"]
    )
    assert result.exit_code == 0, result.output
    assert "hosts not reachable from this machine" in plain(result.output)
    assert nmap_calls == []


def test_scan_preflight_says_checks_will_run(as_root, no_engine):
    result = runner.invoke(cli.app, ["scan", "10.0.0.1", "--internal"], input="n\n")
    assert "Follow-up checks Yes (read-only" in plain(result.output)
    result = runner.invoke(cli.app, ["scan", "10.0.0.1", "--internal", "--no-checks"], input="n\n")
    assert "Follow-up checks No (--no-checks)" in plain(result.output)


def test_import_reports_intel_not_assessed_when_offline(monkeypatch):
    result = runner.invoke(
        cli.app,
        ["import", str(NMAP_FIXTURES / "services_mixed.xml"), "--no-checks", "--no-color"],
    )
    assert result.exit_code == 0, result.output
    out = plain(result.output)
    assert "Vulnerable versions 0 services" in out
    assert "NVD not reachable (offline in tests)" in out
    assert "CVE check not possible: no version detected" in out


def test_no_intel_flag(monkeypatch):
    result = runner.invoke(
        cli.app,
        ["import", str(NMAP_FIXTURES / "udp.xml"), "--no-checks", "--no-intel", "--no-color"],
    )
    assert "Vulnerable versions" not in result.output
