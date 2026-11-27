"""The follow-up runner: batching, reuse of earlier script output, guards and the loader."""

import asyncio
import http.server
import sys
import threading
from pathlib import Path

import pytest

from portgoblin import checks as checks_pkg
from portgoblin.checks import load_checks
from portgoblin.checks.base import ScriptCheck
from portgoblin.checks.ftp import FtpAnonymous
from portgoblin.checks.snmp import SnmpPublic
from portgoblin.checks.ssh import SshAlgorithms
from portgoblin.core.config import Config
from portgoblin.core.followup import FollowUpContext, FollowUps, http_get_sync
from portgoblin.core.models import Host, Port, ScanResult, Service, Status
from portgoblin.core.nmap_runner import RunResult

SCRIPT_DB = {
    "ftp-anon": {"default", "auth", "safe"},
    "ssh2-enum-algos": {"safe", "discovery"},
    "snmp-sysdescr": {"default", "discovery", "safe"},
    "snmp-info": {"default", "version", "safe"},
}

SSH_OUTPUT = (
    "\n  kex_algorithms: (1)\n      curve25519-sha256\n  server_host_key_algorithms: (1)\n"
    "      ssh-ed25519\n  encryption_algorithms: (1)\n      aes128-cbc\n"
    "  mac_algorithms: (1)\n      hmac-sha2-256\n  compression_algorithms: (1)\n      none"
)


class ScriptRunner:
    def __init__(self, returncode=0):
        self.calls = []
        self.returncode = returncode

    async def run(self, cmd, on_line=None):
        self.calls.append(cmd)
        base = Path(cmd[cmd.index("-oA") + 1])
        host = cmd[-1]
        xml = (
            f'<nmaprun version="7.94SVN"><host><status state="up" reason="user-set"/>'
            f'<address addr="{host}" addrtype="ipv4"/><ports>'
            f'<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/>'
            f'<script id="ssh2-enum-algos" output="{SSH_OUTPUT.replace(chr(10), "&#xa;")}"/>'
            f"</port></ports></host></nmaprun>"
        )
        base.with_name(base.name + ".xml").write_text(xml)
        return RunResult(self.returncode, "")


def scan(default_scripts=True, udp=False):
    ports = [
        Port(
            protocol="tcp",
            portid=21,
            state="open",
            service=Service(name="ftp"),
            default_scripts=default_scripts,
        ),
        Port(
            protocol="tcp",
            portid=22,
            state="open",
            service=Service(name="ssh"),
            default_scripts=default_scripts,
        ),
    ]
    if udp:
        ports.append(Port(protocol="udp", portid=161, state="open", service=Service(name="snmp")))
    host = Host(address="10.0.0.5", status="up", status_reason="syn-ack", ports=ports)
    return ScanResult(hosts={host.address: host})


def followups(tmp_path, runner, checks, root=True, db=None):
    ctx = FollowUpContext(Config(), root, which=lambda name: None)
    return FollowUps(
        Config(), runner, tmp_path, db if db is not None else SCRIPT_DB, ctx, checks=checks
    )


def test_default_script_output_is_reused_not_rerun(tmp_path):
    runner = ScriptRunner()
    fu = followups(tmp_path, runner, [FtpAnonymous(), SshAlgorithms()])
    findings = asyncio.run(fu.run(scan(default_scripts=True)))
    # ftp-anon already ran in service detection (and found nothing): no second login attempt.
    assert len(runner.calls) == 1
    cmd = runner.calls[0]
    assert cmd[cmd.index("--script") + 1] == "ssh2-enum-algos"
    assert cmd[cmd.index("-p") + 1] == "22"
    statuses = {(f.finding_id, f.status) for f in findings}
    assert ("FTP-001", Status.OK) in statuses and ("SSH-001", Status.ISSUE) in statuses
    assert any(r.sent.startswith("nothing") and "ftp-anon" in r.result for r in fu.ctx.records)


def test_scripts_for_a_host_are_batched_into_one_nmap_call(tmp_path):
    runner = ScriptRunner()
    fu = followups(tmp_path, runner, [FtpAnonymous(), SshAlgorithms()])
    asyncio.run(fu.run(scan(default_scripts=False)))
    assert len(runner.calls) == 1
    cmd = runner.calls[0]
    assert cmd[cmd.index("--script") + 1] == "ftp-anon,ssh2-enum-algos"
    assert cmd[cmd.index("-p") + 1] == "21,22"


def test_udp_checks_need_root(tmp_path):
    runner = ScriptRunner()
    fu = followups(tmp_path, runner, [SnmpPublic()], root=False)
    (finding,) = asyncio.run(fu.run(scan(udp=True)))
    assert finding.status is Status.NOT_ASSESSED and "need root" in finding.observed
    assert runner.calls == []


def test_unknown_script_is_refused_and_reported(tmp_path):
    class Rogue(ScriptCheck):
        check_id = "rogue"
        name = "Rogue"
        scripts = ("smb-brute",)

        def matches(self, port):
            return port.portid == 22

        def evaluate(self, host, ports, results):
            raise AssertionError("must not run")

    runner = ScriptRunner()
    fu = followups(tmp_path, runner, [Rogue()])
    (finding,) = asyncio.run(fu.run(scan()))
    assert finding.status is Status.NOT_ASSESSED and "not on the allowlist" in finding.observed
    assert runner.calls == []


def test_missing_script_db_reports_not_assessed(tmp_path):
    fu = followups(tmp_path, ScriptRunner(), [SshAlgorithms()], db={})
    (finding,) = asyncio.run(fu.run(scan(default_scripts=False)))
    assert finding.status is Status.NOT_ASSESSED and "not installed" in finding.observed


def test_nmap_failure_reports_not_assessed(tmp_path):
    fu = followups(tmp_path, ScriptRunner(returncode=1), [SshAlgorithms()])
    (finding,) = asyncio.run(fu.run(scan(default_scripts=False)))
    assert finding.status is Status.NOT_ASSESSED and "exited with code 1" in finding.observed


def test_a_crashing_check_does_not_stop_the_others(tmp_path):
    class Broken(ScriptCheck):
        check_id = "broken"
        name = "Broken"

        def matches(self, port):
            return True

        def evaluate(self, host, ports, results):
            raise ValueError("boom")

    fu = followups(tmp_path, ScriptRunner(), [Broken(), FtpAnonymous()])
    findings = asyncio.run(fu.run(scan()))
    assert {f.status for f in findings} == {Status.NOT_ASSESSED, Status.OK}


def test_every_shipped_check_loads():
    ids = [c.check_id for c in load_checks()]
    assert len(ids) == len(set(ids))
    for expected in ("ftp-anonymous", "smb-signing", "smb-null-guest", "tls", "snmp-public"):
        assert expected in ids


def test_dropping_a_file_into_checks_adds_a_check(tmp_path, monkeypatch):
    (tmp_path / "zz_example.py").write_text(
        "from portgoblin.checks.base import ScriptCheck\n"
        "class ExampleCheck(ScriptCheck):\n"
        "    check_id = 'example'\n"
        "    name = 'Example'\n"
        "    def matches(self, port):\n"
        "        return False\n"
        "    def evaluate(self, host, ports, results):\n"
        "        return []\n"
    )
    monkeypatch.setattr(checks_pkg, "__path__", [*checks_pkg.__path__, str(tmp_path)])
    try:
        assert "example" in [c.check_id for c in load_checks()]
    finally:
        sys.modules.pop("portgoblin.checks.zz_example", None)


def test_every_script_used_by_a_check_is_allowlisted():
    allowlist = set(Config().nse.allowlist)
    for check in load_checks():
        for script in getattr(check, "scripts", ()):
            assert script in allowlist, f"{check.check_id} uses {script}"


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 (http.server API)
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://198.51.100.1/elsewhere")
            self.end_headers()
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"ok": true}')

    def log_message(self, *args):
        pass


@pytest.fixture
def local_server():
    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def test_http_get_never_follows_redirects_or_uses_proxies(local_server, monkeypatch):
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    ok = http_get_sync(f"{local_server}/", 5)
    assert ok.status == 200 and ok.body == b'{"ok": true}'
    redirect = http_get_sync(f"{local_server}/redirect", 5)
    assert redirect.status == 302
