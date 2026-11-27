import asyncio
import time
from pathlib import Path

import pytest

from portgoblin.core.config import Config
from portgoblin.core.nmap_runner import (
    SAFE_DEFAULT_SCRIPTS,
    NmapRunner,
    ScriptNotAllowedError,
    check_scripts_allowed,
    discovery_cmd,
    parse_progress,
    parse_script_db,
    resume_cmd,
    script_cmd,
    tcp_all_cmd,
    tcp_svc_cmd,
    udp_cmd,
)

T = Path("/w/chunk_000/targets.txt")
X = Path("/w/exclude.txt")

SCRIPT_DB = """
Entry { filename = "ftp-anon.nse", categories = { "auth", "default", "safe", } }
Entry { filename = "ssl-enum-ciphers.nse", categories = { "discovery", "intrusive", } }
Entry { filename = "smb-brute.nse", categories = { "brute", "intrusive", } }
Entry { filename = "docker-version.nse", categories = { "version", } }
"""


def test_discovery_command():
    cmd = discovery_cmd(T, Path("/w/chunk_000/discovery"), X, "30s")
    assert cmd[:6] == [
        "nmap",
        "-sn",
        "-PE",
        "-PP",
        "-PS21,22,25,80,135,139,443,445,3389",
        "-PA80,443",
    ]
    assert ["-iL", str(T)] == cmd[-2:]
    assert "--excludefile" in cmd and "--stats-every" in cmd


def test_tcp_all_command():
    cmd = tcp_all_cmd(T, Path("/w/tcp_all"), 300, None, "30s")
    joined = " ".join(cmd)
    assert "-sS -Pn -p- -T3 --min-rate 300 --max-retries 2" in joined
    assert "-oA /w/tcp_all" in joined
    assert "--excludefile" not in cmd


def test_tcp_svc_uses_filtered_default_scripts_not_sc():
    cmd = tcp_svc_cmd("10.0.0.5", [443, 22, 80], Path("/w/tcp_svc_10.0.0.5"), None, "30s")
    assert "-sC" not in cmd
    assert cmd[cmd.index("--script") + 1] == SAFE_DEFAULT_SCRIPTS
    assert cmd[cmd.index("-p") + 1] == "22,80,443"
    assert cmd[-1] == "10.0.0.5"


def test_udp_command_has_no_min_rate():
    cmd = udp_cmd(T, Path("/w/udp"), 100, None, "30s")
    joined = " ".join(cmd)
    assert "--min-rate" not in cmd
    assert "-sU -Pn --top-ports 100 -sV --version-intensity 0 -T3 --max-retries 1" in joined


def test_resume_command_takes_no_other_options():
    assert resume_cmd(Path("/w/tcp_all")) == ["nmap", "--resume", "/w/tcp_all.nmap"]


def test_parse_progress_real_lines():
    line = "SYN Stealth Scan Timing: About 26.67% done; ETC: 12:18 (0:00:06 remaining)"
    progress = parse_progress(line)
    assert progress.task == "SYN Stealth Scan"
    assert progress.percent == pytest.approx(26.67)
    assert progress.remaining == "0:00:06"
    early = parse_progress("SYN Stealth Scan Timing: About 0.33% done")
    assert early.percent == pytest.approx(0.33) and early.remaining is None
    assert parse_progress("Stats: 0:00:02 elapsed; 0 hosts completed (1 up)") is None


def test_script_db_parsing():
    db = parse_script_db(SCRIPT_DB)
    assert db["ssl-enum-ciphers"] == {"discovery", "intrusive"}
    assert db["ftp-anon"] == {"auth", "default", "safe"}


def test_only_allowlisted_scripts_can_run():
    db = parse_script_db(SCRIPT_DB)
    config = Config()
    with pytest.raises(ScriptNotAllowedError, match="not on the allowlist"):
        script_cmd("10.0.0.1", [445], "tcp", ["smb-brute"], Path("/w/x"), config, db)
    with pytest.raises(ScriptNotAllowedError, match="not on the allowlist"):
        script_cmd("10.0.0.1", [2375], "tcp", ["docker-version"], Path("/w/x"), config, db)
    cmd = script_cmd("10.0.0.1", [21], "tcp", ["ftp-anon"], Path("/w/x"), config, db)
    assert cmd[cmd.index("--script") + 1] == "ftp-anon"


def test_confirmed_non_safe_script_allowed_unconfirmed_refused():
    db = parse_script_db(SCRIPT_DB)
    config = Config()
    check_scripts_allowed(["ssl-enum-ciphers"], config, db)
    config.nse.confirmed_non_safe = []
    with pytest.raises(ScriptNotAllowedError, match="not confirmed"):
        check_scripts_allowed(["ssl-enum-ciphers"], config, db)


def test_allowlisted_but_missing_script_refused():
    with pytest.raises(ScriptNotAllowedError, match="not installed"):
        check_scripts_allowed(["ftp-anon"], Config(), {})


def test_udp_script_command():
    db = {"snmp-sysdescr": {"default", "discovery", "safe"}}
    cmd = script_cmd(
        "10.0.0.1",
        [161],
        "udp",
        ["snmp-sysdescr"],
        Path("/w/x"),
        Config(),
        db,
        "snmpcommunity=public",
    )
    assert "-sU" in cmd and cmd[cmd.index("--script-args") + 1] == "snmpcommunity=public"


def test_runner_streams_lines():
    lines = []
    cmd = ["sh", "-c", "echo one; echo 'UDP Scan Timing: About 10.00% done'; echo three >&2"]
    result = asyncio.run(NmapRunner().run(cmd, lines.append))
    assert result.returncode == 0
    assert lines == ["one", "UDP Scan Timing: About 10.00% done"]
    assert "three" in result.stderr


def test_runner_gives_child_a_terminal():
    # nmap only prints --stats-every lines when it has a controlling terminal.
    lines = []
    asyncio.run(NmapRunner().run(["sh", "-c", "test -t 0 && echo tty || echo notty"], lines.append))
    assert lines == ["tty"]


def test_runner_stops_child_on_cancel():
    async def scenario():
        task = asyncio.create_task(NmapRunner(interrupt_grace=5).run(["sleep", "30"]))
        await asyncio.sleep(0.3)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    started = time.monotonic()
    asyncio.run(scenario())
    assert time.monotonic() - started < 5
