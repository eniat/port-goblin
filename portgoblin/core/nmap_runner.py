"""Builds nmap commands and runs them as asyncio subprocesses."""

from __future__ import annotations

import asyncio
import contextlib
import fcntl
import os
import re
import shutil
import signal
import termios
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from portgoblin.core.config import Config

# Default scripts with anything unsafe filtered out, used instead of -sC so the
# rule holds even if a future nmap release adds an intrusive script to "default".
SAFE_DEFAULT_SCRIPTS = "default and not (brute or dos or exploit or intrusive)"
UNSAFE_CATEGORIES = frozenset({"brute", "dos", "exploit", "intrusive"})

DISCOVERY_PROBES = [
    "-sn",
    "-PE",
    "-PP",
    "-PS21,22,25,80,135,139,443,445,3389",
    "-PA80,443",
]

PROGRESS_RE = re.compile(
    r"^(?P<task>.+?) Timing: About (?P<pct>\d+(?:\.\d+)?)% done"
    r"(?:; ETC: [^(]*\((?P<remaining>\d+:\d{2}:\d{2}) remaining\))?"
)

LineCallback = Callable[[str], None]


class ScriptNotAllowedError(Exception):
    pass


class NmapError(Exception):
    pass


@dataclass
class Progress:
    task: str
    percent: float
    remaining: str | None


def parse_progress(line: str) -> Progress | None:
    """Parse an nmap --stats-every timing line, for example
    'SYN Stealth Scan Timing: About 26.67% done; ETC: 12:18 (0:00:06 remaining)'."""
    match = PROGRESS_RE.match(line.strip())
    if not match:
        return None
    return Progress(match.group("task"), float(match.group("pct")), match.group("remaining"))


def _common(out_base: Path, stats_every: str) -> list[str]:
    return ["--stats-every", stats_every, "-oA", str(out_base)]


def _excludes(exclude_file: Path | None) -> list[str]:
    return ["--excludefile", str(exclude_file)] if exclude_file else []


def discovery_cmd(
    targets_file: Path, out_base: Path, exclude_file: Path | None, stats_every: str
) -> list[str]:
    return [
        "nmap",
        *DISCOVERY_PROBES,
        "-T3",
        *_common(out_base, stats_every),
        *_excludes(exclude_file),
        "-iL",
        str(targets_file),
    ]


def tcp_all_cmd(
    targets_file: Path,
    out_base: Path,
    rate: int,
    exclude_file: Path | None,
    stats_every: str,
) -> list[str]:
    return [
        "nmap",
        "-sS",
        "-Pn",
        "-p-",
        "-T3",
        "--min-rate",
        str(rate),
        "--max-retries",
        "2",
        *_common(out_base, stats_every),
        *_excludes(exclude_file),
        "-iL",
        str(targets_file),
    ]


def tcp_svc_cmd(
    host: str,
    ports: list[int],
    out_base: Path,
    exclude_file: Path | None,
    stats_every: str,
) -> list[str]:
    if not ports:
        raise ValueError("tcp_svc_cmd needs at least one port")
    return [
        "nmap",
        "-sS",
        "-Pn",
        "-sV",
        "--script",
        SAFE_DEFAULT_SCRIPTS,
        "-p",
        ",".join(str(p) for p in sorted(ports)),
        "-T3",
        *_common(out_base, stats_every),
        *_excludes(exclude_file),
        host,
    ]


def udp_cmd(
    targets_file: Path,
    out_base: Path,
    top_udp: int,
    exclude_file: Path | None,
    stats_every: str,
) -> list[str]:
    # No --min-rate on UDP: it causes ports to be missed.
    return [
        "nmap",
        "-sU",
        "-Pn",
        "--top-ports",
        str(top_udp),
        "-sV",
        "--version-intensity",
        "0",
        "-T3",
        "--max-retries",
        "1",
        *_common(out_base, stats_every),
        *_excludes(exclude_file),
        "-iL",
        str(targets_file),
    ]


def resume_cmd(out_base: Path) -> list[str]:
    # nmap refuses any other option alongside --resume.
    return ["nmap", "--resume", f"{out_base}.nmap"]


def find_script_db(nmap_path: str | None = None) -> Path | None:
    nmap_path = nmap_path or shutil.which("nmap")
    candidates = []
    if nmap_path:
        real = Path(nmap_path).resolve()
        candidates.append(real.parent.parent / "share" / "nmap" / "scripts" / "script.db")
    candidates += [
        Path("/usr/share/nmap/scripts/script.db"),
        Path("/usr/local/share/nmap/scripts/script.db"),
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


SCRIPT_DB_RE = re.compile(r'filename\s*=\s*"([^"]+)\.nse"\s*,\s*categories\s*=\s*\{([^}]*)\}')


def parse_script_db(text: str) -> dict[str, set[str]]:
    """Parse nmap's script.db, for example
    'Entry { filename = "ssl-enum-ciphers.nse", categories = { "discovery", "intrusive", } }'."""
    db: dict[str, set[str]] = {}
    for match in SCRIPT_DB_RE.finditer(text):
        db[match.group(1)] = set(re.findall(r'"([^"]+)"', match.group(2)))
    return db


def check_scripts_allowed(
    scripts: list[str], config: Config, script_db: dict[str, set[str]]
) -> None:
    """Raise unless every script is allowlisted, installed, and either safe or confirmed."""
    for name in scripts:
        if name not in config.nse.allowlist:
            raise ScriptNotAllowedError(f"NSE script {name} is not on the allowlist")
        categories = script_db.get(name)
        if categories is None:
            raise ScriptNotAllowedError(f"NSE script {name} is not installed or not in script.db")
        unsafe = categories & UNSAFE_CATEGORIES
        if unsafe and name not in config.nse.confirmed_non_safe:
            raise ScriptNotAllowedError(
                f"NSE script {name} is in {', '.join(sorted(unsafe))} and was not confirmed"
            )


def script_cmd(
    host: str,
    ports: list[int],
    protocol: str,
    scripts: list[str],
    out_base: Path,
    config: Config,
    script_db: dict[str, set[str]],
    script_args: str | None = None,
) -> list[str]:
    """Command for allowlisted follow-up scripts. Raises ScriptNotAllowedError otherwise."""
    if not scripts:
        raise ScriptNotAllowedError("No scripts given")
    check_scripts_allowed(scripts, config, script_db)
    cmd = ["nmap", "-Pn", "-sV"]
    if protocol == "udp":
        cmd.append("-sU")
    cmd += ["--script", ",".join(scripts)]
    if script_args:
        cmd += ["--script-args", script_args]
    cmd += ["-p", ",".join(str(p) for p in sorted(ports)), "-T3", "-oA", str(out_base), host]
    return cmd


@dataclass
class RunResult:
    returncode: int
    stderr: str


def _child_setup() -> None:  # pragma: no cover - runs in the child process
    # nmap only prints --stats-every progress when it has a controlling terminal, so the
    # child gets its own session with the pty on stdin as its terminal. Being in its own
    # session also keeps the user's Ctrl+C away from it; PortGoblin forwards it instead.
    os.setsid()
    with contextlib.suppress(OSError):
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)


class NmapRunner:
    """Runs one command at a time per call. Ctrl+C sends SIGINT to nmap and waits for it."""

    def __init__(self, interrupt_grace: int = 30) -> None:
        self.interrupt_grace = interrupt_grace

    async def run(self, cmd: list[str], on_line: LineCallback | None = None) -> RunResult:
        try:
            master, slave = os.openpty()
        except OSError:
            master = slave = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=slave if slave is not None else asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                preexec_fn=_child_setup if slave is not None else None,
                start_new_session=slave is None,
            )
        finally:
            if slave is not None:
                os.close(slave)
        stderr_task = asyncio.create_task(proc.stderr.read())
        try:
            while True:
                raw = await proc.stdout.readline()
                if not raw:
                    break
                if on_line:
                    on_line(raw.decode("utf-8", "replace").rstrip("\n"))
            returncode = await proc.wait()
            stderr = (await stderr_task).decode("utf-8", "replace")
            return RunResult(returncode, stderr)
        except BaseException:
            await self._stop(proc)
            stderr_task.cancel()
            raise
        finally:
            if master is not None:
                os.close(master)

    async def _stop(self, proc: asyncio.subprocess.Process) -> None:
        if proc.returncode is not None:
            return
        with contextlib.suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGINT)
        try:
            await asyncio.wait_for(asyncio.shield(proc.wait()), self.interrupt_grace)
        except (TimeoutError, asyncio.CancelledError):
            with contextlib.suppress(ProcessLookupError):
                os.killpg(proc.pid, signal.SIGKILL)
            with contextlib.suppress(Exception):
                await proc.wait()
