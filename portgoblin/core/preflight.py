"""Pre-flight: root check, tool detection, time estimate and confirmation."""

from __future__ import annotations

import math
import os
import re
import shutil
import socket
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from portgoblin.core.engine import Mode, ScanOptions
from portgoblin.core.models import ScanResult
from portgoblin.core.targets import TargetSet

ROOT_MESSAGE = "PortGoblin needs root for SYN (-sS) and UDP (-sU) scans. Run it again with sudo."

INSTALL = {
    "nmap": "sudo apt install nmap",
    "searchsploit": "sudo apt install exploitdb",
    "metasploit": "sudo apt install metasploit-framework",
    "netexec": "sudo apt install netexec",
    "smbclient": "sudo apt install smbclient",
}

MSF_METADATA_CANDIDATES = [
    Path("/usr/share/metasploit-framework/db/modules_metadata_base.json"),
    Path("/opt/metasploit-framework/embedded/framework/db/modules_metadata_base.json"),
]


def is_root() -> bool:
    return os.geteuid() == 0


@dataclass
class ToolStatus:
    name: str
    found: bool
    path: str | None = None
    version: str | None = None
    install: str | None = None
    note: str | None = None


def _run_text(cmd: list[str], timeout: int = 15) -> str | None:
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return (proc.stdout or "") + (proc.stderr or "")


def nmap_version(path: str) -> str | None:
    out = _run_text([path, "--version"])
    match = re.search(r"Nmap version (\S+)", out or "")
    return match.group(1) if match else None


def smbclient_version(path: str) -> str | None:
    out = _run_text([path, "--version"])
    match = re.search(r"Version (\S+)", out or "")
    return match.group(1) if match else None


def searchsploit_version(path: str) -> str | None:
    """searchsploit is a shell script with its version in a header comment."""
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            head = handle.read(4096)
    except OSError:
        return None
    match = re.search(r"Version:\s*(\S+)", head)
    return match.group(1) if match else None


def netexec_info(path: str) -> tuple[str | None, bool]:
    """Version line, and whether --shares uses the ACL check (no writes) by default.

    netexec builds that offer --file-write-check only create files when that flag is
    passed. Older builds created a directory on every share, so they are not used.
    """
    version_out = _run_text([path, "--version"])
    version = version_out.strip().splitlines()[0] if version_out and version_out.strip() else None
    help_out = _run_text([path, "smb", "--help"]) or ""
    return version, "--file-write-check" in help_out


def find_msf_metadata() -> Path | None:
    candidates = list(MSF_METADATA_CANDIDATES)
    msfconsole = shutil.which("msfconsole")
    if msfconsole:
        real = Path(msfconsole).resolve()
        candidates.insert(0, real.parent / "db" / "modules_metadata_base.json")
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def detect_tools() -> list[ToolStatus]:
    tools: list[ToolStatus] = []

    path = shutil.which("nmap")
    tools.append(
        ToolStatus("nmap", bool(path), path, nmap_version(path) if path else None, INSTALL["nmap"])
    )

    path = shutil.which("searchsploit")
    tools.append(
        ToolStatus(
            "searchsploit",
            bool(path),
            path,
            searchsploit_version(path) if path else None,
            INSTALL["searchsploit"],
        )
    )

    metadata = find_msf_metadata()
    tools.append(
        ToolStatus(
            "Metasploit metadata",
            metadata is not None,
            str(metadata) if metadata else None,
            None,
            INSTALL["metasploit"],
        )
    )

    path = shutil.which("netexec") or shutil.which("nxc")
    if path:
        version, acl_shares = netexec_info(path)
        note = None if acl_shares else "this build may write to shares; smbclient will be used"
        tools.append(ToolStatus("netexec", True, path, version, INSTALL["netexec"], note))
    else:
        tools.append(ToolStatus("netexec", False, install=INSTALL["netexec"]))

    path = shutil.which("smbclient")
    tools.append(
        ToolStatus(
            "smbclient",
            bool(path),
            path,
            smbclient_version(path) if path else None,
            INSTALL["smbclient"],
        )
    )
    return tools


@dataclass
class Estimate:
    tcp_seconds: float
    udp_seconds: float

    @property
    def total_seconds(self) -> float:
        return self.tcp_seconds + self.udp_seconds


# nmap scans UDP hosts in parallel groups. Most hosts answer closed UDP ports with about
# one ICMP port unreachable per second, so this is a rough guide only.
UDP_PARALLEL_HOSTS = 64
UDP_SECONDS_PER_PORT = 1.0


def estimate(host_count: int, options: ScanOptions, udp_parallel: bool) -> Estimate:
    """Rough worst case. --min-rate is a floor, so the full TCP scan should not take longer
    than hosts x 65535 / rate (before retries). Service detection is not included because
    it depends on how many ports are open."""
    tcp = host_count * 65535 / options.rate if options.tcp else 0.0
    udp = 0.0
    if options.udp:
        groups = math.ceil(host_count / UDP_PARALLEL_HOSTS)
        udp = groups * options.top_udp * UDP_SECONDS_PER_PORT
    if udp_parallel and options.tcp and options.udp:
        return Estimate(tcp, max(0.0, udp - tcp))
    return Estimate(tcp, udp)


def format_duration(seconds: float) -> str:
    seconds = int(round(seconds))
    if seconds < 60:
        return f"{seconds}s"
    minutes, _ = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def timing_label(options: ScanOptions) -> str:
    return f"Cautious (-T3, min-rate {options.rate})"


@dataclass
class PreflightPlan:
    target_set: TargetSet
    options: ScanOptions
    tools: list[ToolStatus]
    estimate: Estimate
    warnings: list[str] = field(default_factory=list)

    @property
    def missing_tools(self) -> list[ToolStatus]:
        return [t for t in self.tools if not t.found]


def build_plan(
    target_set: TargetSet, options: ScanOptions, tools: list[ToolStatus], udp_parallel: bool
) -> PreflightPlan:
    warnings = []
    if options.mode is Mode.EXTERNAL:
        for target in target_set.targets:
            if target.hostname:
                warnings.append(
                    f"{target.hostname} resolves to {', '.join(target.ips)}. Confirm these IPs "
                    "are in scope: shared hosting or CDN addresses may belong to others."
                )
    return PreflightPlan(
        target_set, options, tools, estimate(target_set.host_count, options, udp_parallel), warnings
    )


def confirm(assume_yes: bool, ask: Callable[[str], str]) -> bool:
    """Proceed? [y/N]. Anything but y or yes is a no."""
    if assume_yes:
        return True
    try:
        answer = ask("Proceed? [y/N] ")
    except (EOFError, KeyboardInterrupt):
        return False
    return answer.strip().lower() in ("y", "yes")


def reachability_targets(result: ScanResult, limit: int = 5) -> list[tuple[str, int]]:
    """Up to `limit` imported hosts, each with one known open TCP port."""
    picks = []
    for host in result.live_hosts():
        ports = host.ports_in_state("tcp", "open")
        if ports:
            picks.append((host.address, ports[0].portid))
        if len(picks) >= limit:
            break
    return picks


def tcp_connect(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def check_reachability(
    result: ScanResult,
    timeout: float,
    connect: Callable[[str, int, float], bool] = tcp_connect,
    limit: int = 5,
) -> tuple[bool, list[tuple[str, int, bool]]]:
    """TCP connect to up to `limit` imported hosts. True if any answered."""
    attempts = [(h, p, connect(h, p, timeout)) for h, p in reachability_targets(result, limit)]
    return any(ok for _, _, ok in attempts), attempts


NOT_REACHABLE = "Not assessed: hosts not reachable from this machine"
