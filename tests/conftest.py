from __future__ import annotations

import asyncio
import signal
from pathlib import Path

import pytest

from portgoblin.core.nmap_runner import RunResult

FIXTURES = Path(__file__).parent / "fixtures"
NMAP_FIXTURES = FIXTURES / "nmap"


def host_xml(ip: str, ports: list[tuple[str, int, str, str | None]], reason: str) -> str:
    port_xml = "".join(
        f'<port protocol="{proto}" portid="{port}"><state state="{state}" reason="x"/>'
        + (f'<service name="{name}" method="probed" conf="10"/>' if name else "")
        + "</port>"
        for proto, port, state, name in ports
    )
    return (
        f'<host><status state="up" reason="{reason}"/><address addr="{ip}" addrtype="ipv4"/>'
        f"<hostnames></hostnames><ports>{port_xml}</ports></host>\n"
    )


def nmap_doc(hosts: str, complete: bool = True) -> str:
    head = '<?xml version="1.0"?>\n<nmaprun scanner="nmap" version="7.94SVN">\n'
    return head + hosts + ("</nmaprun>\n" if complete else "")


class FakeRunner:
    """Stands in for nmap. Writes plausible -oA output for each phase and records calls.

    interrupt_on: phase name ("discovery", "tcp_all", "tcp_svc", "udp") at which to press
    Ctrl+C once: a partial (unclosed) output file is written, as nmap does, then a real
    SIGINT is sent to this process. asyncio.run cancels the main task, exactly as it does
    for a real Ctrl+C, and the cancellation reaches this call while it waits.
    """

    def __init__(self, down: set[str] | None = None, interrupt_on: str | None = None) -> None:
        self.calls: list[list[str]] = []
        self.down = down or set()
        self.interrupt_on = interrupt_on
        self.interrupted = False
        self.fail_resume = False

    @staticmethod
    def _targets(cmd: list[str]) -> list[str]:
        if "-iL" in cmd:
            path = Path(cmd[cmd.index("-iL") + 1])
            return [line for line in path.read_text().splitlines() if line]
        return [cmd[-1]]

    def _hosts(self, phase: str, targets: list[str]) -> str:
        out = ""
        for ip in targets:
            if phase == "discovery":
                if ip not in self.down:
                    out += host_xml(ip, [], "echo-reply")
            elif phase == "tcp_all" or phase == "tcp_svc":
                out += host_xml(
                    ip, [("tcp", 22, "open", "ssh"), ("tcp", 80, "open", "http")], "user-set"
                )
            elif phase == "udp":
                out += host_xml(
                    ip,
                    [("udp", 161, "open", "snmp"), ("udp", 123, "open|filtered", "ntp")],
                    "user-set",
                )
        return out

    async def run(self, cmd, on_line=None) -> RunResult:
        self.calls.append(cmd)
        if cmd[1] == "--resume":
            if self.fail_resume:
                return RunResult(1, "Cannot resume")
            base = Path(cmd[2][: -len(".nmap")])
            xml = base.with_name(base.name + ".xml")
            xml.write_text(xml.read_text() + "</nmaprun>\n")
            return RunResult(0, "")
        base = Path(cmd[cmd.index("-oA") + 1])
        phase = "tcp_svc" if base.name.startswith("tcp_svc_") else base.name
        if on_line:
            on_line("SYN Stealth Scan Timing: About 50.00% done; ETC: 12:00 (0:00:10 remaining)")
        hosts = self._hosts(phase, self._targets(cmd))
        base.with_name(base.name + ".nmap").write_text("# Nmap 7.94SVN scan initiated\n")
        if phase == self.interrupt_on and not self.interrupted:
            self.interrupted = True
            base.with_name(base.name + ".xml").write_text(nmap_doc(hosts, complete=False))
            signal.raise_signal(signal.SIGINT)
            await asyncio.sleep(30)
            raise AssertionError("SIGINT did not cancel the run")
        base.with_name(base.name + ".xml").write_text(nmap_doc(hosts))
        return RunResult(0, "")


@pytest.fixture
def fake_resolver():
    table = {"web.example.test": ["10.0.0.10", "10.0.0.11"], "one.example.test": ["10.0.1.5"]}

    def resolve(name: str) -> list[str]:
        from portgoblin.core.targets import TargetError

        if name not in table:
            raise TargetError(f"Could not resolve hostname {name}")
        return table[name]

    return resolve
