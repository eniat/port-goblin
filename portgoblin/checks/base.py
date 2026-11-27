"""Building blocks for follow-up checks.

A check is a class in any module in this package that subclasses ScriptCheck or
DirectCheck. Dropping a new file here is enough: the loader finds it, and the engine
does not need editing.

ScriptCheck: runs allowlisted NSE scripts. The runner batches every script check for a
host into one nmap call per protocol and reuses output nmap already produced (for
example ftp-anon from the default scripts in service detection), so each service gets
one attempt. The check only has to say which ports it wants and how to read the output.

DirectCheck: talks to the service itself through the context (a tool command or one
HTTP GET), for things nmap has no suitable safe script for.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import ClassVar, Protocol

from portgoblin.core.models import CheckRecord, Finding, Host, Port, Status

NSEDOC = "https://nmap.org/nsedoc/scripts/{}.html"


def nsedoc(script: str) -> str:
    return NSEDOC.format(script)


def hp(host: Host | str, port: Port | int) -> str:
    address = host.address if isinstance(host, Host) else host
    number = port.portid if isinstance(port, Port) else port
    return f"{address}:{number}"


def service_name(port: Port) -> str:
    return (port.service.name or "").lower() if port.service and port.service.name else ""


def product(port: Port) -> str:
    return (port.service.product or "").lower() if port.service and port.service.product else ""


def is_tls(port: Port) -> bool:
    return bool(port.service and port.service.tunnel == "ssl")


@dataclass
class ScriptResults:
    """Script output for one host: per port, plus host scripts (SMB scripts are host scripts).

    `ran` holds the script IDs known to have run, so a script with no output can be read
    as "ran and found nothing" rather than "did not run".
    """

    ports: dict[tuple[str, int], dict[str, str]] = field(default_factory=dict)
    host: dict[str, str] = field(default_factory=dict)
    ran: set[str] = field(default_factory=set)
    failed: dict[str, str] = field(default_factory=dict)

    def port_output(self, port: Port, script: str) -> str | None:
        return self.ports.get(port.key, {}).get(script)

    def host_output(self, script: str) -> str | None:
        return self.host.get(script)


@dataclass
class ToolResult:
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool = False
    error: str | None = None


@dataclass
class HttpResult:
    status: int | None
    body: bytes = b""
    error: str | None = None
    headers: dict[str, str] = field(default_factory=dict)


class CheckContext(Protocol):
    """What a check may use. Implemented in core.followup."""

    is_root: bool

    def tool(self, name: str) -> str | None: ...

    def netexec_safe(self, path: str) -> bool:
        """True if this netexec build checks share access without writing files."""
        ...

    async def run_tool(self, check: str, target: str, cmd: list[str]) -> ToolResult: ...

    async def http_get(self, check: str, target: str, url: str) -> HttpResult: ...

    def record(self, record: CheckRecord) -> None: ...


class BaseCheck:
    check_id: ClassVar[str]  # for example "smb-null-session"
    name: ClassVar[str]  # shown in progress and Not assessed lines
    protocol: ClassVar[str] = "tcp"
    states: ClassVar[tuple[str, ...]] = ("open",)

    def matches(self, port: Port) -> bool:
        raise NotImplementedError

    def ports(self, host: Host) -> list[Port]:
        return sorted(
            (
                p
                for p in host.ports
                if p.protocol == self.protocol and p.state in self.states and self.matches(p)
            ),
            key=lambda p: p.portid,
        )

    # Helpers for building findings

    def not_assessed(self, host: Host, ports: Iterable[Port], reason: str) -> Finding:
        return Finding(
            finding_id=f"NA-{self.check_id}",
            check=self.check_id,
            title=self.name,
            status=Status.NOT_ASSESSED,
            hosts=[hp(host, p) for p in ports],
            observed=f"Not assessed: {reason}",
            why_it_matters="The check could not run, so this service was not assessed.",
        )


class ScriptCheck(BaseCheck):
    scripts: ClassVar[tuple[str, ...]] = ()
    script_args: ClassVar[str | None] = None

    def evaluate(self, host: Host, ports: list[Port], results: ScriptResults) -> list[Finding]:
        raise NotImplementedError


class DirectCheck(BaseCheck):
    async def run(self, ctx: CheckContext, host: Host, ports: list[Port]) -> list[Finding]:
        raise NotImplementedError


def nmap_repro(
    host: Host | str,
    ports: Iterable[Port | int],
    scripts: Iterable[str],
    udp: bool = False,
    args: str | None = None,
) -> str:
    """The nmap command a tester can run to see the same result."""
    address = host.address if isinstance(host, Host) else host
    numbers = sorted({p.portid if isinstance(p, Port) else p for p in ports})
    parts = ["nmap", "-Pn", "-sV"]
    if udp:
        parts = ["sudo", *parts, "-sU"]
    parts += ["--script", ",".join(scripts)]
    if args:
        parts += ["--script-args", f"'{args}'"]
    parts += ["-p", ",".join(str(n) for n in numbers), address]
    return " ".join(parts)


def finding(
    finding_id: str,
    check: str,
    title: str,
    status: Status,
    hosts: Iterable[str],
    why: str,
    observed: str | None = None,
    fix: str | None = None,
    reproduce: Iterable[str] = (),
    manual: Iterable[str] = (),
    refs: Iterable[str] = (),
) -> Finding:
    return Finding(
        finding_id=finding_id,
        check=check,
        title=title,
        status=status,
        hosts=list(hosts),
        observed=observed,
        why_it_matters=why,
        remediation=fix,
        reproduce=list(reproduce),
        manual_steps=list(manual),
        references=list(refs),
    )
