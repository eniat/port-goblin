"""FTP: anonymous login (ftp-anon, usually already run by service detection)."""

from __future__ import annotations

import re

from portgoblin.checks.base import ScriptCheck, ScriptResults, finding, hp, nmap_repro, nsedoc
from portgoblin.core.models import Finding, Host, Port, Status

# Unix LIST line: permissions, links, owner, group, size, month, day, time or year, name.
UNIX_LIST = re.compile(
    r"^[-dlcbps][-rwxsStT]{9}\S*\s+\d+\s+\S+\s+\S+\s+\d+\s+\S+\s+\d+\s+\S+\s+(.+)$"
)
# Windows (IIS) LIST line: date, time, <DIR> or size, name.
WINDOWS_LIST = re.compile(r"^\d{2}-\d{2}-\d{2,4}\s+\d{1,2}:\d{2}(?:AM|PM)?\s+(?:<DIR>|\d+)\s+(.+)$")
NAME_LIMIT = 20


def listing_names(output: str) -> tuple[list[str], list[str]]:
    """Top-level names from ftp-anon's listing, and which of them nmap marks writeable."""
    names, writeable = [], []
    for line in output.splitlines()[1:]:
        line = line.strip()
        flag = line.endswith("[NSE: writeable]")
        line = line.removesuffix("[NSE: writeable]").strip()
        match = UNIX_LIST.match(line) or WINDOWS_LIST.match(line)
        if not match:
            continue
        name = match.group(1).split(" -> ", 1)[0]
        names.append(name)
        if flag:
            writeable.append(name)
    return names, writeable


class FtpAnonymous(ScriptCheck):
    check_id = "ftp-anonymous"
    name = "FTP anonymous login"
    scripts = ("ftp-anon",)

    def matches(self, port: Port) -> bool:
        name = port.service.name if port.service and port.service.name else ""
        return name in ("ftp", "ftps") or port.portid in (21, 990)

    def evaluate(self, host: Host, ports: list[Port], results: ScriptResults) -> list[Finding]:
        out: list[Finding] = []
        for port in ports:
            output = results.port_output(port, "ftp-anon")
            target = hp(host, port)
            repro = [nmap_repro(host, [port], self.scripts)]
            if output and "Anonymous FTP login allowed" in output:
                names, writeable = listing_names(output)
                shown = ", ".join(names[:NAME_LIMIT]) or "none listed"
                if len(names) > NAME_LIMIT:
                    shown += f" (+{len(names) - NAME_LIMIT} more)"
                observed = f"{target}: anonymous login allowed; top-level names: {shown}"
                if writeable:
                    observed += f"; nmap marks writeable: {', '.join(writeable)}"
                out.append(
                    finding(
                        "FTP-001",
                        self.check_id,
                        "Anonymous FTP login allowed",
                        Status.ISSUE,
                        [target],
                        "Anyone can log in without credentials and read whatever the FTP root "
                        "exposes.",
                        observed=observed,
                        fix="Disable anonymous login (for vsftpd: anonymous_enable=NO), or "
                        "confirm the content is meant to be public.",
                        reproduce=repro + [f"ftp {host.address} {port.portid}  (user anonymous)"],
                        refs=[nsedoc("ftp-anon")],
                    )
                )
            elif "ftp-anon" in results.ran:
                out.append(
                    finding(
                        "FTP-001",
                        self.check_id,
                        "Anonymous FTP login allowed",
                        Status.OK,
                        [target],
                        "Anonymous login was not accepted.",
                        reproduce=repro,
                    )
                )
        return out
