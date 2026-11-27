"""rsync daemon: module names (rsync-list-modules).

nmap 7.94's rsync library expects the server greeting "@RSYNCD: <version>" with nothing
after it. rsync 3.2 and later add a list of checksum names, so the script fails and
prints nothing. In that case the result is a manual check with the command to run.
"""

from __future__ import annotations

from portgoblin.checks.base import ScriptCheck, ScriptResults, finding, hp, nmap_repro, nsedoc
from portgoblin.core.models import Finding, Host, Port, Status


def parse_modules(output: str) -> list[str]:
    modules = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("ERROR"):
            continue
        modules.append(stripped.split()[0])
    return modules


class RsyncModules(ScriptCheck):
    check_id = "rsync-modules"
    name = "rsync modules"
    scripts = ("rsync-list-modules",)

    def matches(self, port: Port) -> bool:
        name = port.service.name if port.service and port.service.name else ""
        return name == "rsync" or port.portid == 873

    def evaluate(self, host: Host, ports: list[Port], results: ScriptResults) -> list[Finding]:
        out: list[Finding] = []
        for port in ports:
            target = hp(host, port)
            output = results.port_output(port, "rsync-list-modules") or ""
            modules = parse_modules(output)
            manual = f"rsync rsync://{host.address}:{port.portid}/  (lists module names only)"
            if modules:
                out.append(
                    finding(
                        "RSYNC-001",
                        self.check_id,
                        "rsync modules listed",
                        Status.OBSERVATION,
                        [target],
                        "Module names are visible without credentials. Modules without auth "
                        "users may be readable by anyone.",
                        observed=f"{target}: {', '.join(modules)}",
                        reproduce=[nmap_repro(host, [port], self.scripts), manual],
                        manual=[
                            "For each module, check whether it needs a password (auth users and "
                            "secrets file in rsyncd.conf). PortGoblin does not list files."
                        ],
                        refs=[nsedoc("rsync-list-modules")],
                    )
                )
            elif "rsync-list-modules" in results.ran:
                out.append(
                    finding(
                        "RSYNC-002",
                        self.check_id,
                        "rsync daemon: module list not confirmed",
                        Status.MANUAL_CHECK,
                        [target],
                        "An rsync daemon is listening. nmap's script returned nothing, which "
                        "happens with rsync 3.2 and later, so module access was not checked.",
                        observed=f"{target}: rsync-list-modules returned no output",
                        reproduce=[manual],
                        manual=[
                            f"Run {manual}. If modules are listed, check whether each needs a "
                            "password (auth users in rsyncd.conf)."
                        ],
                        refs=[nsedoc("rsync-list-modules")],
                    )
                )
        return out
