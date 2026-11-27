"""NFS: exports visible through mountd (nfs-showmount)."""

from __future__ import annotations

from portgoblin.checks.base import ScriptCheck, ScriptResults, finding, hp, nmap_repro, nsedoc
from portgoblin.core.models import Finding, Host, Port, Status


def parse_exports(output: str) -> list[tuple[str, str]]:
    exports = []
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("/"):
            path, _, clients = line.partition(" ")
            exports.append((path, clients.strip() or "(no client list)"))
    return exports


class NfsExports(ScriptCheck):
    check_id = "nfs-exports"
    name = "NFS exports"
    scripts = ("nfs-showmount",)

    def matches(self, port: Port) -> bool:
        name = port.service.name if port.service and port.service.name else ""
        return port.portid == 111 or name in ("rpcbind", "mountd")

    def evaluate(self, host: Host, ports: list[Port], results: ScriptResults) -> list[Finding]:
        for port in ports:
            output = results.port_output(port, "nfs-showmount")
            if not output:
                continue
            exports = parse_exports(output)
            if not exports:
                continue
            target = hp(host, port)
            listed = "; ".join(f"{path} allowed {clients}" for path, clients in exports)
            return [
                finding(
                    "NFS-001",
                    self.check_id,
                    "NFS exports visible",
                    Status.ISSUE,
                    [target],
                    "Exports open to everyone, or to address ranges an attacker can use, may be "
                    "mountable without credentials.",
                    observed=f"{target}: {listed}",
                    fix="Limit each export to the hosts that need it in /etc/exports, and use "
                    "root_squash. Firewall mountd and NFS from other networks.",
                    reproduce=[
                        nmap_repro(host, [port], self.scripts),
                        f"showmount -e {host.address}",
                    ],
                    manual=[
                        f"Check whether this machine is in an allowed range: showmount -e "
                        f"{host.address}. Mounting is not done by PortGoblin."
                    ],
                    refs=[nsedoc("nfs-showmount")],
                )
            ]
        if "nfs-showmount" in results.ran:
            port = ports[0]
            return [
                finding(
                    "NFS-001",
                    self.check_id,
                    "NFS exports visible",
                    Status.OK,
                    [hp(host, port)],
                    "No exports were listed.",
                    reproduce=[nmap_repro(host, [port], self.scripts)],
                )
            ]
        return []
