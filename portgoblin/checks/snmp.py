"""SNMP on UDP 161: community public readable (snmp-sysdescr), engine info (snmp-info)."""

from __future__ import annotations

from portgoblin.checks.base import ScriptCheck, ScriptResults, finding, hp, nmap_repro, nsedoc
from portgoblin.core.models import Finding, Host, Port, Status


class SnmpPublic(ScriptCheck):
    """Runs only on confirmed open 161/udp, so community public is tried once."""

    check_id = "snmp-public"
    name = "SNMP community public"
    protocol = "udp"
    scripts = ("snmp-sysdescr", "snmp-info")
    script_args = "snmpcommunity=public"

    def matches(self, port: Port) -> bool:
        name = port.service.name if port.service and port.service.name else ""
        return port.portid == 161 or name == "snmp"

    def evaluate(self, host: Host, ports: list[Port], results: ScriptResults) -> list[Finding]:
        out: list[Finding] = []
        for port in ports:
            target = hp(host, port)
            descr = results.port_output(port, "snmp-sysdescr")
            repro = [nmap_repro(host, [port], ("snmp-sysdescr",), udp=True, args=self.script_args)]
            repro.append(f"snmpget -v2c -c public {host.address} 1.3.6.1.2.1.1.1.0")
            if descr:
                first = descr.strip().splitlines()[0].strip()
                out.append(
                    finding(
                        "SNMP-001",
                        self.check_id,
                        "SNMP community public readable",
                        Status.ISSUE,
                        [target],
                        "The default community string gives read access to device details, "
                        "and often to interfaces, routes, processes and user names.",
                        observed=f"{target}: sysDescr {first}",
                        fix="Remove the public community. Use SNMPv3 with authentication, or a "
                        "long random community restricted to management hosts.",
                        reproduce=repro,
                        refs=[nsedoc("snmp-sysdescr")],
                    )
                )
            elif "snmp-sysdescr" in results.ran:
                out.append(
                    finding(
                        "SNMP-001",
                        self.check_id,
                        "SNMP community public readable",
                        Status.OK,
                        [target],
                        "Community public got no answer.",
                        reproduce=repro,
                    )
                )
        return out
