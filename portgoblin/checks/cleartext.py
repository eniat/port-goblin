"""Telnet, TFTP, rlogin, rsh and rexec exposed. Presence only: no login attempts."""

from __future__ import annotations

from portgoblin.checks.base import ScriptCheck, ScriptResults, finding, hp, service_name
from portgoblin.core.models import Finding, Host, Port, Status

FIX = "Turn the service off, or replace it with SSH (or SFTP for file transfer)."


class TelnetExposed(ScriptCheck):
    check_id = "telnet"
    name = "Telnet"

    def matches(self, port: Port) -> bool:
        return service_name(port) == "telnet" or (port.portid == 23 and not service_name(port))

    def evaluate(self, host: Host, ports: list[Port], results: ScriptResults) -> list[Finding]:
        return [
            finding(
                "CLEAR-001",
                self.check_id,
                "Telnet exposed",
                Status.ISSUE,
                [hp(host, p) for p in ports],
                "Telnet sends credentials and sessions in clear text.",
                observed="; ".join(
                    f"{hp(host, p)}: {p.service.label if p.service else 'telnet'}" for p in ports
                ),
                fix=FIX,
                reproduce=[
                    f"nmap -Pn -sV -p {','.join(str(p.portid) for p in ports)} {host.address}"
                ],
            )
        ]


R_SERVICES = {"login": (513, "rlogin"), "shell": (514, "rsh"), "exec": (512, "rexec")}


class RServicesExposed(ScriptCheck):
    check_id = "r-services"
    name = "rlogin, rsh and rexec"

    def matches(self, port: Port) -> bool:
        name = service_name(port)
        if name in R_SERVICES:
            return True
        # Fall back to the port only when nmap had nothing better to say.
        return not name and port.portid in (512, 513, 514)

    def evaluate(self, host: Host, ports: list[Port], results: ScriptResults) -> list[Finding]:
        labels = []
        for port in ports:
            known = R_SERVICES.get(service_name(port))
            labels.append(f"{hp(host, port)}: {known[1] if known else 'port ' + str(port.portid)}")
        return [
            finding(
                "CLEAR-003",
                self.check_id,
                "rlogin, rsh or rexec exposed",
                Status.ISSUE,
                [hp(host, p) for p in ports],
                "These services send credentials in clear text, and rlogin and rsh may trust "
                "hosts by address alone (.rhosts).",
                observed="; ".join(labels),
                fix=FIX,
                reproduce=[
                    f"nmap -Pn -sV -p {','.join(str(p.portid) for p in ports)} {host.address}"
                ],
            )
        ]


class TftpExposed(ScriptCheck):
    check_id = "tftp"
    name = "TFTP"
    protocol = "udp"
    states = ("open", "open|filtered")

    def matches(self, port: Port) -> bool:
        return port.portid == 69 or service_name(port) == "tftp"

    def evaluate(self, host: Host, ports: list[Port], results: ScriptResults) -> list[Finding]:
        out = []
        repro = f"sudo nmap -Pn -sU -sV -p 69 {host.address}"
        confirmed = [p for p in ports if p.state == "open"]
        maybe = [p for p in ports if p.state == "open|filtered"]
        if confirmed:
            out.append(
                finding(
                    "CLEAR-002",
                    self.check_id,
                    "TFTP exposed",
                    Status.ISSUE,
                    [f"{hp(host, p)}/udp" for p in confirmed],
                    "TFTP has no authentication, so any file it serves (often device configs or "
                    "boot images) can be fetched by anyone.",
                    fix=FIX.replace("SSH (or SFTP for file transfer)", "SFTP or HTTPS"),
                    reproduce=[repro],
                )
            )
        if maybe:
            out.append(
                finding(
                    "CLEAR-002",
                    self.check_id,
                    "TFTP possibly exposed",
                    Status.MANUAL_CHECK,
                    [f"{hp(host, p)}/udp" for p in maybe],
                    "69/udp is open|filtered: nmap got no answer, so TFTP was not confirmed.",
                    reproduce=[repro.replace("-sV", "-sV --version-intensity 9")],
                    manual=[
                        "Confirm with a version scan at full intensity. PortGoblin does not "
                        "request files."
                    ],
                )
            )
        return out
