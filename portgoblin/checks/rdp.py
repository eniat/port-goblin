"""RDP: NLA and encryption (rdp-enum-encryption), NTLM info (rdp-ntlm-info)."""

from __future__ import annotations

import re

from portgoblin.checks.base import ScriptCheck, ScriptResults, finding, hp, nmap_repro, nsedoc
from portgoblin.core.models import Finding, Host, Port, Status

LAYER = re.compile(
    r"^\s*(Native RDP|SSL|CredSSP \(NLA\)|CredSSP with Early User Auth|RDSTLS):\s*(\w+)"
)
# Security layers that let a client connect without authenticating first.
NON_NLA = ("Native RDP", "SSL", "RDSTLS")


def _rdp(port: Port) -> bool:
    name = port.service.name if port.service and port.service.name else ""
    return name == "ms-wbt-server" or port.portid == 3389


def parse_layers(output: str) -> dict[str, str]:
    layers = {}
    for line in output.splitlines():
        match = LAYER.match(line)
        if match:
            layers[match.group(1)] = match.group(2)
    return layers


class RdpNla(ScriptCheck):
    check_id = "rdp-nla"
    name = "RDP Network Level Authentication"
    scripts = ("rdp-enum-encryption",)

    def matches(self, port: Port) -> bool:
        return _rdp(port)

    def evaluate(self, host: Host, ports: list[Port], results: ScriptResults) -> list[Finding]:
        out: list[Finding] = []
        for port in ports:
            output = results.port_output(port, "rdp-enum-encryption")
            target = hp(host, port)
            if not output:
                if "rdp-enum-encryption" in results.ran:
                    out.append(
                        self.not_assessed(host, [port], "rdp-enum-encryption returned nothing")
                    )
                continue
            layers = parse_layers(output)
            if not layers:
                out.append(self.not_assessed(host, [port], "could not parse nmap output"))
                continue
            allowed = [name for name in NON_NLA if layers.get(name) == "SUCCESS"]
            repro = [nmap_repro(host, [port], self.scripts)]
            if allowed:
                out.append(
                    finding(
                        "RDP-001",
                        self.check_id,
                        "RDP without NLA",
                        Status.ISSUE,
                        [target],
                        "Without NLA the login screen is reachable before authentication, which "
                        "exposes more of the RDP stack to unauthenticated users.",
                        observed=f"{target}: accepts {', '.join(allowed)}",
                        fix="Require Network Level Authentication (Group Policy: Require user "
                        "authentication for remote connections by using NLA).",
                        reproduce=repro,
                        refs=[nsedoc("rdp-enum-encryption")],
                    )
                )
            else:
                out.append(
                    finding(
                        "RDP-001",
                        self.check_id,
                        "RDP without NLA",
                        Status.OK,
                        [target],
                        "Only CredSSP (NLA) security layers were accepted.",
                        reproduce=repro,
                    )
                )
        return out


INFO_KEYS = (
    "Target_Name",
    "NetBIOS_Domain_Name",
    "DNS_Domain_Name",
    "DNS_Computer_Name",
    "Product_Version",
)


class RdpNtlmInfo(ScriptCheck):
    check_id = "rdp-ntlm-info"
    name = "RDP NTLM information"
    scripts = ("rdp-ntlm-info",)

    def matches(self, port: Port) -> bool:
        return _rdp(port)

    def evaluate(self, host: Host, ports: list[Port], results: ScriptResults) -> list[Finding]:
        out = []
        for port in ports:
            output = results.port_output(port, "rdp-ntlm-info")
            if not output:
                continue
            values = {}
            for line in output.splitlines():
                key, _, value = line.strip().partition(":")
                if key in INFO_KEYS and value.strip():
                    values[key] = value.strip()
            if not values:
                continue
            target = hp(host, port)
            out.append(
                finding(
                    "RDP-002",
                    self.check_id,
                    "RDP discloses host and domain names",
                    Status.OBSERVATION,
                    [target],
                    "The NTLM challenge gives domain, host name and Windows build to anyone "
                    "who connects. Useful for mapping the domain.",
                    observed=f"{target}: " + ", ".join(f"{k}={v}" for k, v in values.items()),
                    reproduce=[nmap_repro(host, [port], self.scripts)],
                )
            )
        return out
