"""IPMI on UDP 623: cipher zero (ipmi-cipher-zero) and version (ipmi-version).

Both scripts accept open|filtered, as IPMI often does not answer nmap's UDP probes.
"""

from __future__ import annotations

from portgoblin.checks.base import ScriptCheck, ScriptResults, finding, hp, nmap_repro, nsedoc
from portgoblin.core.models import Finding, Host, Port, Status


class IpmiCipherZero(ScriptCheck):
    check_id = "ipmi"
    name = "IPMI"
    protocol = "udp"
    states = ("open", "open|filtered")
    scripts = ("ipmi-version", "ipmi-cipher-zero")

    def matches(self, port: Port) -> bool:
        name = port.service.name if port.service and port.service.name else ""
        return port.portid == 623 or name == "asf-rmcp"

    def evaluate(self, host: Host, ports: list[Port], results: ScriptResults) -> list[Finding]:
        out: list[Finding] = []
        for port in ports:
            target = hp(host, port)
            version = results.port_output(port, "ipmi-version") or ""
            zero = results.port_output(port, "ipmi-cipher-zero") or ""
            repro = [nmap_repro(host, [port], self.scripts, udp=True)]
            if "State: VULNERABLE" in zero:
                out.append(
                    finding(
                        "IPMI-001",
                        self.check_id,
                        "IPMI cipher zero accepted",
                        Status.ISSUE,
                        [target],
                        "Cipher suite 0 lets anyone log in to the BMC with any password if they "
                        "know a valid user name, giving control of the server hardware.",
                        observed=f"{target}: cipher zero authentication bypass reported by nmap",
                        fix="Disable cipher suite 0 on the BMC (for example ipmitool lan set 1 "
                        "cipher_privs) and keep the BMC on a separate management network.",
                        reproduce=repro,
                        refs=[nsedoc("ipmi-cipher-zero")],
                    )
                )
            elif zero and "NOT VULNERABLE" in zero:
                out.append(
                    finding(
                        "IPMI-001",
                        self.check_id,
                        "IPMI cipher zero accepted",
                        Status.OK,
                        [target],
                        "Cipher zero was not accepted.",
                        reproduce=repro,
                    )
                )
            if version:
                lines = ", ".join(line.strip() for line in version.splitlines() if line.strip())
                out.append(
                    finding(
                        "IPMI-002",
                        self.check_id,
                        "IPMI exposed",
                        Status.OBSERVATION,
                        [target],
                        "A BMC answers on this address. BMCs often allow password hash "
                        "retrieval (RAKP) by design, so their exposure matters.",
                        observed=f"{target}: {lines}",
                        reproduce=[nmap_repro(host, [port], ("ipmi-version",), udp=True)],
                        manual=["Check whether this BMC needs to be reachable from this network."],
                    )
                )
        return out
