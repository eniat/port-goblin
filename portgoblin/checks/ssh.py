"""SSH: weak algorithms offered (ssh2-enum-algos)."""

from __future__ import annotations

import re

from portgoblin.checks.base import ScriptCheck, ScriptResults, finding, hp, nmap_repro, nsedoc
from portgoblin.core.models import Finding, Host, Port, Status

SECTION = re.compile(r"^\s*(\w+_algorithms):\s*\(\d+\)\s*$")

# Only algorithms with a published reason to drop them. hmac-sha1 and umac-64 are still
# in OpenSSH's defaults and are not flagged.
WEAK = {
    "server_host_key_algorithms": {
        "ssh-dss": "DSA, removed from OpenSSH",
        "ssh-rsa": "RSA with SHA-1 signatures (RFC 8332), disabled by default in OpenSSH 8.8+",
    },
}
WEAK_KEX_PATTERNS = [
    (re.compile(r"group1-"), "1024-bit group with SHA-1 (RFC 9142)"),
    (re.compile(r"-sha1(-|@|$)"), "SHA-1 key exchange (RFC 9142)"),
]
WEAK_CIPHER_PATTERNS = [
    (re.compile(r"-cbc(@|$)"), "CBC mode"),
    (re.compile(r"^3des"), "3DES"),
    (re.compile(r"^arcfour"), "RC4 (RFC 8758)"),
    (re.compile(r"^(blowfish|cast128|des)"), "64-bit block cipher"),
    (re.compile(r"^none$"), "no encryption"),
]
WEAK_MAC_PATTERNS = [
    (re.compile(r"md5"), "MD5"),
    (re.compile(r"-96(@|$)"), "truncated 96-bit MAC"),
    (re.compile(r"^none$"), "no integrity"),
]


def parse_algorithms(output: str) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {}
    current = None
    for line in output.splitlines():
        match = SECTION.match(line)
        if match:
            current = match.group(1)
            sections[current] = []
        elif current and line.strip():
            sections[current].append(line.strip())
    return sections


def weak_algorithms(sections: dict[str, list[str]]) -> list[str]:
    found = []
    for section, names in sections.items():
        for name in names:
            reason = WEAK.get(section, {}).get(name)
            patterns = {
                "kex_algorithms": WEAK_KEX_PATTERNS,
                "encryption_algorithms": WEAK_CIPHER_PATTERNS,
                "mac_algorithms": WEAK_MAC_PATTERNS,
            }.get(section, [])
            for pattern, why in patterns:
                if pattern.search(name):
                    reason = why
                    break
            if reason:
                found.append(f"{name} ({reason})")
    return found


class SshAlgorithms(ScriptCheck):
    check_id = "ssh-algorithms"
    name = "SSH algorithms"
    scripts = ("ssh2-enum-algos",)

    def matches(self, port: Port) -> bool:
        return bool(port.service and port.service.name == "ssh")

    def evaluate(self, host: Host, ports: list[Port], results: ScriptResults) -> list[Finding]:
        out: list[Finding] = []
        for port in ports:
            output = results.port_output(port, "ssh2-enum-algos")
            target = hp(host, port)
            if not output:
                if "ssh2-enum-algos" in results.ran:
                    out.append(self.not_assessed(host, [port], "ssh2-enum-algos returned nothing"))
                continue
            sections = parse_algorithms(output)
            if not sections:
                out.append(self.not_assessed(host, [port], "could not parse nmap output"))
                continue
            weak = weak_algorithms(sections)
            repro = [nmap_repro(host, [port], self.scripts)]
            if weak:
                out.append(
                    finding(
                        "SSH-001",
                        self.check_id,
                        "Weak SSH algorithms offered",
                        Status.ISSUE,
                        [target],
                        "Clients that prefer or are limited to these algorithms get weaker "
                        "protection for the session.",
                        observed=f"{target}: {', '.join(weak)}",
                        fix="Remove these from KexAlgorithms, HostKeyAlgorithms, Ciphers and MACs "
                        "in sshd_config, then restart sshd.",
                        reproduce=repro
                        + [f"ssh -vv {host.address} -p {port.portid}  (shows offers)"],
                        refs=[
                            nsedoc("ssh2-enum-algos"),
                            "https://www.rfc-editor.org/rfc/rfc9142",
                            "https://www.rfc-editor.org/rfc/rfc8758",
                        ],
                    )
                )
            else:
                out.append(
                    finding(
                        "SSH-001",
                        self.check_id,
                        "Weak SSH algorithms offered",
                        Status.OK,
                        [target],
                        "No algorithms from the weak list were offered.",
                        reproduce=repro,
                    )
                )
        return out
