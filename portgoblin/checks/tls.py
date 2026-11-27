"""TLS on any service: certificate (ssl-cert) and protocols and ciphers (ssl-enum-ciphers).

ssl-enum-ciphers is in the intrusive category (it makes many handshakes). It is on the
allowlist because the tester confirmed it.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

from portgoblin.checks.base import ScriptCheck, ScriptResults, finding, hp, nmap_repro, nsedoc
from portgoblin.core.models import Finding, Host, Port, Status

# shortport.ssl's LIKELY_SSL_SERVICES in nmap 7.94, plus tunnel=ssl from -sV.
TLS_SERVICES = {
    "ftps",
    "ftps-data",
    "ftps-control",
    "https",
    "https-alt",
    "imaps",
    "ircs",
    "ldapssl",
    "ms-wbt-server",
    "pop3s",
    "sip-tls",
    "smtps",
    "telnets",
    "tor-orport",
}
LEGACY = ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1")
WEAK_GRADES = ("C", "D", "E", "F")


def tls_port(port: Port) -> bool:
    if not port.service:
        return False
    return port.service.tunnel == "ssl" or (port.service.name or "") in TLS_SERVICES


def parse_ciphers(output: str) -> tuple[list[str], str | None, list[str]]:
    protocols = re.findall(r"^\s{2}(SSLv\d|TLSv1\.\d):\s*$", output, re.MULTILINE)
    least = re.search(r"least strength:\s*(\w)", output)
    warnings = []
    in_warnings = False
    for line in output.splitlines():
        if line.strip() == "warnings:":
            in_warnings = True
            continue
        if in_warnings:
            if line.startswith("      ") and line.strip():
                warnings.append(line.strip())
            else:
                in_warnings = False
    return protocols, least.group(1) if least else None, warnings


def parse_cert(output: str) -> dict[str, str]:
    fields = {}
    for line in output.splitlines():
        key, sep, value = line.partition(":")
        if sep and key.strip() in (
            "Subject",
            "Issuer",
            "Public Key type",
            "Public Key bits",
            "Signature Algorithm",
            "Not valid before",
            "Not valid after",
        ):
            fields[key.strip()] = value.strip()
    return fields


def _parse_time(value: str) -> datetime | None:
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


class TlsCheck(ScriptCheck):
    check_id = "tls"
    name = "TLS"
    scripts = ("ssl-cert", "ssl-enum-ciphers")

    def __init__(self, now: datetime | None = None) -> None:
        self.now = now

    def matches(self, port: Port) -> bool:
        return tls_port(port)

    def evaluate(self, host: Host, ports: list[Port], results: ScriptResults) -> list[Finding]:
        now = self.now or datetime.now(UTC)
        out: list[Finding] = []
        for port in ports:
            target = hp(host, port)
            ciphers = results.port_output(port, "ssl-enum-ciphers")
            cert = results.port_output(port, "ssl-cert")
            if ciphers:
                out += self._ciphers(host, port, target, ciphers)
            if cert:
                out += self._cert(host, port, target, cert, now)
            if not ciphers and not cert and {"ssl-cert", "ssl-enum-ciphers"} <= results.ran:
                out.append(self.not_assessed(host, [port], "no TLS handshake completed"))
        return out

    def _ciphers(self, host: Host, port: Port, target: str, output: str) -> list[Finding]:
        protocols, least, warnings = parse_ciphers(output)
        repro = [nmap_repro(host, [port], ("ssl-enum-ciphers",))]
        out = []
        legacy = [p for p in protocols if p in LEGACY]
        if legacy:
            out.append(
                finding(
                    "TLS-001",
                    self.check_id,
                    "Legacy SSL or TLS protocol offered",
                    Status.ISSUE,
                    [target],
                    "SSLv3, TLS 1.0 and TLS 1.1 are deprecated (RFC 7568, RFC 8996) and lack "
                    "modern protections.",
                    observed=f"{target}: {', '.join(legacy)}",
                    fix="Offer TLS 1.2 and 1.3 only.",
                    reproduce=repro,
                    refs=[
                        "https://www.rfc-editor.org/rfc/rfc8996",
                        "https://www.rfc-editor.org/rfc/rfc7568",
                        nsedoc("ssl-enum-ciphers"),
                    ],
                )
            )
        if least in WEAK_GRADES or warnings:
            detail = f"nmap least strength {least}" if least else "nmap warnings"
            if warnings:
                detail += f" ({'; '.join(warnings)})"
            out.append(
                finding(
                    "TLS-002",
                    self.check_id,
                    "Weak TLS cipher suites offered",
                    Status.ISSUE,
                    [target],
                    "Some offered cipher suites give weak or no protection to clients that "
                    "negotiate them.",
                    observed=f"{target}: {detail}",
                    fix="Remove the weak suites (anonymous, export, NULL, RC4, 3DES and small "
                    "DH groups) from the server's TLS configuration.",
                    reproduce=repro,
                    refs=[nsedoc("ssl-enum-ciphers")],
                )
            )
        if not legacy and least not in WEAK_GRADES and not warnings and protocols:
            out.append(
                finding(
                    "TLS-001",
                    self.check_id,
                    "Legacy SSL or TLS protocol offered",
                    Status.OK,
                    [target],
                    "Only TLS 1.2 or later with nmap grade A or B suites.",
                    observed=f"{target}: {', '.join(protocols)}, least strength {least}",
                    reproduce=repro,
                )
            )
        return out

    def _cert(
        self, host: Host, port: Port, target: str, output: str, now: datetime
    ) -> list[Finding]:
        fields = parse_cert(output)
        repro = [nmap_repro(host, [port], ("ssl-cert",))]
        out = []
        not_after = _parse_time(fields.get("Not valid after", ""))
        if not_after and not_after < now:
            out.append(
                finding(
                    "TLS-003",
                    self.check_id,
                    "Expired TLS certificate",
                    Status.ISSUE,
                    [target],
                    "Clients either warn or fail, and users who are used to clicking through "
                    "warnings are easier to intercept.",
                    observed=f"{target}: expired {fields['Not valid after']} UTC "
                    f"(subject {fields.get('Subject', '?')})",
                    fix="Renew the certificate.",
                    reproduce=repro,
                )
            )
        problems = []
        bits = fields.get("Public Key bits", "")
        key_type = fields.get("Public Key type", "").lower()
        if key_type in ("rsa", "dsa") and bits.isdigit() and int(bits) < 2048:
            problems.append(f"{key_type.upper()} {bits}-bit key")
        signature = fields.get("Signature Algorithm", "").lower()
        if "md5" in signature or "sha1" in signature:
            problems.append(f"signature {fields['Signature Algorithm']}")
        if problems:
            out.append(
                finding(
                    "TLS-005",
                    self.check_id,
                    "Weak TLS certificate key or signature",
                    Status.ISSUE,
                    [target],
                    "Small keys and MD5 or SHA-1 signatures are below current minimums.",
                    observed=f"{target}: {', '.join(problems)}",
                    fix="Reissue the certificate with an RSA key of 2048 bits or more (or ECDSA) "
                    "and a SHA-256 signature.",
                    reproduce=repro,
                )
            )
        subject, issuer = fields.get("Subject"), fields.get("Issuer")
        if subject and issuer and subject == issuer:
            out.append(
                finding(
                    "TLS-004",
                    self.check_id,
                    "Self-signed TLS certificate",
                    Status.OBSERVATION,
                    [target],
                    "Clients cannot verify the server, so they must trust it on first use or "
                    "ignore warnings. Common on internal services.",
                    observed=f"{target}: subject and issuer {subject}",
                    reproduce=repro,
                )
            )
        return out
