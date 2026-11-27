"""SMB: signing, SMBv1, and null or guest share listing."""

from __future__ import annotations

import re
import shlex

from portgoblin.checks.base import (
    CheckContext,
    DirectCheck,
    ScriptCheck,
    ScriptResults,
    finding,
    hp,
    nmap_repro,
    nsedoc,
)
from portgoblin.core.models import Finding, Host, Port, Status

SMB_PORTS = (445, 139)


def _smb_port(port: Port) -> bool:
    name = port.service.name if port.service and port.service.name else ""
    return port.portid in SMB_PORTS or name in ("microsoft-ds", "netbios-ssn")


def _primary(ports: list[Port]) -> Port:
    """SMB results are per host: report them against 445 if open, else the first port."""
    return next((p for p in ports if p.portid == 445), ports[0])


class SmbSigning(ScriptCheck):
    check_id = "smb-signing"
    name = "SMB signing"
    scripts = ("smb2-security-mode", "smb-security-mode")

    def matches(self, port: Port) -> bool:
        return _smb_port(port)

    def evaluate(self, host: Host, ports: list[Port], results: ScriptResults) -> list[Finding]:
        smb2 = results.host_output("smb2-security-mode") or ""
        smb1 = results.host_output("smb-security-mode") or ""
        port = _primary(ports)
        target = hp(host, port)
        repro = [nmap_repro(host, [port], ("smb2-security-mode",))]
        problems = []
        if "not required" in smb2 or "disabled" in smb2.lower():
            problems.append("SMBv2+: " + _last_line(smb2))
        match = re.search(r"message_signing:\s*(\w+)", smb1)
        if match and match.group(1) in ("disabled", "supported"):
            problems.append(f"SMBv1: message_signing {match.group(1)}")
            repro.append(nmap_repro(host, [port], ("smb-security-mode",)))
        if problems:
            return [
                finding(
                    "SMB-001",
                    self.check_id,
                    "SMB signing not required",
                    Status.ISSUE,
                    [target],
                    "Without required signing, NTLM authentication to this host can be relayed "
                    "by an attacker on the network.",
                    observed=f"{target}: {'; '.join(problems)}",
                    fix="Require SMB signing (Group Policy: Microsoft network server: Digitally "
                    "sign communications (always); Samba: server signing = mandatory).",
                    reproduce=repro + [f"netexec smb {host.address}  (shows signing:False)"],
                    refs=[nsedoc("smb2-security-mode")],
                )
            ]
        if "required" in smb2 or (match and match.group(1) == "required"):
            return [
                finding(
                    "SMB-001",
                    self.check_id,
                    "SMB signing not required",
                    Status.OK,
                    [target],
                    "SMB signing is required.",
                    reproduce=repro,
                )
            ]
        if set(self.scripts) & results.ran:
            return [self.not_assessed(host, [port], "no SMB security mode was returned")]
        return []


def _last_line(text: str) -> str:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return lines[-1] if lines else text.strip()


class SmbV1(ScriptCheck):
    check_id = "smb-v1"
    name = "SMBv1"
    scripts = ("smb-protocols",)

    def matches(self, port: Port) -> bool:
        return _smb_port(port)

    def evaluate(self, host: Host, ports: list[Port], results: ScriptResults) -> list[Finding]:
        output = results.host_output("smb-protocols")
        port = _primary(ports)
        target = hp(host, port)
        repro = [nmap_repro(host, [port], self.scripts)]
        if not output:
            if "smb-protocols" in results.ran:
                return [self.not_assessed(host, [port], "smb-protocols returned nothing")]
            return []
        dialects = [
            line.split("[", 1)[0].strip()
            for line in output.splitlines()
            if line.strip() and not line.strip().startswith("dialects")
        ]
        if "SMBv1" in output or "NT LM 0.12" in output:
            return [
                finding(
                    "SMB-002",
                    self.check_id,
                    "SMBv1 enabled",
                    Status.ISSUE,
                    [target],
                    "SMBv1 lacks the protections of later versions and was the protocol used by "
                    "worms such as WannaCry.",
                    observed=f"{target}: dialects {', '.join(dialects)}",
                    fix="Disable SMBv1 (Windows: Set-SmbServerConfiguration "
                    "-EnableSMB1Protocol $false; Samba: server min protocol = SMB2_10).",
                    reproduce=repro,
                    refs=[nsedoc("smb-protocols")],
                )
            ]
        return [
            finding(
                "SMB-002",
                self.check_id,
                "SMBv1 enabled",
                Status.OK,
                [target],
                "SMBv1 was not offered.",
                observed=f"{target}: dialects {', '.join(dialects)}",
                reproduce=repro,
            )
        ]


# netexec and smbclient output parsing

NXC_PREFIX = re.compile(r"^SMB\s+\S+\s+\d+\s+\S+\s+(.*)$")


def _nxc_lines(text: str) -> list[str]:
    lines = []
    for raw in text.splitlines():
        match = NXC_PREFIX.match(raw.rstrip())
        if match:
            lines.append(match.group(1))
    return lines


def parse_netexec(text: str) -> tuple[bool | None, list[tuple[str, str]], str | None]:
    """(authenticated, [(share, permissions)], error) from `netexec smb --shares` output.

    The share table is read by the column positions of its header, which copes with
    builds that have or lack the Type column.
    """
    lines = _nxc_lines(text)
    authenticated: bool | None = None
    error = None
    shares: list[tuple[str, str]] = []
    header_index = None
    for index, line in enumerate(lines):
        if line.startswith("[+]"):
            authenticated = True
        elif line.startswith("[-]"):
            if "Error enumerating shares" in line:
                error = line[3:].strip()
            else:
                authenticated = False
                error = line[3:].strip()
        if line.startswith("Share") and "Permissions" in line:
            header_index = index
    if header_index is not None:
        header = lines[header_index]
        perm_start = header.index("Permissions")
        type_start = header.find("Type")
        remark_start = header.find("Remark")
        perm_end = type_start if type_start > perm_start else remark_start
        for line in lines[header_index + 2 :]:
            if line.startswith("[") or not line.strip():
                break
            name = line[:perm_start].strip()
            perms = line[perm_start:perm_end].strip() if perm_end > 0 else line[perm_start:].strip()
            if name:
                shares.append((name, perms))
    return authenticated, shares, error


def parse_smbclient(text: str) -> tuple[bool, list[str], str | None]:
    """(listed, [share names], error) from `smbclient -L -g` output."""
    shares = []
    for line in text.splitlines():
        parts = line.split("|")
        if len(parts) >= 2 and parts[0] in ("Disk", "IPC", "Printer"):
            shares.append(parts[1])
    error = None
    match = re.search(r"(NT_STATUS_[A-Z_]+)", text)
    if match:
        error = match.group(1)
    return bool(shares), shares, error


class SmbNullGuest(DirectCheck):
    """One null and one guest attempt per host, share names only. No password guessing."""

    check_id = "smb-null-guest"
    name = "SMB null and guest session"

    def matches(self, port: Port) -> bool:
        return port.portid == 445

    async def run(self, ctx: CheckContext, host: Host, ports: list[Port]) -> list[Finding]:
        port = _primary(ports)
        netexec = ctx.tool("netexec") or ctx.tool("nxc")
        smbclient = ctx.tool("smbclient")
        if netexec and ctx.netexec_safe(netexec):
            return await self._netexec(ctx, host, port, netexec)
        if smbclient:
            return await self._smbclient(ctx, host, port, smbclient)
        reason = "netexec not found (sudo apt install netexec)"
        if netexec:
            reason = "this netexec build may write to shares, and smbclient is not installed"
        return [
            self.not_assessed(
                host, [port], reason + "; smbclient not found (sudo apt install smbclient)"
            )
        ]

    async def _netexec(self, ctx: CheckContext, host: Host, port: Port, tool: str) -> list[Finding]:
        out: list[Finding] = []
        target = hp(host, port)
        for label, user, fid in (("null", "", "SMB-003"), ("guest", "guest", "SMB-004")):
            cmd = [tool, "smb", host.address, "-u", user, "-p", "", "--shares"]
            result = await ctx.run_tool(self.check_id, target, cmd)
            repro = [shlex.join(["netexec", "smb", host.address, "-u", user, "-p", "", "--shares"])]
            if result.timed_out or result.returncode is None:
                out.append(
                    self.not_assessed(host, [port], f"netexec {label} session timed out or failed")
                )
                continue
            authenticated, shares, error = parse_netexec(result.stdout)
            if authenticated is None:
                out.append(self.not_assessed(host, [port], "could not parse netexec output"))
                continue
            out.append(
                self._result(
                    label,
                    fid,
                    target,
                    authenticated,
                    [f"{name} ({perms or 'no access'})" for name, perms in shares],
                    error,
                    repro,
                )
            )
        return out

    async def _smbclient(
        self, ctx: CheckContext, host: Host, port: Port, tool: str
    ) -> list[Finding]:
        out: list[Finding] = []
        target = hp(host, port)
        attempts = (
            ("null", [tool, "-N", "-L", f"//{host.address}", "-g"], "SMB-003"),
            ("guest", [tool, "-L", f"//{host.address}", "-U", "guest%", "-g"], "SMB-004"),
        )
        for label, cmd, fid in attempts:
            result = await ctx.run_tool(self.check_id, target, cmd)
            repro = [shlex.join(cmd).replace(tool, "smbclient", 1)]
            if result.timed_out or result.returncode is None:
                out.append(
                    self.not_assessed(
                        host, [port], f"smbclient {label} session timed out or failed"
                    )
                )
                continue
            listed, shares, error = parse_smbclient(result.stdout + result.stderr)
            accepted = listed or "Anonymous login successful" in result.stdout
            out.append(
                self._result(label, fid, target, accepted, shares if listed else [], error, repro)
            )
        return out

    def _result(
        self,
        label: str,
        fid: str,
        target: str,
        authenticated: bool,
        shares: list[str],
        error: str | None,
        repro: list[str],
    ) -> Finding:
        title = f"SMB {label} session share listing"
        if authenticated and shares:
            return finding(
                fid,
                self.check_id,
                title,
                Status.ISSUE,
                [target],
                f"A {label} session can list shares without a password, which helps an attacker "
                "map the host and find readable data.",
                observed=f"{target}: {', '.join(shares)}",
                fix="Disable null and guest access (Windows: RestrictAnonymous and the Guest "
                "account; Samba: restrict anonymous = 2, map to guest = never).",
                reproduce=repro,
            )
        if authenticated:
            return finding(
                fid,
                self.check_id,
                f"SMB {label} session accepted",
                Status.OBSERVATION,
                [target],
                f"A {label} session was accepted but share listing was refused.",
                observed=f"{target}: {error or 'share listing refused'}",
                reproduce=repro,
            )
        return finding(
            fid,
            self.check_id,
            title,
            Status.OK,
            [target],
            f"The {label} session was refused.",
            observed=f"{target}: {error}" if error else None,
            reproduce=repro,
        )
