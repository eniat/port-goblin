"""VNC without authentication (vnc-info) and open X11 (-sV result or x11-access).

x11-access skips itself when -sV has already identified the X server, because -sV runs
the same connection test: its extra info reads "open" or "access denied".
"""

from __future__ import annotations

from portgoblin.checks.base import ScriptCheck, ScriptResults, finding, hp, nmap_repro, nsedoc
from portgoblin.core.models import Finding, Host, Port, Status


class VncNoAuth(ScriptCheck):
    check_id = "vnc-auth"
    name = "VNC authentication"
    scripts = ("vnc-info",)

    def matches(self, port: Port) -> bool:
        name = port.service.name if port.service and port.service.name else ""
        return name == "vnc" or 5900 <= port.portid <= 5910

    def evaluate(self, host: Host, ports: list[Port], results: ScriptResults) -> list[Finding]:
        out: list[Finding] = []
        for port in ports:
            target = hp(host, port)
            output = results.port_output(port, "vnc-info")
            if not output:
                continue
            repro = [nmap_repro(host, [port], self.scripts)]
            types = [
                line.strip()
                for line in output.split("Security types:", 1)[-1].splitlines()
                if line.startswith("    ") and line.strip()
            ]
            if "does not require authentication" in output or any(
                t.startswith("None (1)") for t in types
            ):
                out.append(
                    finding(
                        "VNC-001",
                        self.check_id,
                        "VNC with no authentication",
                        Status.ISSUE,
                        [target],
                        "Anyone who can reach the port gets the desktop without a password.",
                        observed=f"{target}: security types {', '.join(types)}",
                        fix="Require a password or system authentication in the VNC server, and "
                        "restrict access to the port.",
                        reproduce=repro,
                        refs=[nsedoc("vnc-info")],
                    )
                )
            else:
                out.append(
                    finding(
                        "VNC-001",
                        self.check_id,
                        "VNC with no authentication",
                        Status.OK,
                        [target],
                        "The server asks for authentication.",
                        observed=f"{target}: security types {', '.join(types)}",
                        reproduce=repro,
                    )
                )
        return out


class X11Open(ScriptCheck):
    check_id = "x11-access"
    name = "X11 access"
    scripts = ("x11-access",)

    def matches(self, port: Port) -> bool:
        name = (port.service.name or "") if port.service else ""
        return name.lower() == "x11" or 6000 <= port.portid <= 6009

    def evaluate(self, host: Host, ports: list[Port], results: ScriptResults) -> list[Finding]:
        out: list[Finding] = []
        for port in ports:
            target = hp(host, port)
            info = (port.service.extrainfo or "") if port.service else ""
            granted = "access is granted" in (results.port_output(port, "x11-access") or "")
            granted = granted or info == "open"
            repro = [
                f"nmap -Pn -sV -p {port.portid} {host.address}  "
                "(X11 extra info: open or access denied)"
            ]
            if granted:
                out.append(
                    finding(
                        "X11-001",
                        self.check_id,
                        "Open X11 server",
                        Status.ISSUE,
                        [target],
                        "Anyone who can connect can capture the screen and keystrokes and inject "
                        "input.",
                        observed=f"{target}: X server access granted",
                        fix="Turn off TCP listening for X (-nolisten tcp) or remove xhost + "
                        "access control exceptions.",
                        reproduce=repro
                        + [f"xdpyinfo -display {host.address}:{port.portid - 6000}"],
                        refs=[nsedoc("x11-access")],
                    )
                )
            elif info == "access denied" or "x11-access" in results.ran:
                out.append(
                    finding(
                        "X11-001",
                        self.check_id,
                        "Open X11 server",
                        Status.OK,
                        [target],
                        "X server access was denied.",
                        reproduce=repro,
                    )
                )
        return out
