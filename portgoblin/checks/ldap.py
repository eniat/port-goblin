"""LDAP: anonymous search (ldap-search, one object, DN only) and naming contexts."""

from __future__ import annotations

import re

from portgoblin.checks.base import ScriptCheck, ScriptResults, finding, hp, nmap_repro, nsedoc
from portgoblin.core.models import Finding, Host, Port, Status

ARGS = "ldap.maxobjects=1,ldap.attrib=distinguishedName"


def naming_contexts(rootdse: str) -> list[str]:
    found = []
    for match in re.finditer(r"(?:namingContexts|defaultNamingContext):\s*(\S.*)", rootdse):
        value = match.group(1).strip()
        if value not in found:
            found.append(value)
    return found


def _ldapsearch(host: Host, port: Port, contexts: list[str]) -> str:
    base = contexts[0] if contexts else ""
    url = f"ldap://{host.address}:{port.portid}"
    return f"ldapsearch -x -H {url} -b '{base}' -s base dn"


class LdapAnonymous(ScriptCheck):
    check_id = "ldap-anonymous"
    name = "LDAP anonymous search"
    scripts = ("ldap-rootdse", "ldap-search")
    script_args = ARGS

    def matches(self, port: Port) -> bool:
        name = port.service.name if port.service and port.service.name else ""
        return port.portid in (389, 636, 3268, 3269) or name in ("ldap", "ldapssl")

    def evaluate(self, host: Host, ports: list[Port], results: ScriptResults) -> list[Finding]:
        out: list[Finding] = []
        for port in ports:
            target = hp(host, port)
            search = results.port_output(port, "ldap-search") or ""
            rootdse = results.port_output(port, "ldap-rootdse") or ""
            contexts = naming_contexts(rootdse)
            repro = [nmap_repro(host, [port], ("ldap-search",), args=ARGS)]
            dns = re.findall(r"^\s*dn:\s*(\S.*)$", search, re.MULTILINE)
            if dns:
                out.append(
                    finding(
                        "LDAP-001",
                        self.check_id,
                        "LDAP anonymous search allowed",
                        Status.ISSUE,
                        [target],
                        "Anonymous users can search the directory, which often exposes users, "
                        "groups and computers.",
                        observed=f"{target}: returned {dns[0]} (search limited to 1 object)",
                        fix="Disable anonymous binds or searches (OpenLDAP: olcDisallows "
                        "bind_anon; AD: dsHeuristics, do not grant ANONYMOUS LOGON read).",
                        reproduce=repro + [_ldapsearch(host, port, contexts)],
                        refs=[nsedoc("ldap-search")],
                    )
                )
            elif {"ldap-search"} <= results.ran:
                out.append(
                    finding(
                        "LDAP-001",
                        self.check_id,
                        "LDAP anonymous search allowed",
                        Status.OK,
                        [target],
                        "The anonymous search returned nothing.",
                        reproduce=repro,
                    )
                )
            if contexts:
                out.append(
                    finding(
                        "LDAP-002",
                        self.check_id,
                        "LDAP naming contexts readable",
                        Status.OBSERVATION,
                        [target],
                        "The root DSE is readable anonymously, which is normal, and names the "
                        "directory (for AD, the domain).",
                        observed=f"{target}: {', '.join(contexts)}",
                        reproduce=[nmap_repro(host, [port], ("ldap-rootdse",))],
                    )
                )
        return out
