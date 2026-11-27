"""Groups open services by type and builds copy-ready host:port and URL lists."""

from __future__ import annotations

from dataclasses import dataclass, field

from portgoblin.core.models import Host, Port, ScanResult, ip_sort_key

# Order here is the display order.
GROUPS: list[tuple[str, set[str]]] = [
    ("SMB", {"microsoft-ds", "netbios-ssn", "smb"}),
    ("RDP", {"ms-wbt-server", "rdp"}),
    ("SSH", {"ssh"}),
    ("Web", set()),
    (
        "Databases",
        {
            "mysql",
            "ms-sql-s",
            "ms-sql-m",
            "postgresql",
            "oracle-tns",
            "oracle",
            "mongodb",
            "mongod",
            "redis",
            "cassandra",
            "couchdb",
            "memcache",
            "memcached",
            "elasticsearch",
            "db2",
            "sybase",
            "firebird",
            "gds_db",
        },
    ),
    (
        "Mail",
        {"smtp", "smtps", "submission", "pop3", "pop3s", "imap", "imaps", "lmtp"},
    ),
    ("DNS", {"domain"}),
    ("SNMP", {"snmp", "snmptrap"}),
    (
        "Directory and Kerberos",
        {
            "ldap",
            "ldaps",
            "ldapssl",
            "globalcatldap",
            "globalcatldapssl",
            "kerberos-sec",
            "kpasswd5",
        },
    ),
    (
        "File sharing",
        {"ftp", "ftps", "ftp-data", "tftp", "nfs", "mountd", "rsync", "afp", "iscsi"},
    ),
    (
        "Remote access",
        {"telnet", "vnc", "vnc-http", "x11", "login", "shell", "exec", "rlogin", "rsh", "rexec"},
    ),
    (
        "Management interfaces",
        {"asf-rmcp", "ipmi", "docker", "wsman", "wsmans", "kubernetes", "jetdirect", "snmp-mgmt"},
    ),
    ("RPC", {"msrpc", "rpcbind", "ncacn_http"}),
    ("VPN", {"isakmp", "openvpn", "pptp", "l2tp", "ipsec-nat-t"}),
]

PORT_FALLBACK = {
    ("tcp", 445): "SMB",
    ("tcp", 139): "SMB",
    ("tcp", 3389): "RDP",
    ("tcp", 22): "SSH",
    ("tcp", 53): "DNS",
    ("udp", 53): "DNS",
    ("udp", 161): "SNMP",
    ("udp", 623): "Management interfaces",
    ("tcp", 2375): "Management interfaces",
    ("tcp", 2376): "Management interfaces",
    ("tcp", 9200): "Databases",
}

HTTPS_NAMES = {"https", "https-alt", "ssl/http", "ssl/https"}


def is_web(port: Port) -> bool:
    name = (port.service.name or "").lower() if port.service else ""
    return port.protocol == "tcp" and ("http" in name) and name not in ("ncacn_http",)


def is_tls(port: Port) -> bool:
    if not port.service:
        return False
    return port.service.tunnel == "ssl" or (port.service.name or "").lower() in HTTPS_NAMES


def classify(port: Port) -> str:
    if is_web(port):
        return "Web"
    name = (port.service.name or "").lower() if port.service else ""
    for group, names in GROUPS:
        if name in names:
            return group
    fallback = PORT_FALLBACK.get((port.protocol, port.portid))
    if fallback:
        return fallback
    return f"Other ({name})" if name and name != "unknown" else "Other (unidentified)"


def display_host(host: Host, hostnames: dict[str, list[str]]) -> str:
    """Use a hostname only if the tester gave the target as a hostname."""
    names = hostnames.get(host.address) or host.user_hostnames
    return names[0] if names else host.address


def web_url(host_label: str, port: Port) -> str:
    scheme = "https" if is_tls(port) else "http"
    default = 443 if scheme == "https" else 80
    if port.portid == default:
        return f"{scheme}://{host_label}"
    return f"{scheme}://{host_label}:{port.portid}"


@dataclass
class ServiceGroup:
    name: str
    entries: list[str] = field(default_factory=list)


def _group_order(name: str) -> tuple[int, str]:
    for index, (group, _) in enumerate(GROUPS):
        if group == name:
            return (index, "")
    return (len(GROUPS), name)


def group_services(
    result: ScanResult, hostnames: dict[str, list[str]] | None = None
) -> list[ServiceGroup]:
    """Only confirmed open ports. UDP open|filtered is listed separately.

    Web services print as URLs using the hostname the tester gave, if any. Everything
    else prints as IP:port so it pastes straight into nmap or netexec.
    """
    hostnames = hostnames or {}
    groups: dict[str, list[tuple[tuple, str]]] = {}
    for host in sorted(result.hosts.values(), key=lambda h: ip_sort_key(h.address)):
        label = display_host(host, hostnames)
        for port in sorted(host.ports, key=lambda p: (p.protocol, p.portid)):
            if port.state != "open":
                continue
            group = classify(port)
            if group == "Web":
                entry = web_url(label, port)
            else:
                suffix = "/udp" if port.protocol == "udp" else ""
                entry = f"{host.address}:{port.portid}{suffix}"
            sort_key = (ip_sort_key(host.address), port.protocol, port.portid)
            groups.setdefault(group, []).append((sort_key, entry))
    ordered = sorted(groups, key=_group_order)
    return [ServiceGroup(name, [entry for _, entry in sorted(groups[name])]) for name in ordered]


def open_filtered_udp(result: ScanResult) -> list[str]:
    entries = []
    for host in sorted(result.hosts.values(), key=lambda h: ip_sort_key(h.address)):
        for port in host.ports_in_state("udp", "open|filtered"):
            entries.append(f"{host.address}:{port.portid}/udp")
    return entries
