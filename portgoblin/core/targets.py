"""Target and exclusion parsing, hostname resolution and chunking."""

from __future__ import annotations

import ipaddress
import re
import socket
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

from portgoblin.core.models import ip_sort_key

HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)
OCTET_RANGE_RE = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$")
FULL_RANGE_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3}){3})$")

Resolver = Callable[[str], list[str]]


class TargetError(ValueError):
    pass


@dataclass
class ParsedTarget:
    spec: str
    ips: list[str]
    hostname: str | None = None


@dataclass
class TargetSet:
    targets: list[ParsedTarget]
    exclusions: list[ParsedTarget]
    ips: list[str]
    excluded_count: int
    hostnames: dict[str, list[str]] = field(default_factory=dict)

    @property
    def host_count(self) -> int:
        return len(self.ips)


def resolve_hostname(name: str) -> list[str]:
    """Resolve a hostname to its IPv4 addresses, once."""
    try:
        infos = socket.getaddrinfo(name, None, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise TargetError(f"Could not resolve hostname {name}: {exc.strerror}") from exc
    ips = {info[4][0] for info in infos}
    if not ips:
        raise TargetError(f"Hostname {name} has no IPv4 address")
    return sorted(ips, key=ip_sort_key)


def _valid_ipv4(text: str) -> ipaddress.IPv4Address:
    try:
        return ipaddress.IPv4Address(text)
    except ipaddress.AddressValueError as exc:
        raise TargetError(f"Invalid IPv4 address: {text}") from exc


def parse_target(spec: str, max_hosts: int, resolver: Resolver = resolve_hostname) -> ParsedTarget:
    spec = spec.strip()
    if not spec:
        raise TargetError("Empty target")
    if ":" in spec:
        raise TargetError(f"IPv6 targets are not supported in this version: {spec}")

    if "/" in spec:
        try:
            network = ipaddress.IPv4Network(spec, strict=False)
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError) as exc:
            raise TargetError(f"Invalid CIDR: {spec}") from exc
        if network.num_addresses > max_hosts:
            raise TargetError(
                f"{spec} has {network.num_addresses} addresses, over the limit of {max_hosts} "
                "(scan.max_hosts in the config)"
            )
        if network.prefixlen >= 31:
            return ParsedTarget(spec, [str(ip) for ip in network])
        return ParsedTarget(spec, [str(ip) for ip in network.hosts()])

    match = OCTET_RANGE_RE.match(spec)
    if match:
        prefix, start, end = match.group(1), int(match.group(2)), int(match.group(3))
        _valid_ipv4(f"{prefix}{start}")
        _valid_ipv4(f"{prefix}{end}")
        if start > end:
            raise TargetError(f"Range start is after range end: {spec}")
        return ParsedTarget(spec, [f"{prefix}{n}" for n in range(start, end + 1)])

    match = FULL_RANGE_RE.match(spec)
    if match:
        start_ip, end_ip = _valid_ipv4(match.group(1)), _valid_ipv4(match.group(2))
        if int(start_ip) > int(end_ip):
            raise TargetError(f"Range start is after range end: {spec}")
        size = int(end_ip) - int(start_ip) + 1
        if size > max_hosts:
            raise TargetError(f"{spec} has {size} addresses, over the limit of {max_hosts}")
        return ParsedTarget(
            spec, [str(ipaddress.IPv4Address(n)) for n in range(int(start_ip), int(end_ip) + 1)]
        )

    if re.fullmatch(r"[\d.]+", spec):
        return ParsedTarget(spec, [str(_valid_ipv4(spec))])

    if HOSTNAME_RE.match(spec):
        name = spec.rstrip(".").lower()
        return ParsedTarget(spec, resolver(name), hostname=name)

    raise TargetError(f"Could not parse target: {spec}")


def read_target_file(path: Path) -> list[str]:
    """Read targets from a file: one or more per line, comma or space separated, # comments."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise TargetError(f"Could not read {path}: {exc.strerror}") from exc
    specs: list[str] = []
    for line in text.splitlines():
        line = line.split("#", 1)[0]
        specs.extend(part for part in re.split(r"[,\s]+", line) if part)
    return specs


def split_specs(values: Iterable[str]) -> list[str]:
    specs: list[str] = []
    for value in values:
        specs.extend(part for part in re.split(r"[,\s]+", value) if part)
    return specs


def build_target_set(
    specs: list[str],
    exclude_specs: list[str],
    max_hosts: int,
    resolver: Resolver = resolve_hostname,
) -> TargetSet:
    if not specs:
        raise TargetError("No targets given")
    targets = [parse_target(spec, max_hosts, resolver) for spec in specs]
    exclusions = [parse_target(spec, max_hosts, resolver) for spec in exclude_specs]

    included: set[str] = set()
    hostnames: dict[str, list[str]] = {}
    for target in targets:
        included.update(target.ips)
        if target.hostname:
            for ip in target.ips:
                names = hostnames.setdefault(ip, [])
                if target.hostname not in names:
                    names.append(target.hostname)
        if len(included) > max_hosts:
            raise TargetError(
                f"Target set is over the limit of {max_hosts} addresses (scan.max_hosts)"
            )

    excluded = {ip for exclusion in exclusions for ip in exclusion.ips}
    final = sorted(included - excluded, key=ip_sort_key)
    if not final:
        raise TargetError("No targets left after exclusions")
    hostnames = {ip: names for ip, names in hostnames.items() if ip in set(final)}
    return TargetSet(
        targets=targets,
        exclusions=exclusions,
        ips=final,
        excluded_count=len(included & excluded),
        hostnames=hostnames,
    )


def chunk_ips(ips: list[str], prefix: int) -> list[list[str]]:
    """Group addresses into chunks by network of the given prefix length, in address order."""
    chunks: dict[ipaddress.IPv4Network, list[str]] = {}
    for ip in sorted(ips, key=ip_sort_key):
        network = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
        chunks.setdefault(network, []).append(ip)
    return [chunks[network] for network in sorted(chunks)]
