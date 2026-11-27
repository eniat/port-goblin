"""Data models for scan results and findings."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class Status(str, Enum):
    ISSUE = "issue"
    OBSERVATION = "observation"
    MANUAL_CHECK = "manual_check"
    OK = "ok"
    NOT_ASSESSED = "not_assessed"


class Finding(BaseModel):
    finding_id: str
    check: str
    title: str
    status: Status
    hosts: list[str] = Field(default_factory=list)
    observed: str | None = None
    why_it_matters: str
    remediation: str | None = None
    reproduce: list[str] = Field(default_factory=list)
    manual_steps: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)


def group_findings(findings: list[Finding]) -> list[Finding]:
    """Merge findings with the same ID and status into one result listing every host.

    Order of first appearance is kept. Hosts, reproduce commands, manual steps and
    references are combined without duplicates.
    """
    grouped: dict[tuple[str, Status], Finding] = {}
    for finding in findings:
        key = (finding.finding_id, finding.status)
        existing = grouped.get(key)
        if existing is None:
            grouped[key] = finding.model_copy(deep=True)
            continue
        for field in ("hosts", "reproduce", "manual_steps", "references"):
            merged = getattr(existing, field)
            for item in getattr(finding, field):
                if item not in merged:
                    merged.append(item)
    return list(grouped.values())


class Script(BaseModel):
    script_id: str
    output: str = ""


class Service(BaseModel):
    name: str | None = None
    product: str | None = None
    version: str | None = None
    extrainfo: str | None = None
    tunnel: str | None = None
    method: str | None = None
    conf: int | None = None
    cpes: list[str] = Field(default_factory=list)

    @property
    def label(self) -> str:
        """Product and version for display, falling back to the service name."""
        parts = [p for p in (self.product, self.version) if p]
        if parts:
            return " ".join(parts)
        return self.name or "unknown"


class Port(BaseModel):
    protocol: str
    portid: int
    state: str
    reason: str | None = None
    service: Service | None = None
    scripts: list[Script] = Field(default_factory=list)

    @property
    def key(self) -> tuple[str, int]:
        return (self.protocol, self.portid)

    def detail_score(self) -> int:
        """How much detail this record carries, used when merging scans."""
        score = 0
        if self.service:
            if self.service.method == "probed":
                score += 4
            if self.service.product:
                score += 2
            if self.service.version:
                score += 1
            if self.service.cpes:
                score += 1
        score += min(len(self.scripts), 5)
        return score


class Host(BaseModel):
    address: str
    status: str = "unknown"
    status_reason: str | None = None
    mac: str | None = None
    hostnames: list[str] = Field(default_factory=list)
    user_hostnames: list[str] = Field(default_factory=list)
    ports: list[Port] = Field(default_factory=list)
    scripts: list[Script] = Field(default_factory=list)

    def is_responsive(self) -> bool:
        """Up for a real reason (not just -Pn), or with any open port."""
        if self.status == "up" and self.status_reason != "user-set":
            return True
        return any(p.state == "open" for p in self.ports)

    def ports_in_state(self, protocol: str, state: str) -> list[Port]:
        return sorted(
            (p for p in self.ports if p.protocol == protocol and p.state == state),
            key=lambda p: p.portid,
        )

    def merge(self, other: Host) -> None:
        if _status_rank(other) > _status_rank(self):
            self.status = other.status
            self.status_reason = other.status_reason
        self.mac = self.mac or other.mac
        for name in other.hostnames:
            if name not in self.hostnames:
                self.hostnames.append(name)
        for name in other.user_hostnames:
            if name not in self.user_hostnames:
                self.user_hostnames.append(name)
        by_key = {p.key: i for i, p in enumerate(self.ports)}
        for port in other.ports:
            index = by_key.get(port.key)
            if index is None:
                by_key[port.key] = len(self.ports)
                self.ports.append(port)
            elif port.detail_score() >= self.ports[index].detail_score():
                self.ports[index] = port
        known = {s.script_id for s in self.scripts}
        for script in other.scripts:
            if script.script_id not in known:
                self.scripts.append(script)


def _status_rank(host: Host) -> int:
    if host.status == "up":
        return 2 if host.status_reason == "user-set" else 3
    return 1 if host.status == "down" else 0


class ScanResult(BaseModel):
    hosts: dict[str, Host] = Field(default_factory=dict)
    sources: list[str] = Field(default_factory=list)
    nmap_versions: list[str] = Field(default_factory=list)
    parse_errors: list[str] = Field(default_factory=list)

    def merge(self, other: ScanResult) -> None:
        for address, host in other.hosts.items():
            if address in self.hosts:
                self.hosts[address].merge(host)
            else:
                self.hosts[address] = host.model_copy(deep=True)
        for field in ("sources", "nmap_versions", "parse_errors"):
            merged = getattr(self, field)
            for item in getattr(other, field):
                if item not in merged:
                    merged.append(item)

    def live_hosts(self) -> list[Host]:
        """Hosts that answered discovery or have an open port. With -Pn every host is
        reported up (reason user-set), so that alone does not count."""
        live = [h for h in self.hosts.values() if h.is_responsive()]
        return sorted(live, key=lambda h: ip_sort_key(h.address))

    def count_ports(self, protocol: str, state: str) -> int:
        return sum(len(h.ports_in_state(protocol, state)) for h in self.hosts.values())


def ip_sort_key(address: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in address.split("."))
    except ValueError:
        return (999,)


class Report(BaseModel):
    source: str  # "scan" or "import"
    mode: str | None = None
    timing: str | None = None
    targets: list[str] = Field(default_factory=list)
    host_count: int | None = None
    excluded_count: int = 0
    imported_files: list[str] = Field(default_factory=list)
    scan: ScanResult
    hostnames: dict[str, list[str]] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    duration_seconds: float | None = None
    interrupted: bool = False
    run_id: str | None = None
    tcp_scanned: bool = True
    udp_scanned: bool = True
