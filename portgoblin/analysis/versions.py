"""Version intelligence: NVD CVEs for nmap's CPEs, joined with KEV, EPSS, Exploit-DB,
Metasploit and endoflife.date. Every result is version-based and unconfirmed."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date

from portgoblin.core.models import Finding, Port, ScanResult, Status, VersionCve, VersionRow
from portgoblin.intelligence import exploitdb, metasploit
from portgoblin.intelligence.cache import FetchError
from portgoblin.intelligence.eol import EolIndex
from portgoblin.intelligence.exploitdb import ExploitDb, SearchsploitError
from portgoblin.intelligence.kev import KevCatalogue
from portgoblin.intelligence.metasploit import MetasploitIndex
from portgoblin.intelligence.nvd import CpeResult, NvdClient, cpe22_to_23, cpe_version

LABEL = "version-based, unconfirmed, distro backports possible"
DISTRO_RE = re.compile(
    r"\b(Ubuntu|Debian|Red Hat|RHEL|CentOS|Rocky|AlmaLinux|SUSE|Fedora)\b|"
    r"\b(deb\d+u\d+|\d+ubuntu\d|el\d+)\b",
    re.IGNORECASE,
)


def versioned_cpes(port: Port) -> list[str]:
    out = []
    for cpe in port.service.cpes if port.service else []:
        cpe23 = cpe22_to_23(cpe)
        if cpe23 and cpe_version(cpe23) and cpe23 not in out:
            out.append(cpe23)
    return out


def short_label(port: Port) -> str:
    """Product and the first version token: 'OpenSSH 8.9p1' from 'OpenSSH 8.9p1 Ubuntu ...'.
    The distro part is kept as a note on the row."""
    service = port.service
    if not service:
        return "unknown"
    version = (service.version or "").split()
    return " ".join(x for x in (service.product, version[0] if version else "") if x) or (
        service.name or "unknown"
    )


def distro_hint(port: Port) -> str | None:
    if not port.service:
        return None
    text = " ".join(x for x in (port.service.version, port.service.extrainfo) if x)
    match = DISTRO_RE.search(text)
    return match.group(0) if match else None


@dataclass
class Sources:
    """What could be loaded. A missing source becomes a Not assessed line."""

    nvd: NvdClient
    kev: Callable[[], KevCatalogue]
    epss: Callable[[list[str]], dict[str, float]]
    eol: Callable[[], EolIndex]
    exploitdb: ExploitDb | None = None
    metasploit: Callable[[], MetasploitIndex] | None = None
    today: date | None = None


@dataclass
class IntelResult:
    rows: list[VersionRow] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)  # KEV, Metasploit, EOL, Not assessed


def _na(title: str, reason: str, hosts: list[str] | None = None) -> Finding:
    return Finding(
        finding_id=f"NA-intel-{title.lower().replace(' ', '-')}",
        check="intelligence",
        title=title,
        status=Status.NOT_ASSESSED,
        hosts=hosts or [],
        observed=f"Not assessed: {reason}",
        why_it_matters="Version intelligence from this source is missing from the results.",
    )


class VersionIntel:
    def __init__(
        self,
        sources: Sources,
        progress: Callable[[str], None] | None = None,
        max_shown: int = 10,
    ) -> None:
        self.sources = sources
        self.progress = progress or (lambda _text: None)
        self.max_shown = max_shown

    async def run(self, result: ScanResult) -> IntelResult:
        out = IntelResult()
        targets: list[tuple[str, Port, list[str]]] = []
        no_version: list[str] = []
        for host in result.live_hosts():
            for port in sorted(host.ports, key=lambda p: (p.protocol, p.portid)):
                if port.state != "open":
                    continue
                cpes = versioned_cpes(port)
                target = f"{host.address}:{port.portid}" + (
                    "/udp" if port.protocol == "udp" else ""
                )
                if cpes:
                    targets.append((target, port, cpes))
                else:
                    no_version.append(target)
        if no_version:
            out.findings.append(
                _na("CVE check", "CVE check not possible: no version detected", no_version)
            )
        if not targets:
            return out

        lookups = await self._nvd([c for _, _, cpes in targets for c in cpes], out)
        all_cves = sorted({c.cve_id for r in lookups.values() for c in r.cves})
        kev = self._load(out, "CISA KEV", self.sources.kev)
        epss: dict[str, float] = {}
        if all_cves:
            try:
                epss = await asyncio.to_thread(self.sources.epss, all_cves)
            except FetchError as exc:
                out.findings.append(_na("EPSS", f"FIRST EPSS API not reachable ({exc})"))
        exploits = await self._exploits(all_cves, targets, out)
        msf = None
        if self.sources.metasploit is None:
            out.findings.append(
                _na("Metasploit", f"module metadata not found ({metasploit.INSTALL})")
            )
        else:
            msf = self._load(out, "Metasploit", self.sources.metasploit)
        eol = self._load(out, "End of life", self.sources.eol)

        for target, port, cpes in targets:
            row = VersionRow(target=target, service=short_label(port), cpes=cpes)
            seen: set[str] = set()
            for cpe in cpes:
                lookup = lookups.get(cpe)
                if lookup is None:
                    continue
                # A vendor note only helps if the mapped CPE was not one nmap reported anyway.
                if lookup.note and lookup.queried not in cpes and lookup.note not in row.notes:
                    row.notes.append(lookup.note)
                for cve in lookup.cves:
                    if cve.cve_id in seen:
                        continue
                    seen.add(cve.cve_id)
                    row.cves.append(
                        VersionCve(
                            cve_id=cve.cve_id,
                            cvss=cve.cvss,
                            cvss_label=cve.cvss_label,
                            kev=bool(kev and kev.get(cve.cve_id)),
                            epss=epss.get(cve.cve_id),
                            exploits=[
                                f"{e.edb_id} {e.title}" for e in exploits[0].get(cve.cve_id, [])
                            ],
                            metasploit=msf.modules(cve.cve_id) if msf else [],
                        )
                    )
                if eol and row.eol is None:
                    version = cpe_version(cpe) or ""
                    status = eol.check(cpe, version, self.sources.today)
                    if status and status.is_eol:
                        ended = status.eol_from or "(date unknown)"
                        row.eol = f"{status.label} {status.cycle} ended {ended} ({status.link})"
            confirmed = {e.split(" ", 1)[0] for c in row.cves for e in c.exploits}
            row.possible_exploits = [
                f"{e.edb_id} {e.title}"
                for e in exploits[1].get(target, [])
                if e.edb_id not in confirmed
            ]
            hint = distro_hint(port)
            if hint:
                row.notes.append(f"distro build ({hint}): fixes are often backported")
            row.cves.sort(
                key=lambda c: (not c.kev, not c.metasploit, -(c.epss or 0), -(c.cvss or 0))
            )
            if row.cves or row.eol or row.possible_exploits:
                out.rows.append(row)
        out.findings += self._findings(out.rows)
        return out

    def _load(self, out: IntelResult, title: str, loader: Callable):
        try:
            return loader()
        except (FetchError, OSError, ValueError) as exc:
            out.findings.append(_na(title, f"could not load ({exc})"))
            return None

    async def _nvd(self, cpes: list[str], out: IntelResult) -> dict[str, CpeResult]:
        results: dict[str, CpeResult] = {}
        unique = list(dict.fromkeys(cpes))
        failed: list[str] = []
        for index, cpe in enumerate(unique, start=1):
            if failed and failed[-1] == "offline":
                failed.append(cpe)
                continue
            self.progress(f"NVD lookup {index}/{len(unique)}")
            try:
                results[cpe] = await asyncio.to_thread(self.sources.nvd.lookup, cpe)
            except FetchError as exc:
                failed.append(cpe)
                if exc.status is None:
                    # Network-level failure: stop instead of waiting on every CPE.
                    out.findings.append(_na("NVD", f"NVD not reachable ({exc})"))
                    failed.append("offline")
        real_failures = [c for c in failed if c != "offline"]
        if real_failures and not any(f.title == "NVD" for f in out.findings):
            out.findings.append(_na("NVD", f"NVD lookups failed for {len(real_failures)} CPEs"))
        return results

    async def _exploits(self, cves, targets, out):
        by_cve: dict[str, list[exploitdb.Exploit]] = {}
        by_target: dict[str, list[exploitdb.Exploit]] = {}
        edb = self.sources.exploitdb
        if edb is None:
            out.findings.append(_na("Exploit-DB", f"searchsploit not found ({exploitdb.INSTALL})"))
            return by_cve, by_target
        try:
            for index, cve in enumerate(cves, start=1):
                self.progress(f"Exploit-DB {index}/{len(cves)}")
                found = await edb.by_cve(cve)
                if found:
                    by_cve[cve] = found
            for target, port, _cpes in targets:
                service = port.service
                if service and service.product and service.version:
                    by_target[target] = await edb.by_product(service.product, service.version)
        except SearchsploitError as exc:
            out.findings.append(_na("Exploit-DB", str(exc)))
        return by_cve, by_target

    def _findings(self, rows: list[VersionRow]) -> list[Finding]:
        findings: list[Finding] = []
        highlighted = [r for r in rows if r.kev_count or r.metasploit_count]
        groups: dict[str, list[VersionRow]] = {}
        for row in highlighted:
            groups.setdefault(row.service, []).append(row)
        for index, (service, group) in enumerate(sorted(groups.items()), start=1):
            first = group[0]
            key_cves = [c for c in first.cves if c.kev or c.metasploit]
            lines = [f"{r.target}: {service}" for r in group]
            for cve in key_cves[: self.max_shown]:
                parts = [cve.cve_id, f"CVSS {cve.cvss_label}"]
                if cve.kev:
                    parts.append("CISA KEV")
                if cve.epss is not None:
                    parts.append(f"EPSS {cve.epss:.2f}")
                if cve.metasploit:
                    parts.append("Metasploit " + ", ".join(cve.metasploit))
                if cve.exploits:
                    parts.append(
                        "Exploit-DB " + ", ".join(e.split(" ", 1)[0] for e in cve.exploits)
                    )
                lines.append("  " + "; ".join(parts))
            lines.append(f"  ({LABEL})")
            tags = []
            if any(r.kev_count for r in group):
                tags.append("KEV-listed CVE")
            if any(r.metasploit_count for r in group):
                tags.append("Metasploit module")
            host, _, port = first.target.partition(":")
            port_number = port.split("/")[0]
            udp = "-sU " if port.endswith("/udp") else ""
            findings.append(
                Finding(
                    finding_id=f"VER-{index:03d}",
                    check="version-intelligence",
                    title=f"{service}: {' and '.join(tags)}",
                    status=Status.MANUAL_CHECK,
                    hosts=[r.target for r in group],
                    observed="\n".join(lines),
                    why_it_matters="The reported version matches a CVE that CISA lists as "
                    "exploited in the wild or that has a Metasploit module.",
                    remediation="Upgrade to a fixed version, after confirming the installed "
                    "version and patch level.",
                    reproduce=[
                        f"nmap -Pn -sV {udp}-p {port_number} {host}",
                        f"searchsploit --cve {key_cves[0].cve_id}",
                    ],
                    manual_steps=[
                        "Confirm the exact version and patch level on the host (package manager "
                        "or vendor build): distros often backport fixes without changing the "
                        "version string.",
                    ],
                    references=[
                        f"https://nvd.nist.gov/vuln/detail/{c.cve_id}" for c in key_cves[:3]
                    ],
                )
            )
        eol_groups: dict[str, list[VersionRow]] = {}
        for row in rows:
            if row.eol:
                eol_groups.setdefault(row.eol, []).append(row)
        for index, (eol, group) in enumerate(sorted(eol_groups.items()), start=1):
            host, _, port = group[0].target.partition(":")
            findings.append(
                Finding(
                    finding_id=f"EOL-{index:03d}",
                    check="end-of-life",
                    title=f"End-of-life software: {eol.split(' (')[0]}",
                    status=Status.MANUAL_CHECK,
                    hosts=[r.target for r in group],
                    observed="\n".join(f"{r.target}: {r.service}" for r in group)
                    + f"\n  ({LABEL})",
                    why_it_matters="Upstream no longer ships security fixes for this release, "
                    "unless a vendor or distro provides extended support.",
                    remediation="Upgrade to a supported release, or confirm the vendor or distro "
                    "still supports this build.",
                    reproduce=[f"nmap -Pn -sV -p {port.split('/')[0]} {host}"],
                    manual_steps=[
                        "Check whether the OS vendor supports this package version (for example "
                        "Ubuntu ESM or RHEL) before reporting it as unsupported."
                    ],
                    references=[eol.rsplit("(", 1)[-1].rstrip(")")],
                )
            )
        return findings
