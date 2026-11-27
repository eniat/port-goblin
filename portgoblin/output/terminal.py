"""Terminal output with rich: pre-flight, live progress, the report, runs and doctor."""

from __future__ import annotations

import io
import time
from pathlib import Path

from rich import box
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TaskID, TextColumn, TimeElapsedColumn
from rich.table import Table

from portgoblin import TAGLINE, __version__
from portgoblin.analysis.quick_wins import Sections, sections
from portgoblin.analysis.services import group_services, open_filtered_udp
from portgoblin.core import nmap_runner as nr
from portgoblin.core.engine import RunState, state_summary
from portgoblin.core.models import Finding, Host, Report, Status
from portgoblin.core.preflight import PreflightPlan, ToolStatus, format_duration, timing_label

PORT_LIST_LIMIT = 12


def make_console(no_color: bool = False) -> Console:
    if no_color:
        return Console(color_system=None, highlight=False)
    return Console(highlight=False)


def plural(count: int, word: str) -> str:
    return f"{count} {word}" if count == 1 else f"{count} {word}s"


def host_count_label(entries: list[str]) -> str:
    """'14 hosts', or '1 host, 2 services' when one host has several affected ports."""
    addresses = {entry.split(":", 1)[0] for entry in entries}
    label = plural(len(addresses), "host")
    if len(entries) != len(addresses):
        label += f", {plural(len(entries), 'service')}"
    return label


def banner(console: Console) -> None:
    console.print(f"[bold]PortGoblin {__version__}[/bold] | {TAGLINE}")
    console.print()


def _kv_table() -> Table:
    table = Table(box=None, show_header=False, padding=(0, 2, 0, 0))
    table.add_column(style="bold", no_wrap=True)
    table.add_column()
    return table


def render_preflight(
    console: Console, plan: PreflightPlan, checks: str, save_path: str | None
) -> None:
    ts = plan.target_set
    table = _kv_table()
    for target in ts.targets:
        if target.hostname:
            table.add_row("Target", f"{escape(target.spec)} resolves to {', '.join(target.ips)}")
        else:
            table.add_row("Target", escape(target.spec))
    if ts.exclusions:
        table.add_row("Excluded", escape(", ".join(t.spec for t in ts.exclusions)))
    excluded = f", {ts.excluded_count} excluded" if ts.excluded_count else ""
    table.add_row("Hosts", f"{ts.host_count} after exclusions{excluded}")
    table.add_row("Mode", plan.options.mode.value.capitalize())
    table.add_row("Timing", timing_label(plan.options))
    phases = []
    if plan.options.mode.value == "internal":
        phases.append("1 host discovery")
    else:
        phases.append("no host discovery (-Pn, external)")
    if plan.options.tcp:
        phases += ["2 all TCP ports", "3 TCP service detection"]
    if plan.options.udp:
        when = "parallel with TCP" if plan.options.udp_parallel and plan.options.tcp else ""
        phases.append(f"4 UDP top {plan.options.top_udp} ports" + (f" ({when})" if when else ""))
    table.add_row("Phases", ", ".join(phases))
    table.add_row("Follow-up checks", checks)
    if save_path:
        table.add_row("Save to", escape(save_path))
    missing = plan.missing_tools
    table.add_row(
        "Missing tools",
        ", ".join(f"{t.name} ({t.install})" for t in missing) if missing else "None",
    )
    est = plan.estimate
    parts = []
    if plan.options.tcp:
        parts.append(f"TCP up to {format_duration(est.tcp_seconds)}")
    if plan.options.udp:
        extra = " extra" if plan.options.udp_parallel and plan.options.tcp else ""
        parts.append(f"UDP roughly {format_duration(est.udp_seconds)}{extra}")
    table.add_row(
        "Estimate",
        f"{format_duration(est.total_seconds)} worst case ({'; '.join(parts)}). "
        "Service detection not included.",
    )
    console.print(Panel(table, title="Pre-flight", title_align="left", box=box.ROUNDED))
    for warning in plan.warnings:
        console.print(f"[yellow]Check scope:[/yellow] {escape(warning)}")
    if plan.warnings:
        console.print()


def render_import_preflight(console: Console, plan, tools: list[ToolStatus], root: bool) -> None:
    """What the follow-up checks for an import will contact, before any traffic."""
    hosts = [host.address for host, _ in plan]
    names: list[str] = []
    for _, matched in plan:
        for check, _ports in matched:
            if check.name not in names:
                names.append(check.name)
    udp = any(check.protocol == "udp" for _, matched in plan for check, _ in matched)
    table = _kv_table()
    table.columns[1].overflow = "fold"
    shown = ", ".join(hosts[:20]) + (f" (+{len(hosts) - 20} more)" if len(hosts) > 20 else "")
    table.add_row("Hosts", f"{plural(len(hosts), 'host')}: {shown}")
    table.add_row("Checks", ", ".join(names))
    table.add_row(
        "Traffic",
        "TCP connect to up to 5 hosts, then read-only checks, one attempt per service, "
        "one host at a time",
    )
    if udp and not root:
        table.add_row("UDP checks", "Not run: they need root (sudo)")
    missing = [t for t in tools if not t.found and t.name in ("netexec", "smbclient")]
    if missing:
        table.add_row("Missing tools", ", ".join(f"{t.name} ({t.install})" for t in missing))
    console.print(
        Panel(
            table, title="Follow-up checks for imported hosts", title_align="left", box=box.ROUNDED
        )
    )


class RichReporter:
    """Live progress per phase from nmap's --stats-every output."""

    def __init__(self, console: Console) -> None:
        self.console = console
        self.progress = Progress(
            TextColumn("{task.description}"),
            BarColumn(),
            TextColumn("{task.percentage:>5.1f}%"),
            TextColumn("{task.fields[remaining]}"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        )
        self.tasks: dict[str, TaskID] = {}
        self.labels: dict[str, str] = {}
        self.started: dict[str, float] = {}

    def __enter__(self) -> RichReporter:
        self.progress.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.progress.stop()

    def chunk_start(self, index: int, total: int, host_count: int) -> None:
        if total > 1:
            self.console.print(f"Chunk {index + 1}/{total}: {host_count} hosts")

    def phase_start(self, key: str, label: str) -> None:
        self.labels[key] = label
        self.started[key] = time.monotonic()
        self.tasks[key] = self.progress.add_task(escape(label), total=100, remaining="")

    def phase_progress(self, key: str, progress: nr.Progress) -> None:
        task = self.tasks.get(key)
        if task is not None:
            remaining = f"{progress.remaining} left" if progress.remaining else ""
            self.progress.update(task, completed=progress.percent, remaining=remaining)

    def phase_end(self, key: str) -> None:
        task = self.tasks.pop(key, None)
        if task is not None:
            self.progress.remove_task(task)
            elapsed = time.monotonic() - self.started.pop(key, time.monotonic())
            took = f" ({format_duration(elapsed)})"
            self.console.print(f"  {escape(self.labels.get(key, key))} finished{took}")

    def message(self, text: str) -> None:
        self.console.print(escape(text))


def _port_list(ports: list[int]) -> str:
    if not ports:
        return "-"
    shown = ", ".join(str(p) for p in ports[:PORT_LIST_LIMIT])
    if len(ports) > PORT_LIST_LIMIT:
        shown += f" (+{len(ports) - PORT_LIST_LIMIT} more)"
    return shown


def _summary(console: Console, report: Report) -> None:
    scan = report.scan
    table = _kv_table()
    if report.source == "scan":
        table.add_row("Mode", f"{(report.mode or '').capitalize()} | {report.timing or ''}")
        excluded = f", {report.excluded_count} excluded" if report.excluded_count else ""
        hosts = plural(report.host_count or 0, "host")
        table.add_row("Targets", f"{escape(', '.join(report.targets))} ({hosts}{excluded})")
    else:
        table.add_row("Imported", escape(", ".join(report.imported_files)))
        if scan.nmap_versions:
            table.add_row("nmap", ", ".join(scan.nmap_versions))
    live = len(scan.live_hosts())
    parts = [plural(live, "host")]
    if report.tcp_scanned:
        parts.append(f"{scan.count_ports('tcp', 'open')} TCP open")
    if report.udp_scanned:
        parts.append(f"{scan.count_ports('udp', 'open')} UDP open")
        parts.append(f"{scan.count_ports('udp', 'open|filtered')} UDP open|filtered")
    table.add_row("Live", " | ".join(parts))
    if report.duration_seconds is not None:
        table.add_row("Duration", format_duration(report.duration_seconds))
    if report.interrupted:
        table.add_row("Status", "[yellow]Interrupted: results so far[/yellow]")
    console.print(Panel(table, box=box.ROUNDED))
    console.print()


def _hosts_table(console: Console, report: Report) -> None:
    hosts = report.scan.live_hosts()
    if not hosts:
        console.print("[bold]Hosts[/bold]  No live hosts found")
        console.print()
        return
    table = Table(title="Hosts", title_justify="left", box=box.SIMPLE_HEAD, title_style="bold")
    table.add_column("Host", no_wrap=True)
    table.add_column("Hostname", overflow="fold")
    table.add_column("TCP open")
    table.add_column("UDP open")
    table.add_column("UDP open|filtered", justify="right")
    for host in hosts:
        names = escape("\n".join(host.hostnames)) if host.hostnames else ""
        table.add_row(
            host.address,
            names,
            _port_list([p.portid for p in host.ports_in_state("tcp", "open")]),
            _port_list([p.portid for p in host.ports_in_state("udp", "open")]),
            str(len(host.ports_in_state("udp", "open|filtered"))),
        )
    console.print(table)


def _host_detail(console: Console, host: Host) -> None:
    ports = [p for p in host.ports if p.state in ("open", "open|filtered")]
    if not ports:
        return
    names = f" ({escape(', '.join(host.hostnames))})" if host.hostnames else ""
    table = Table(
        title=f"{host.address}{names}",
        title_justify="left",
        box=box.SIMPLE_HEAD,
        title_style="bold",
    )
    table.add_column("Port", no_wrap=True)
    table.add_column("State", no_wrap=True)
    table.add_column("Service")
    table.add_column("Version")
    table.add_column("CPE", overflow="fold")
    for port in sorted(ports, key=lambda p: (p.protocol, p.portid)):
        service = port.service
        name = service.name if service and service.name else "unknown"
        if service and service.tunnel == "ssl":
            name = f"ssl/{name}"
        version = (
            " ".join(x for x in (service.product, service.version, service.extrainfo) if x)
            if service
            else ""
        )
        table.add_row(
            f"{port.portid}/{port.protocol}",
            port.state,
            escape(name),
            escape(version) or "-",
            escape("\n".join(service.cpes)) if service and service.cpes else "-",
        )
    console.print(table)


def _services(console: Console, report: Report) -> None:
    groups = group_services(report.scan, report.hostnames)
    console.print("[bold]Services[/bold]")
    if not groups:
        console.print("  No open services found")
    for group in groups:
        console.print()
        console.print(f"[bold]{escape(group.name)}[/bold] ({len(group.entries)})")
        for entry in group.entries:
            console.print(entry, markup=False, soft_wrap=True)
    udp_of = open_filtered_udp(report.scan)
    if udp_of:
        console.print()
        console.print(
            f"[bold]UDP open|filtered[/bold] ({len(udp_of)}, not confirmed, not in the lists above)"
        )
        console.print(", ".join(udp_of), markup=False)
    console.print()


STATUS_TAGS = {
    Status.ISSUE: "[bold red]ISSUE[/bold red]",
    Status.MANUAL_CHECK: "[bold yellow]CHECK[/bold yellow]",
    Status.OBSERVATION: "[bold cyan]NOTE[/bold cyan]",
    Status.OK: "[green]OK[/green]",
}
LINE_LIMIT = 5


def _limited(items: list[str], verbose: bool, limit: int = LINE_LIMIT) -> list[str]:
    if verbose or len(items) <= limit:
        return items
    return items[:limit] + [f"(+{len(items) - limit} more, --verbose shows all)"]


def _finding_block(console: Console, finding: Finding, verbose: bool) -> None:
    hosts_label = host_count_label(finding.hosts)
    console.print(
        f"  {STATUS_TAGS.get(finding.status, '')}  {escape(finding.finding_id)}  "
        f"{escape(finding.title)} ({hosts_label})"
    )
    table = Table(box=None, show_header=False, padding=(0, 2, 0, 4))
    table.add_column(style="bold", no_wrap=True)
    table.add_column(overflow="fold")
    table.add_row("Hosts", escape(", ".join(finding.hosts)))
    if finding.observed:
        lines = _limited(finding.observed.splitlines(), verbose)
        table.add_row("Observed", escape("\n".join(lines)))
    table.add_row("Why", escape(finding.why_it_matters))
    if finding.remediation:
        table.add_row("Fix", escape(finding.remediation))
    if finding.reproduce:
        table.add_row("Reproduce", escape("\n".join(_limited(finding.reproduce, verbose, 2))))
    if finding.manual_steps:
        table.add_row("Manual", escape("\n".join(finding.manual_steps)))
    if finding.references and verbose:
        table.add_row("References", escape("\n".join(finding.references)))
    console.print(table)
    console.print()


def _quick_wins(console: Console, parts: Sections, verbose: bool) -> None:
    console.print(
        f"[bold]Quick wins[/bold]   {plural(parts.issue_count, 'issue')} | "
        f"{plural(parts.manual_count, 'manual check')}"
    )
    console.print()
    for finding in parts.quick_wins:
        _finding_block(console, finding, verbose)


def _observations(console: Console, parts: Sections, verbose: bool) -> None:
    if not parts.observations:
        return
    console.print(f"[bold]Observations[/bold]   {len(parts.observations)}")
    console.print()
    for finding in parts.observations:
        _finding_block(console, finding, verbose)


def _passed(console: Console, parts: Sections) -> None:
    if not parts.passed:
        return
    console.print("[bold]Passed checks[/bold]")
    table = _kv_table()
    for finding in parts.passed:
        table.add_row(
            f"{escape(finding.finding_id)} {escape(finding.title)}",
            host_count_label(finding.hosts),
        )
    console.print(table)
    console.print()


def _not_assessed(console: Console, report: Report, parts: Sections, verbose: bool) -> None:
    errors = report.scan.parse_errors
    if not parts.not_assessed and not errors:
        return
    console.print("[bold]Not assessed[/bold]")
    table = _kv_table()
    table.columns[1].overflow = "fold"
    for finding in parts.not_assessed:
        reasons = (finding.observed or "").splitlines()
        hosts = f" ({host_count_label(finding.hosts)})" if finding.hosts else ""
        table.add_row(
            escape(finding.title + hosts),
            escape("\n".join(_limited(reasons, verbose))),
        )
    for error in errors:
        table.add_row("nmap output", escape(f"Not assessed: {error}"))
    console.print(table)
    console.print()


def _check_log(console: Console, report: Report) -> None:
    if not report.check_log:
        return
    table = Table(
        title="Check log (what was sent)",
        title_justify="left",
        box=box.SIMPLE_HEAD,
        title_style="bold",
    )
    for column in ("Target", "Check", "Sent", "Result"):
        table.add_column(column, overflow="fold")
    for record in report.check_log:
        table.add_row(
            escape(record.target), escape(record.check), escape(record.sent), escape(record.result)
        )
    console.print(table)
    console.print()


def render_report(console: Console, report: Report, verbose: bool = False) -> None:
    parts = sections(report.findings)
    banner(console)
    _summary(console, report)
    if report.checks_run:
        _quick_wins(console, parts, verbose)
    _observations(console, parts, verbose)
    _hosts_table(console, report)
    if verbose:
        for host in report.scan.live_hosts():
            _host_detail(console, host)
    console.print()
    _services(console, report)
    _passed(console, parts)
    _not_assessed(console, report, parts, verbose)
    if verbose:
        _check_log(console, report)


def report_text(report: Report, verbose: bool = False, width: int = 120) -> str:
    """The report as plain text with no ANSI codes, for --save."""
    buffer = io.StringIO()
    console = Console(
        file=buffer, width=width, color_system=None, force_terminal=False, highlight=False
    )
    render_report(console, report, verbose)
    return buffer.getvalue()


def save_report(path: Path, report: Report, verbose: bool = False) -> None:
    path.write_text(report_text(report, verbose), encoding="utf-8")


def render_runs(
    console: Console, runs: list[tuple[Path, RunState | None]], hint: bool = True
) -> None:
    if not runs:
        console.print("No interrupted runs.")
        return
    table = Table(box=box.SIMPLE_HEAD)
    for column in ("Run ID", "Created (UTC)", "Status", "Mode"):
        table.add_column(column, no_wrap=True)
    for column in ("Targets", "Chunks done", "Note"):
        table.add_column(column)
    for workdir, state in runs:
        if state is None:
            table.add_row(workdir.name, "-", "unreadable", "-", "-", "-", "state file missing")
            continue
        summary = state_summary(state)
        targets = ", ".join(state.target_specs)
        if len(targets) > 40:
            targets = targets[:37] + "..."
        table.add_row(
            state.run_id,
            state.created.replace("T", " ").split("+")[0],
            state.status.value,
            state.options.mode.value,
            escape(targets),
            f"{summary['chunks_done']}/{summary['chunks_total']}",
            escape(state.error or ""),
        )
    console.print(table)
    if hint:
        console.print("Resume with: portgoblin resume <run-id>")


def render_doctor(
    console: Console,
    tools: list[ToolStatus],
    root: bool,
    cache: str,
    script_rows: list[tuple[str, str, str]],
    config_path: str,
) -> None:
    banner(console)
    table = Table(title="Tools", title_justify="left", box=box.SIMPLE_HEAD, title_style="bold")
    for column in ("Tool", "Status", "Version", "Path or install"):
        table.add_column(column)
    for tool in tools:
        status = "[green]Installed[/green]" if tool.found else "[red]Missing[/red]"
        where = tool.path if tool.found else tool.install
        version = tool.version or ("unknown" if tool.found else "-")
        if tool.note:
            version += f" ({tool.note})"
        table.add_row(tool.name, status, escape(version), escape(where or "-"))
    console.print(table)
    info = _kv_table()
    info.add_row("Running as root", "Yes" if root else "No (scan and resume need root)")
    info.add_row("Cache", escape(cache))
    info.add_row("Config", escape(config_path))
    console.print(info)
    console.print()
    if script_rows:
        scripts = Table(
            title="Allowlisted NSE scripts",
            title_justify="left",
            box=box.SIMPLE_HEAD,
            title_style="bold",
        )
        for column in ("Script", "Categories", "Status"):
            scripts.add_column(column)
        for name, categories, status in script_rows:
            scripts.add_row(name, categories, status)
        console.print(scripts)
