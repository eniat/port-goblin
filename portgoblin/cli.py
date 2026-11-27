"""PortGoblin command line interface."""

from __future__ import annotations

import asyncio
import shutil
from datetime import datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape

from portgoblin import TAGLINE, __version__
from portgoblin.core import preflight
from portgoblin.core.config import (
    Config,
    ConfigError,
    cache_dir,
    data_dir,
    load_config,
    runs_dir,
)
from portgoblin.core.engine import (
    Engine,
    Mode,
    RunNotFoundError,
    RunStatus,
    ScanOptions,
    list_runs,
    new_run_id,
)
from portgoblin.core.followup import FollowUpContext, FollowUps
from portgoblin.core.models import CheckRecord, Finding, Report, ScanResult, Status
from portgoblin.core.nmap_parser import parse_many
from portgoblin.core.nmap_runner import NmapError, NmapRunner, find_script_db, parse_script_db
from portgoblin.core.targets import TargetError, build_target_set, read_target_file, split_specs
from portgoblin.output import terminal

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode=None,
    help=f"PortGoblin: {TAGLINE}. nmap scanning and triage for infrastructure tests.",
)

EXIT_INTERRUPTED = 130


class State:
    config_path: Path | None = None


STATE = State()


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"PortGoblin {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True, help="Show the version."
    ),
    config: Path | None = typer.Option(
        None, "--config", help="Config file (default: PORTGOBLIN_CONFIG, then the usual paths)."
    ),
) -> None:
    STATE.config_path = config


def _fail(console: Console, message: str, code: int = 1) -> typer.Exit:
    console.print(f"[red]Error:[/red] {escape(message)}")
    return typer.Exit(code)


def _load_config(console: Console) -> tuple[Config, str]:
    try:
        config, path = load_config(STATE.config_path)
    except ConfigError as exc:
        raise _fail(console, str(exc)) from exc
    return config, str(path) if path else "built-in defaults"


def _check_save_path(console: Console, save: Path | None, assume_yes: bool) -> None:
    """Decide about an existing --save file before any traffic is sent."""
    if save is None:
        return
    if not save.parent.exists():
        raise _fail(console, f"Folder for --save does not exist: {save.parent}", 2)
    if save.is_dir():
        raise _fail(console, f"--save points at a folder: {save}", 2)
    if save.exists():
        if assume_yes:
            raise _fail(
                console,
                f"{save} already exists. With --yes it is not overwritten: remove it or "
                "choose another path.",
                2,
            )
        if not preflight.confirm(
            False, lambda _: console.input(f"{save} exists. Overwrite? [y/N] ")
        ):
            raise _fail(console, "Not overwriting. Choose another --save path.", 2)


def _build_gaps() -> list[Finding]:
    """Parts of the tool that are not built yet are reported, never implied."""
    return [
        Finding(
            finding_id="BUILD-002",
            check="intelligence",
            title="Version intelligence",
            status=Status.NOT_ASSESSED,
            observed="Not assessed: not built yet (build phase 3)",
            why_it_matters="CVE, KEV, EPSS, Exploit-DB and Metasploit lookups come from this.",
        )
    ]


def load_script_db() -> dict[str, set[str]]:
    path = find_script_db()
    if path is None:
        return {}
    return parse_script_db(path.read_text(encoding="utf-8", errors="replace"))


def make_followups(config: Config, workdir: Path, reporter, is_root: bool) -> FollowUps:
    return FollowUps(
        config,
        NmapRunner(config.scan.interrupt_grace_seconds),
        workdir,
        load_script_db(),
        FollowUpContext(config, is_root),
        reporter,
    )


def _scan_report(
    engine: Engine,
    result: ScanResult,
    interrupted: bool,
    followups: FollowUps | None = None,
) -> Report:
    state = engine.state
    findings = _build_gaps() + (followups.findings if followups else [])
    return Report(
        source="scan",
        mode=state.options.mode.value,
        timing=preflight.timing_label(state.options),
        targets=state.target_specs,
        host_count=state.host_count,
        excluded_count=state.excluded_count,
        scan=result,
        hostnames=state.hostnames,
        findings=findings,
        duration_seconds=state.elapsed_seconds,
        interrupted=interrupted,
        run_id=state.run_id,
        tcp_scanned=state.options.tcp,
        udp_scanned=state.options.udp,
        checks_run=followups is not None,
        check_log=followups.ctx.records if followups else [],
    )


def _output(console: Console, report: Report, save: Path | None, verbose: bool) -> None:
    console.print()
    terminal.render_report(console, report, verbose)
    if save:
        try:
            terminal.save_report(save, report, verbose)
            console.print(f"Saved to {escape(str(save))}")
        except OSError as exc:
            console.print(f"[red]Could not save to {escape(str(save))}: {exc.strerror}[/red]")


def _execute(console: Console, engine: Engine, save: Path | None, verbose: bool) -> None:
    followups: FollowUps | None = None
    try:
        with terminal.RichReporter(console) as reporter:
            engine.reporter = reporter
            result = asyncio.run(engine.run())
            if engine.state.options.checks:
                followups = make_followups(
                    engine.config, engine.workdir / "checks", reporter, preflight.is_root()
                )
                asyncio.run(followups.run(result))
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted. Running processes stopped.[/yellow]")
        engine.state.status = RunStatus.INTERRUPTED
        engine.save_state()
        report = _scan_report(engine, engine.collect(tolerant=True), True, followups)
        _output(console, report, save, verbose)
        console.print(f"Working directory kept: {escape(str(engine.workdir))}")
        console.print(f"Resume with: portgoblin resume {engine.state.run_id}")
        raise typer.Exit(EXIT_INTERRUPTED) from None
    except NmapError as exc:
        console.print(f"[red]Scan stopped:[/red] {escape(str(exc))}")
        report = _scan_report(engine, engine.collect(tolerant=True), True, followups)
        _output(console, report, save, verbose)
        console.print(f"Working directory kept: {escape(str(engine.workdir))}")
        console.print(f"Resume with: portgoblin resume {engine.state.run_id}")
        raise typer.Exit(1) from None

    report = _scan_report(engine, result, False, followups)
    _output(console, report, save, verbose)
    if engine.state.keep_raw:
        copied = engine.keep_raw_files(Path(engine.state.keep_raw))
        console.print(
            f"Raw nmap files kept: {len(copied)} files in {escape(engine.state.keep_raw)}"
        )
    engine.cleanup()


@app.command()
def scan(
    targets: list[str] | None = typer.Argument(
        None, help="IPs, CIDRs, ranges (10.0.0.1-50) or hostnames."
    ),
    target_file: Path | None = typer.Option(None, "-f", "--file", help="File of targets."),
    exclude: list[str] | None = typer.Option(None, "--exclude", help="Targets to exclude."),
    exclude_file: Path | None = typer.Option(None, "--exclude-file", help="File of exclusions."),
    internal: bool = typer.Option(False, "--internal", help="Internal test (host discovery)."),
    external: bool = typer.Option(False, "--external", help="External test (-Pn, no discovery)."),
    tcp_only: bool = typer.Option(False, "--tcp-only", help="Skip the UDP scan."),
    udp_only: bool = typer.Option(False, "--udp-only", help="Skip the TCP scans."),
    top_udp: int | None = typer.Option(None, "--top-udp", min=1, max=65535, help="UDP ports."),
    rate: int | None = typer.Option(None, "--rate", min=1, help="nmap --min-rate for TCP."),
    no_checks: bool = typer.Option(False, "--no-checks", help="Skip follow-up checks."),
    save: Path | None = typer.Option(None, "--save", help="Also write the output as plain text."),
    keep_raw: Path | None = typer.Option(
        None, "--keep-raw", help="Copy raw nmap files to this folder before clean-up."
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the Proceed? prompt."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show every port per host."),
    no_color: bool = typer.Option(False, "--no-color", help="Plain output with no colour."),
) -> None:
    """Scan targets: discovery, all TCP ports, service detection and top UDP ports."""
    console = terminal.make_console(no_color)
    if internal == external:
        raise _fail(console, "Choose exactly one of --internal or --external.", 2)
    if tcp_only and udp_only:
        raise _fail(console, "--tcp-only and --udp-only cannot be used together.", 2)
    if not preflight.is_root():
        raise _fail(console, preflight.ROOT_MESSAGE)
    config, _ = _load_config(console)

    try:
        specs = split_specs(targets or [])
        if target_file:
            specs += read_target_file(target_file)
        exclude_specs = split_specs(exclude or [])
        if exclude_file:
            exclude_specs += read_target_file(exclude_file)
        target_set = build_target_set(specs, exclude_specs, config.scan.max_hosts)
    except TargetError as exc:
        raise _fail(console, str(exc), 2) from exc

    _check_save_path(console, save, yes)
    mode = Mode.INTERNAL if internal else Mode.EXTERNAL
    options = ScanOptions(
        mode=mode,
        rate=rate or (config.rates.internal if internal else config.rates.external),
        top_udp=top_udp or config.scan.top_udp,
        tcp=not udp_only,
        udp=not tcp_only,
        udp_parallel=config.scan.udp_parallel,
        checks=not no_checks,
        stats_every=config.scan.stats_every,
    )
    tools = preflight.detect_tools()
    plan = preflight.build_plan(target_set, options, tools, config.scan.udp_parallel)
    checks = "No (--no-checks)" if no_checks else "Yes (read-only, one attempt per service)"
    terminal.banner(console)
    terminal.render_preflight(console, plan, checks, str(save) if save else None)
    if not any(t.name == "nmap" and t.found for t in tools):
        raise _fail(console, f"nmap is not installed ({preflight.INSTALL['nmap']})")
    if not preflight.confirm(yes, console.input):
        console.print("Stopped. No traffic was sent.")
        raise typer.Exit(1)

    engine = Engine.create(
        runs_dir(),
        target_set,
        options,
        config,
        NmapRunner(config.scan.interrupt_grace_seconds),
        save_path=str(save) if save else None,
        keep_raw=str(keep_raw) if keep_raw else None,
    )
    console.print(f"Run {engine.state.run_id} started")
    _execute(console, engine, save, verbose)


@app.command()
def resume(
    run_id: str = typer.Argument(..., help="Run ID from portgoblin runs."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the Proceed? prompt."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show every port per host."),
    no_color: bool = typer.Option(False, "--no-color", help="Plain output with no colour."),
) -> None:
    """Continue an interrupted run."""
    console = terminal.make_console(no_color)
    if not preflight.is_root():
        raise _fail(console, preflight.ROOT_MESSAGE)
    config, _ = _load_config(console)
    try:
        engine = Engine.load(
            runs_dir(), run_id, config, NmapRunner(config.scan.interrupt_grace_seconds)
        )
    except RunNotFoundError as exc:
        raise _fail(console, str(exc), 2) from exc
    state = engine.state
    terminal.banner(console)
    terminal.render_runs(console, [(engine.workdir, state)], hint=False)
    console.print(
        f"Mode {state.options.mode.value}, {state.host_count} hosts, "
        f"{', '.join(state.target_specs)}"
    )
    if not preflight.confirm(yes, console.input):
        console.print("Stopped. No traffic was sent.")
        raise typer.Exit(1)
    # The --save file of an interrupted run belongs to that run, so it is overwritten.
    save = Path(state.save_path) if state.save_path else None
    _execute(console, engine, save, verbose)


@app.command("import")
def import_(
    files: list[Path] = typer.Argument(..., help="nmap XML files (TCP, UDP or both)."),
    no_checks: bool = typer.Option(False, "--no-checks", help="Skip follow-up checks."),
    save: Path | None = typer.Option(None, "--save", help="Also write the output as plain text."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Do not ask questions."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show every port per host."),
    no_color: bool = typer.Option(False, "--no-color", help="Plain output with no colour."),
) -> None:
    """Analyse existing nmap XML files instead of scanning."""
    console = terminal.make_console(no_color)
    _check_save_path(console, save, yes)
    result = parse_many(files)
    if not result.hosts and len(result.parse_errors) == len(files):
        for error in result.parse_errors:
            console.print(f"[red]Not assessed:[/red] {escape(error)}")
        raise typer.Exit(1)
    findings = _build_gaps()
    followups: FollowUps | None = None
    if not no_checks:
        followups = _import_checks(console, result, yes, findings)
    report = Report(
        source="import",
        imported_files=[str(f) for f in files],
        scan=result,
        findings=findings + (followups.findings if followups else []),
        tcp_scanned=any(p.protocol == "tcp" for h in result.hosts.values() for p in h.ports),
        udp_scanned=any(p.protocol == "udp" for h in result.hosts.values() for p in h.ports),
        checks_run=followups is not None,
        check_log=followups.ctx.records if followups else [],
    )
    _output(console, report, save, verbose)
    if followups and followups.interrupted:
        raise typer.Exit(EXIT_INTERRUPTED)


def _import_checks(
    console: Console, result: ScanResult, yes: bool, findings: list[Finding]
) -> FollowUps | None:
    """Follow-up checks for imported hosts, after a prompt: they send traffic."""
    config, _ = _load_config(console)
    workdir = data_dir() / "imports" / new_run_id()
    followups = make_followups(config, workdir, None, preflight.is_root())
    plan = followups.plan(result)
    if not plan:
        console.print("No imported service matches a follow-up check.")
        return None
    terminal.banner(console)
    terminal.render_import_preflight(console, plan, preflight.detect_tools(), preflight.is_root())
    if not preflight.confirm(yes, console.input):
        console.print("Follow-up checks skipped. No traffic was sent.")
        findings.append(_not_assessed_checks("Not assessed: skipped at the Proceed? prompt"))
        return None
    reachable, attempts = preflight.check_reachability(result, config.timeouts.reachability)
    for host, port, ok in attempts:
        followups.ctx.record(
            CheckRecord(
                target=f"{host}:{port}",
                check="reachability",
                sent="TCP connect",
                result="connected" if ok else "no connection",
            )
        )
    if attempts and not reachable:
        findings.append(_not_assessed_checks(preflight.NOT_REACHABLE, [h for h, _, _ in attempts]))
        return followups
    try:
        with terminal.RichReporter(console) as reporter:
            followups.reporter = reporter
            asyncio.run(followups.run(result))
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted. Results so far:[/yellow]")
        followups.interrupted = True
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    return followups


def _not_assessed_checks(reason: str, hosts: list[str] | None = None) -> Finding:
    return Finding(
        finding_id="NA-follow-up",
        check="follow-up",
        title="Follow-up checks",
        status=Status.NOT_ASSESSED,
        hosts=hosts or [],
        observed=reason,
        why_it_matters="No follow-up checks ran, so quick wins are not assessed.",
    )


@app.command()
def runs(
    no_color: bool = typer.Option(False, "--no-color", help="Plain output with no colour."),
) -> None:
    """List interrupted runs that can be resumed."""
    console = terminal.make_console(no_color)
    terminal.render_runs(console, list_runs(runs_dir()))


def _cache_summary() -> str:
    directory = cache_dir()
    files = [p for p in directory.rglob("*") if p.is_file()] if directory.is_dir() else []
    if not files:
        return f"{directory} (empty)"
    newest = max(p.stat().st_mtime for p in files)
    stamp = datetime.fromtimestamp(newest).strftime("%Y-%m-%d %H:%M")
    return f"{directory} (last updated {stamp})"


def _script_rows(config: Config) -> list[tuple[str, str, str]]:
    db_path = find_script_db()
    if db_path is None:
        return [(name, "-", "script.db not found") for name in config.nse.allowlist]
    db = parse_script_db(db_path.read_text(encoding="utf-8", errors="replace"))
    rows = []
    for name in config.nse.allowlist:
        categories = db.get(name)
        if categories is None:
            rows.append((name, "-", "Not installed"))
            continue
        unsafe = categories & {"brute", "dos", "exploit", "intrusive"}
        if not unsafe:
            status = "OK (safe)" if "safe" in categories else "OK"
        elif name in config.nse.confirmed_non_safe:
            status = "Confirmed by tester"
        else:
            status = "Blocked: not confirmed"
        rows.append((name, ", ".join(sorted(categories)), status))
    return rows


@app.command()
def doctor(
    no_color: bool = typer.Option(False, "--no-color", help="Plain output with no colour."),
) -> None:
    """Show installed tools, versions, root status and the cache date."""
    console = terminal.make_console(no_color)
    config, config_path = _load_config(console)
    terminal.render_doctor(
        console,
        preflight.detect_tools(),
        preflight.is_root(),
        _cache_summary(),
        _script_rows(config),
        config_path,
    )


if __name__ == "__main__":
    app()
