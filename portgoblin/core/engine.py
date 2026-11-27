"""Scan phases, chunking, working directory state and resume."""

from __future__ import annotations

import asyncio
import secrets
import shutil
import time
from collections.abc import Callable
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, Field

from portgoblin.core import nmap_runner as nr
from portgoblin.core.config import Config
from portgoblin.core.models import ScanResult, ip_sort_key
from portgoblin.core.nmap_parser import is_complete, parse_file, parse_many
from portgoblin.core.targets import TargetSet, chunk_ips

STATE_FILE = "state.json"
STATE_VERSION = 1
PHASES = ("discovery", "tcp_all", "tcp_svc", "udp")
PHASE_LABELS = {
    "discovery": "Host discovery",
    "tcp_all": "All TCP ports",
    "tcp_svc": "TCP service detection",
    "udp": "UDP top ports",
}


class Mode(str, Enum):
    INTERNAL = "internal"
    EXTERNAL = "external"


class PhaseStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    SKIPPED = "skipped"


class RunStatus(str, Enum):
    RUNNING = "running"
    INTERRUPTED = "interrupted"
    FAILED = "failed"
    COMPLETE = "complete"


class ScanOptions(BaseModel):
    mode: Mode
    rate: int
    top_udp: int
    tcp: bool = True
    udp: bool = True
    udp_parallel: bool = True
    checks: bool = True
    stats_every: str = "30s"

    def phases(self) -> list[str]:
        phases = []
        if self.mode is Mode.INTERNAL:
            phases.append("discovery")
        if self.tcp:
            phases += ["tcp_all", "tcp_svc"]
        if self.udp:
            phases.append("udp")
        return phases


class ChunkState(BaseModel):
    index: int
    host_count: int
    phases: dict[str, PhaseStatus]
    svc_done: list[str] = Field(default_factory=list)


class RunState(BaseModel):
    version: int = STATE_VERSION
    run_id: str
    created: str
    status: RunStatus = RunStatus.RUNNING
    options: ScanOptions
    target_specs: list[str]
    exclude_specs: list[str]
    host_count: int
    excluded_count: int
    hostnames: dict[str, list[str]] = Field(default_factory=dict)
    chunks: list[ChunkState]
    elapsed_seconds: float = 0.0
    error: str | None = None
    save_path: str | None = None
    keep_raw: str | None = None


class Reporter(Protocol):
    def chunk_start(self, index: int, total: int, host_count: int) -> None: ...
    def phase_start(self, key: str, label: str) -> None: ...
    def phase_progress(self, key: str, progress: nr.Progress) -> None: ...
    def phase_end(self, key: str) -> None: ...
    def message(self, text: str) -> None: ...


class NullReporter:
    def chunk_start(self, index: int, total: int, host_count: int) -> None:
        pass

    def phase_start(self, key: str, label: str) -> None:
        pass

    def phase_progress(self, key: str, progress: nr.Progress) -> None:
        pass

    def phase_end(self, key: str) -> None:
        pass

    def message(self, text: str) -> None:
        pass


class Runner(Protocol):
    async def run(
        self, cmd: list[str], on_line: Callable[[str], None] | None = None
    ) -> nr.RunResult: ...


class RunNotFoundError(Exception):
    pass


def new_run_id() -> str:
    return datetime.now(UTC).strftime("%Y%m%d-%H%M%S-") + secrets.token_hex(2)


def _atomic_write(path: Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def load_state(workdir: Path) -> RunState:
    path = workdir / STATE_FILE
    if not path.is_file():
        raise RunNotFoundError(f"No run state in {workdir}")
    try:
        return RunState.model_validate_json(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise RunNotFoundError(f"Run state in {workdir} is unreadable: {exc}") from exc


def list_runs(base: Path) -> list[tuple[Path, RunState | None]]:
    if not base.is_dir():
        return []
    runs = []
    for workdir in sorted(base.iterdir()):
        if workdir.is_dir():
            try:
                runs.append((workdir, load_state(workdir)))
            except RunNotFoundError:
                runs.append((workdir, None))
    return runs


class Engine:
    def __init__(
        self,
        workdir: Path,
        state: RunState,
        config: Config,
        runner: Runner,
        reporter: Reporter | None = None,
    ) -> None:
        self.workdir = workdir
        self.state = state
        self.config = config
        self.runner = runner
        self.reporter = reporter or NullReporter()

    @classmethod
    def create(
        cls,
        base: Path,
        target_set: TargetSet,
        options: ScanOptions,
        config: Config,
        runner: Runner,
        reporter: Reporter | None = None,
        save_path: str | None = None,
        keep_raw: str | None = None,
    ) -> Engine:
        run_id = new_run_id()
        workdir = base / run_id
        workdir.mkdir(parents=True, mode=0o700)
        chunks = chunk_ips(target_set.ips, config.scan.chunk_prefix)
        chunk_states = []
        phases = options.phases()
        for index, ips in enumerate(chunks):
            cdir = workdir / f"chunk_{index:03d}"
            cdir.mkdir()
            (cdir / "targets.txt").write_text("\n".join(ips) + "\n", encoding="utf-8")
            chunk_states.append(
                ChunkState(
                    index=index,
                    host_count=len(ips),
                    phases={
                        p: PhaseStatus.PENDING if p in phases else PhaseStatus.SKIPPED
                        for p in PHASES
                    },
                )
            )
        excluded_ips = sorted(
            {ip for exclusion in target_set.exclusions for ip in exclusion.ips}, key=ip_sort_key
        )
        if excluded_ips:
            (workdir / "exclude.txt").write_text("\n".join(excluded_ips) + "\n", encoding="utf-8")
        state = RunState(
            run_id=run_id,
            created=datetime.now(UTC).isoformat(timespec="seconds"),
            options=options,
            target_specs=[t.spec for t in target_set.targets],
            exclude_specs=[t.spec for t in target_set.exclusions],
            host_count=target_set.host_count,
            excluded_count=target_set.excluded_count,
            hostnames=target_set.hostnames,
            chunks=chunk_states,
            save_path=save_path,
            keep_raw=keep_raw,
        )
        engine = cls(workdir, state, config, runner, reporter)
        engine.save_state()
        return engine

    @classmethod
    def load(
        cls,
        base: Path,
        run_id: str,
        config: Config,
        runner: Runner,
        reporter: Reporter | None = None,
    ) -> Engine:
        if "/" in run_id or run_id in ("", ".", ".."):
            raise RunNotFoundError(f"Invalid run ID: {run_id}")
        workdir = base / run_id
        state = load_state(workdir)
        if state.version != STATE_VERSION:
            raise RunNotFoundError(f"Run {run_id} was made by an incompatible version")
        return cls(workdir, state, config, runner, reporter)

    # State

    def save_state(self) -> None:
        _atomic_write(self.workdir / STATE_FILE, self.state.model_dump_json(indent=2))

    @property
    def exclude_file(self) -> Path | None:
        path = self.workdir / "exclude.txt"
        return path if path.is_file() else None

    def chunk_dir(self, chunk: ChunkState) -> Path:
        return self.workdir / f"chunk_{chunk.index:03d}"

    # Running

    async def run(self) -> ScanResult:
        """Run (or continue) every pending phase. Returns the merged results.

        On Ctrl+C or any error the working directory and state are kept for resume.
        """
        started = time.monotonic()
        self.state.status = RunStatus.RUNNING
        self.state.error = None
        self.save_state()
        try:
            total = len(self.state.chunks)
            for chunk in self.state.chunks:
                if all(s in (PhaseStatus.DONE, PhaseStatus.SKIPPED) for s in chunk.phases.values()):
                    continue
                self.reporter.chunk_start(chunk.index, total, chunk.host_count)
                await self._run_chunk(chunk)
        except nr.NmapError as exc:
            self.state.status = RunStatus.FAILED
            self.state.error = str(exc)
            raise
        except BaseException:
            self.state.status = RunStatus.INTERRUPTED
            raise
        else:
            self.state.status = RunStatus.COMPLETE
        finally:
            self.state.elapsed_seconds += time.monotonic() - started
            self.save_state()
        return self.collect()

    async def _run_chunk(self, chunk: ChunkState) -> None:
        cdir = self.chunk_dir(chunk)
        live_file = cdir / "targets.txt"
        if chunk.phases["discovery"] is not PhaseStatus.SKIPPED:
            await self._nmap_phase(
                chunk,
                "discovery",
                cdir / "discovery",
                nr.discovery_cmd(
                    cdir / "targets.txt",
                    cdir / "discovery",
                    self.exclude_file,
                    self.state.options.stats_every,
                ),
            )
            live = self._live_from_discovery(cdir / "discovery.xml")
            live_file = cdir / "live.txt"
            live_file.write_text("\n".join(live) + ("\n" if live else ""), encoding="utf-8")
            if not live:
                self.reporter.message(f"Chunk {chunk.index + 1}: no live hosts found")
                for phase in ("tcp_all", "tcp_svc", "udp"):
                    if chunk.phases[phase] is not PhaseStatus.SKIPPED:
                        chunk.phases[phase] = PhaseStatus.DONE
                self.save_state()
                return

        async def tcp_branch() -> None:
            if chunk.phases["tcp_all"] is not PhaseStatus.SKIPPED:
                await self._nmap_phase(
                    chunk,
                    "tcp_all",
                    cdir / "tcp_all",
                    nr.tcp_all_cmd(
                        live_file,
                        cdir / "tcp_all",
                        self.state.options.rate,
                        self.exclude_file,
                        self.state.options.stats_every,
                    ),
                )
            if chunk.phases["tcp_svc"] is not PhaseStatus.SKIPPED:
                await self._svc_phase(chunk)

        async def udp_branch() -> None:
            if chunk.phases["udp"] is not PhaseStatus.SKIPPED:
                await self._nmap_phase(
                    chunk,
                    "udp",
                    cdir / "udp",
                    nr.udp_cmd(
                        live_file,
                        cdir / "udp",
                        self.state.options.top_udp,
                        self.exclude_file,
                        self.state.options.stats_every,
                    ),
                )

        if self.state.options.udp_parallel:
            try:
                async with asyncio.TaskGroup() as group:
                    group.create_task(tcp_branch())
                    group.create_task(udp_branch())
            except ExceptionGroup as group_error:
                # The first failure cancels the other branch; report it plainly.
                raise group_error.exceptions[0] from None
        else:
            await tcp_branch()
            await udp_branch()

    def _live_from_discovery(self, xml: Path) -> list[str]:
        result = parse_file(xml)
        return [h.address for h in result.live_hosts() if h.status == "up"]

    def _key(self, chunk: ChunkState, phase: str, host: str | None = None) -> str:
        return f"{chunk.index}:{phase}" + (f":{host}" if host else "")

    def _label(self, chunk: ChunkState, phase: str, host: str | None = None) -> str:
        label = PHASE_LABELS[phase]
        if len(self.state.chunks) > 1:
            label = f"Chunk {chunk.index + 1}/{len(self.state.chunks)} {label}"
        return f"{label} {host}" if host else label

    async def _execute(self, key: str, label: str, cmd: list[str]) -> nr.RunResult:
        self.reporter.phase_start(key, label)

        def on_line(line: str) -> None:
            progress = nr.parse_progress(line)
            if progress:
                self.reporter.phase_progress(key, progress)

        try:
            return await self.runner.run(cmd, on_line)
        finally:
            self.reporter.phase_end(key)

    @staticmethod
    def _remove_outputs(out_base: Path) -> None:
        for suffix in (".xml", ".nmap", ".gnmap"):
            out_base.with_name(out_base.name + suffix).unlink(missing_ok=True)

    async def _nmap_phase(
        self, chunk: ChunkState, phase: str, out_base: Path, cmd: list[str]
    ) -> None:
        status = chunk.phases[phase]
        if status in (PhaseStatus.DONE, PhaseStatus.SKIPPED):
            return
        xml = out_base.with_name(out_base.name + ".xml")
        normal = out_base.with_name(out_base.name + ".nmap")
        key, label = self._key(chunk, phase), self._label(chunk, phase)

        if status is PhaseStatus.RUNNING:
            # Never --resume a finished run: nmap appends a second document and breaks the XML.
            if is_complete(xml):
                chunk.phases[phase] = PhaseStatus.DONE
                self.save_state()
                return
            if normal.is_file() and normal.stat().st_size > 0:
                result = await self._execute(key, f"{label} (resuming)", nr.resume_cmd(out_base))
                if result.returncode == 0 and is_complete(xml):
                    chunk.phases[phase] = PhaseStatus.DONE
                    self.save_state()
                    return
                self.reporter.message(f"{label}: nmap could not resume, restarting this phase")
            self._remove_outputs(out_base)

        chunk.phases[phase] = PhaseStatus.RUNNING
        self.save_state()
        result = await self._execute(key, label, cmd)
        if result.returncode != 0:
            raise nr.NmapError(_nmap_failure(label, result))
        chunk.phases[phase] = PhaseStatus.DONE
        self.save_state()

    async def _svc_phase(self, chunk: ChunkState) -> None:
        if chunk.phases["tcp_svc"] in (PhaseStatus.DONE, PhaseStatus.SKIPPED):
            return
        cdir = self.chunk_dir(chunk)
        chunk.phases["tcp_svc"] = PhaseStatus.RUNNING
        self.save_state()
        tcp_all = parse_file(cdir / "tcp_all.xml")
        for host in sorted(tcp_all.hosts.values(), key=lambda h: ip_sort_key(h.address)):
            ports = [p.portid for p in host.ports_in_state("tcp", "open")]
            if not ports or host.address in chunk.svc_done:
                continue
            out_base = cdir / f"tcp_svc_{host.address}"
            if is_complete(out_base.with_name(out_base.name + ".xml")):
                chunk.svc_done.append(host.address)
                self.save_state()
                continue
            self._remove_outputs(out_base)
            cmd = nr.tcp_svc_cmd(
                host.address, ports, out_base, self.exclude_file, self.state.options.stats_every
            )
            result = await self._execute(
                self._key(chunk, "tcp_svc", host.address),
                self._label(chunk, "tcp_svc", host.address),
                cmd,
            )
            if result.returncode != 0:
                raise nr.NmapError(_nmap_failure(f"Service detection {host.address}", result))
            chunk.svc_done.append(host.address)
            self.save_state()
        chunk.phases["tcp_svc"] = PhaseStatus.DONE
        self.save_state()

    # Results

    def output_files(self) -> list[Path]:
        files: list[Path] = []
        for cdir in sorted(self.workdir.glob("chunk_*")):
            for name in ("discovery.xml", "tcp_all.xml"):
                if (cdir / name).is_file():
                    files.append(cdir / name)
            files += sorted(cdir.glob("tcp_svc_*.xml"))
            if (cdir / "udp.xml").is_file():
                files.append(cdir / "udp.xml")
        return files

    def collect(self, tolerant: bool = False) -> ScanResult:
        """Parse and merge every output file. tolerant=True for interrupted runs."""
        return parse_many(self.output_files(), tolerant=tolerant)

    def keep_raw_files(self, destination: Path) -> list[Path]:
        destination.mkdir(parents=True, exist_ok=True)
        copied = []
        for cdir in sorted(self.workdir.glob("chunk_*")):
            for path in sorted(cdir.iterdir()):
                if path.suffix in (".xml", ".nmap", ".gnmap"):
                    target = destination / f"{cdir.name}_{path.name}"
                    shutil.copy2(path, target)
                    copied.append(target)
        return copied

    def cleanup(self) -> None:
        shutil.rmtree(self.workdir, ignore_errors=True)


def _nmap_failure(label: str, result: nr.RunResult) -> str:
    tail = " ".join(result.stderr.strip().splitlines()[-3:]) or "no error output"
    return f"{label}: nmap exited with code {result.returncode}: {tail}"


def state_summary(state: RunState) -> dict[str, int]:
    done = sum(
        1
        for chunk in state.chunks
        if all(s in (PhaseStatus.DONE, PhaseStatus.SKIPPED) for s in chunk.phases.values())
    )
    return {"chunks_done": done, "chunks_total": len(state.chunks)}
