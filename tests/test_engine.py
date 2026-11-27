import asyncio

import pytest

from conftest import FakeRunner
from portgoblin.core.config import Config
from portgoblin.core.engine import (
    Engine,
    Mode,
    PhaseStatus,
    RunNotFoundError,
    RunStatus,
    ScanOptions,
    list_runs,
)
from portgoblin.core.targets import build_target_set


def options(mode=Mode.INTERNAL, **kw):
    return ScanOptions(mode=mode, rate=300, top_udp=200, **kw)


def make_engine(tmp_path, runner, specs=("10.0.0.1-3",), excludes=(), opts=None, config=None):
    config = config or Config()
    ts = build_target_set(list(specs), list(excludes), config.scan.max_hosts)
    return Engine.create(tmp_path / "runs", ts, opts or options(), config, runner)


def phases_called(runner):
    names = []
    for cmd in runner.calls:
        if cmd[1] == "--resume":
            names.append("resume:" + cmd[2].rsplit("/", 1)[1])
        else:
            base = cmd[cmd.index("-oA") + 1].rsplit("/", 2)
            names.append(f"{base[1]}/{base[2]}")
    return names


def test_full_internal_run_and_cleanup(tmp_path):
    runner = FakeRunner(down={"10.0.0.2"})
    engine = make_engine(tmp_path, runner)
    result = asyncio.run(engine.run())
    assert engine.state.status is RunStatus.COMPLETE
    assert sorted(result.hosts) == ["10.0.0.1", "10.0.0.3"]
    assert result.count_ports("udp", "open") == 2
    assert result.count_ports("udp", "open|filtered") == 2
    # Later phases scan live hosts only.
    tcp_all = next(c for c in runner.calls if c[c.index("-oA") + 1].endswith("tcp_all"))
    live = (engine.workdir / "chunk_000" / "live.txt").read_text().split()
    assert tcp_all[tcp_all.index("-iL") + 1].endswith("live.txt") and live == [
        "10.0.0.1",
        "10.0.0.3",
    ]
    svc_hosts = [c[-1] for c in runner.calls if "-sV" in c and "-sS" in c]
    assert svc_hosts == ["10.0.0.1", "10.0.0.3"]
    assert engine.workdir.exists()
    engine.cleanup()
    assert not engine.workdir.exists()


def test_external_skips_discovery_and_uses_pn(tmp_path):
    runner = FakeRunner()
    engine = make_engine(tmp_path, runner, opts=options(Mode.EXTERNAL))
    asyncio.run(engine.run())
    assert not any("-sn" in c for c in runner.calls)
    assert all("-Pn" in c for c in runner.calls)


def test_tcp_only_and_udp_only(tmp_path):
    runner = FakeRunner()
    asyncio.run(make_engine(tmp_path / "a", runner, opts=options(udp=False)).run())
    assert not any("-sU" in c for c in runner.calls)
    runner = FakeRunner()
    asyncio.run(make_engine(tmp_path / "b", runner, opts=options(tcp=False)).run())
    assert not any("-p-" in c for c in runner.calls)
    assert any("-sU" in c for c in runner.calls)


def test_exclusions_never_reach_nmap_target_lists(tmp_path):
    runner = FakeRunner()
    engine = make_engine(tmp_path, runner, specs=["10.0.0.0/29"], excludes=["10.0.0.3", "10.0.0.5"])
    asyncio.run(engine.run())
    targets = (engine.workdir / "chunk_000" / "targets.txt").read_text().split()
    assert "10.0.0.3" not in targets and "10.0.0.5" not in targets
    # Excluded IPs are also passed to nmap as a guard.
    assert (engine.workdir / "exclude.txt").read_text().split() == ["10.0.0.3", "10.0.0.5"]
    assert all("--excludefile" in c for c in runner.calls)


def test_chunks_finish_tcp_before_next_chunk(tmp_path):
    runner = FakeRunner()
    engine = make_engine(
        tmp_path, runner, specs=["10.0.0.1", "10.0.1.1"], opts=options(udp_parallel=False)
    )
    asyncio.run(engine.run())
    assert len(engine.state.chunks) == 2
    order = phases_called(runner)
    last_chunk0 = max(i for i, n in enumerate(order) if n.startswith("chunk_000"))
    first_chunk1 = min(i for i, n in enumerate(order) if n.startswith("chunk_001"))
    assert last_chunk0 < first_chunk1
    assert order[:4] == [
        "chunk_000/discovery",
        "chunk_000/tcp_all",
        "chunk_000/tcp_svc_10.0.0.1",
        "chunk_000/udp",
    ]


def test_ctrl_c_keeps_workdir_and_resume_uses_nmap_resume(tmp_path):
    runner = FakeRunner(interrupt_on="tcp_all")
    engine = make_engine(tmp_path, runner, opts=options(udp_parallel=False))
    with pytest.raises(KeyboardInterrupt):
        asyncio.run(engine.run())
    assert engine.workdir.exists()
    assert engine.state.status is RunStatus.INTERRUPTED
    assert engine.state.chunks[0].phases["discovery"] is PhaseStatus.DONE
    assert engine.state.chunks[0].phases["tcp_all"] is PhaseStatus.RUNNING
    # Results so far are readable from the unclosed XML.
    partial = engine.collect(tolerant=True)
    assert partial.count_ports("tcp", "open") > 0

    runs = list_runs(tmp_path / "runs")
    assert [state.run_id for _, state in runs] == [engine.state.run_id]

    resumed = Engine.load(tmp_path / "runs", engine.state.run_id, Config(), runner)
    runner.calls.clear()
    result = asyncio.run(resumed.run())
    called = phases_called(runner)
    assert called[0] == "resume:tcp_all.nmap"
    assert "chunk_000/discovery" not in called
    assert resumed.state.status is RunStatus.COMPLETE
    assert result.count_ports("tcp", "open") == 6


def test_resume_never_reruns_a_finished_phase(tmp_path):
    runner = FakeRunner()
    engine = make_engine(tmp_path, runner)
    asyncio.run(engine.run())
    # Pretend the run was killed after nmap finished but before the state was saved.
    engine.state.chunks[0].phases["tcp_all"] = PhaseStatus.RUNNING
    engine.save_state()
    runner.calls.clear()
    asyncio.run(Engine.load(tmp_path / "runs", engine.state.run_id, Config(), runner).run())
    assert not any(c[1] == "--resume" for c in runner.calls)


def test_failed_resume_restarts_phase(tmp_path):
    runner = FakeRunner(interrupt_on="udp")
    engine = make_engine(tmp_path, runner, opts=options(udp_parallel=False))
    with pytest.raises(KeyboardInterrupt):
        asyncio.run(engine.run())
    runner.fail_resume = True
    runner.calls.clear()
    asyncio.run(Engine.load(tmp_path / "runs", engine.state.run_id, Config(), runner).run())
    called = phases_called(runner)
    assert called == ["resume:udp.nmap", "chunk_000/udp"]


def test_interrupt_during_service_detection_resumes_remaining_hosts(tmp_path):
    runner = FakeRunner(interrupt_on="tcp_svc")
    engine = make_engine(tmp_path, runner, opts=options(udp=False))
    with pytest.raises(KeyboardInterrupt):
        asyncio.run(engine.run())
    runner.calls.clear()
    asyncio.run(Engine.load(tmp_path / "runs", engine.state.run_id, Config(), runner).run())
    assert [c[-1] for c in runner.calls] == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]


def test_parallel_udp_interrupt(tmp_path):
    runner = FakeRunner(interrupt_on="udp")
    engine = make_engine(tmp_path, runner)
    with pytest.raises(KeyboardInterrupt):
        asyncio.run(engine.run())
    assert engine.state.status is RunStatus.INTERRUPTED
    assert engine.workdir.exists()


def test_no_live_hosts(tmp_path):
    runner = FakeRunner(down={"10.0.0.1", "10.0.0.2", "10.0.0.3"})
    engine = make_engine(tmp_path, runner)
    result = asyncio.run(engine.run())
    assert len(runner.calls) == 1
    assert result.live_hosts() == []


def test_load_rejects_bad_run_ids(tmp_path):
    for bad in ("../x", "", "missing"):
        with pytest.raises(RunNotFoundError):
            Engine.load(tmp_path, bad, Config(), FakeRunner())


def test_keep_raw_copies_files(tmp_path):
    runner = FakeRunner()
    engine = make_engine(tmp_path, runner)
    asyncio.run(engine.run())
    copied = engine.keep_raw_files(tmp_path / "raw")
    assert any(p.name == "chunk_000_tcp_all.xml" for p in copied)
