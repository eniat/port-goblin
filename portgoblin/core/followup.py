"""Runs follow-up checks: one host at a time, read-only, one attempt per service."""

from __future__ import annotations

import asyncio
import os
import re
import shlex
import shutil
import ssl
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path

from portgoblin.checks import load_checks
from portgoblin.checks.base import (
    BaseCheck,
    DirectCheck,
    HttpResult,
    ScriptCheck,
    ScriptResults,
    ToolResult,
    hp,
)
from portgoblin.core import preflight
from portgoblin.core.config import Config
from portgoblin.core.engine import NullReporter, Reporter, Runner
from portgoblin.core.models import CheckRecord, Finding, Host, Port, ScanResult, Status
from portgoblin.core.nmap_parser import NmapParseError, parse_file
from portgoblin.core.nmap_runner import ScriptNotAllowedError, script_cmd

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
HTTP_BODY_LIMIT = 256 * 1024


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def _short(text: str, limit: int = 160) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects: a redirect could point outside the target list."""

    def redirect_request(self, *args, **kwargs):  # noqa: ANN002, ANN003
        return None


def _opener() -> urllib.request.OpenerDirector:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),  # ignore proxy settings in the environment
        urllib.request.HTTPSHandler(context=context),
        _NoRedirect(),
    )


def http_get_sync(url: str, timeout: float) -> HttpResult:
    request = urllib.request.Request(url, method="GET", headers={"User-Agent": "PortGoblin"})
    try:
        with _opener().open(request, timeout=timeout) as response:
            return HttpResult(
                response.status, response.read(HTTP_BODY_LIMIT), headers=dict(response.headers)
            )
    except urllib.error.HTTPError as exc:
        return HttpResult(exc.code, exc.read(HTTP_BODY_LIMIT) if exc.fp else b"")
    except (urllib.error.URLError, OSError, ssl.SSLError) as exc:
        reason = getattr(exc, "reason", exc)
        return HttpResult(None, error=str(reason))


HttpGetter = Callable[[str, float], HttpResult]


class FollowUpContext:
    def __init__(
        self,
        config: Config,
        is_root: bool,
        which: Callable[[str], str | None] = shutil.which,
        http_getter: HttpGetter = http_get_sync,
        netexec_probe: Callable[[str], bool] | None = None,
    ) -> None:
        self.config = config
        self.is_root = is_root
        self._which = which
        self._http = http_getter
        self.records: list[CheckRecord] = []
        self._netexec_safe: dict[str, bool] = {}
        self._netexec_probe = netexec_probe or (lambda path: preflight.netexec_info(path)[1])

    def tool(self, name: str) -> str | None:
        return self._which(name)

    def netexec_safe(self, path: str) -> bool:
        if path not in self._netexec_safe:
            self._netexec_safe[path] = self._netexec_probe(path)
        return self._netexec_safe[path]

    def record(self, record: CheckRecord) -> None:
        self.records.append(record)

    async def run_tool(self, check: str, target: str, cmd: list[str]) -> ToolResult:
        timeout = self.config.timeouts.default
        env = dict(os.environ, NO_COLOR="1", TERM="dumb")
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
                start_new_session=True,
            )
        except OSError as exc:
            result = ToolResult(None, "", "", error=str(exc))
            self.record(
                CheckRecord(target=target, check=check, sent=shlex.join(cmd), result=str(exc))
            )
            return result
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout)
        except TimeoutError:
            proc.kill()
            await proc.wait()
            self.record(
                CheckRecord(
                    target=target,
                    check=check,
                    sent=shlex.join(cmd),
                    result=f"timed out after {timeout}s",
                )
            )
            return ToolResult(None, "", "", timed_out=True)
        except BaseException:
            if proc.returncode is None:
                proc.kill()
                await proc.wait()
            raise
        result = ToolResult(
            proc.returncode,
            strip_ansi(out.decode("utf-8", "replace")),
            strip_ansi(err.decode("utf-8", "replace")),
        )
        summary = _short(result.stdout or result.stderr) or "no output"
        self.record(
            CheckRecord(
                target=target,
                check=check,
                sent=shlex.join(cmd),
                result=f"exit {result.returncode}: {summary}",
            )
        )
        return result

    async def http_get(self, check: str, target: str, url: str) -> HttpResult:
        timeout = self.config.timeouts.http
        result = await asyncio.to_thread(self._http, url, timeout)
        if result.error:
            outcome = f"error: {result.error}"
        else:
            outcome = f"HTTP {result.status}, {len(result.body)} bytes"
        self.record(CheckRecord(target=target, check=check, sent=f"GET {url}", result=outcome))
        return result


class FollowUps:
    """Runs every loaded check against matching services, one host at a time."""

    def __init__(
        self,
        config: Config,
        runner: Runner,
        workdir: Path,
        script_db: dict[str, set[str]],
        context: FollowUpContext,
        reporter: Reporter | None = None,
        checks: list[BaseCheck] | None = None,
    ) -> None:
        self.config = config
        self.runner = runner
        self.workdir = workdir
        self.script_db = script_db
        self.ctx = context
        self.reporter = reporter or NullReporter()
        self.checks = checks if checks is not None else load_checks()
        self.findings: list[Finding] = []  # kept up to date so Ctrl+C keeps results so far
        self.interrupted = False

    def plan(self, result: ScanResult) -> list[tuple[Host, list[tuple[BaseCheck, list[Port]]]]]:
        plan = []
        for host in result.live_hosts():
            matched = [(check, check.ports(host)) for check in self.checks]
            matched = [(check, ports) for check, ports in matched if ports]
            if matched:
                plan.append((host, matched))
        return plan

    async def run(self, result: ScanResult) -> list[Finding]:
        self.findings = []
        plan = self.plan(result)
        self.workdir.mkdir(parents=True, exist_ok=True)
        for index, (host, matched) in enumerate(plan, start=1):
            key = f"checks:{host.address}"
            self.reporter.phase_start(key, f"Follow-up checks {host.address} ({index}/{len(plan)})")
            try:
                self.findings += await self._host(host, matched)
            finally:
                self.reporter.phase_end(key)
        return self.findings

    def _already_ran(self, script: str, ports: list[Port], host: Host) -> bool:
        for port in ports:
            if port.script(script) or host.script(script):
                return True
        default = "default" in self.script_db.get(script, set())
        return default and bool(ports) and all(p.default_scripts for p in ports)

    async def _host(self, host: Host, matched: list[tuple[BaseCheck, list[Port]]]) -> list[Finding]:
        findings: list[Finding] = []
        script_checks = [(c, p) for c, p in matched if isinstance(c, ScriptCheck)]
        for protocol in ("tcp", "udp"):
            group = [(c, p) for c, p in script_checks if c.protocol == protocol]
            if group:
                findings += await self._script_group(host, protocol, group)
        for check, ports in matched:
            if isinstance(check, DirectCheck):
                try:
                    findings += await check.run(self.ctx, host, ports)
                except Exception as exc:  # a bug in one check must not stop the others
                    findings.append(check.not_assessed(host, ports, f"check failed: {exc}"))
        return findings

    async def _script_group(
        self, host: Host, protocol: str, group: list[tuple[ScriptCheck, list[Port]]]
    ) -> list[Finding]:
        results = ScriptResults()
        for port in host.ports:
            if port.protocol == protocol:
                results.ports[port.key] = {s.script_id: s.output for s in port.scripts}
        results.host = {s.script_id: s.output for s in host.scripts}

        missing: dict[str, set[int]] = {}
        args: list[str] = []
        for check, ports in group:
            for script in check.scripts:
                if self._already_ran(script, ports, host):
                    results.ran.add(script)
                else:
                    missing.setdefault(script, set()).update(p.portid for p in ports)
            if check.script_args and check.script_args not in args:
                args.append(check.script_args)

        reused = sorted(results.ran)
        if reused:
            self.ctx.record(
                CheckRecord(
                    target=host.address,
                    check="nmap scripts",
                    sent="nothing (output reused from the scan)",
                    result=", ".join(reused),
                )
            )

        failure: str | None = None
        if missing:
            if protocol == "udp" and not self.ctx.is_root:
                failure = "UDP checks need root (run with sudo)"
            else:
                failure = await self._run_scripts(host, protocol, missing, args, results)

        findings: list[Finding] = []
        for check, ports in group:
            needed = [s for s in check.scripts if s in missing]
            if failure and needed:
                findings.append(check.not_assessed(host, ports, failure))
                continue
            try:
                findings += check.evaluate(host, ports, results)
            except Exception as exc:
                findings.append(
                    check.not_assessed(host, ports, f"could not parse nmap output: {exc}")
                )
        return findings

    async def _run_scripts(
        self,
        host: Host,
        protocol: str,
        missing: dict[str, set[int]],
        args: list[str],
        results: ScriptResults,
    ) -> str | None:
        scripts = sorted(missing)
        ports = sorted(set().union(*missing.values()))
        out_base = self.workdir / f"checks_{host.address}_{protocol}"
        try:
            cmd = script_cmd(
                host.address,
                ports,
                protocol,
                scripts,
                out_base,
                self.config,
                self.script_db,
                ",".join(args) or None,
            )
        except ScriptNotAllowedError as exc:
            return str(exc)
        try:
            run = await asyncio.wait_for(self.runner.run(cmd), self.config.timeouts.default * 2)
        except TimeoutError:
            self.ctx.record(
                CheckRecord(
                    target=host.address,
                    check="nmap scripts",
                    sent=shlex.join(cmd),
                    result="timed out",
                )
            )
            return "nmap timed out"
        if run.returncode != 0:
            self.ctx.record(
                CheckRecord(
                    target=host.address,
                    check="nmap scripts",
                    sent=shlex.join(cmd),
                    result=f"exit {run.returncode}: {_short(run.stderr)}",
                )
            )
            return f"nmap exited with code {run.returncode}"
        try:
            parsed = parse_file(out_base.with_name(out_base.name + ".xml"))
        except NmapParseError as exc:
            return str(exc)
        found = parsed.hosts.get(host.address)
        with_output: list[str] = []
        if found:
            for port in found.ports:
                if port.protocol != protocol:
                    continue
                slot = results.ports.setdefault(port.key, {})
                for script in port.scripts:
                    slot[script.script_id] = script.output
                    with_output.append(f"{script.script_id} on {port.portid}")
            for script in found.scripts:
                results.host[script.script_id] = script.output
                with_output.append(script.script_id)
        results.ran.update(scripts)
        self.ctx.record(
            CheckRecord(
                target=host.address,
                check="nmap scripts",
                sent=shlex.join(cmd),
                result=(
                    "output from " + ", ".join(with_output) if with_output else "no script output"
                ),
            )
        )
        return None


def summarise_not_reachable(hosts: list[Host]) -> Finding:
    return Finding(
        finding_id="NA-reachability",
        check="follow-up",
        title="Follow-up checks",
        status=Status.NOT_ASSESSED,
        hosts=[h.address for h in hosts],
        observed="Not assessed: hosts not reachable from this machine",
        why_it_matters="The imported hosts did not answer a TCP connect, so no checks ran.",
    )


__all__ = ["FollowUpContext", "FollowUps", "hp", "http_get_sync", "strip_ansi"]
