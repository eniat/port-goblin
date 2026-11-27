"""Unauthenticated Redis (redis-info), MongoDB (mongodb-databases) and Elasticsearch (GET)."""

from __future__ import annotations

import contextlib
import json
import re

from portgoblin.checks.base import (
    CheckContext,
    DirectCheck,
    ScriptCheck,
    ScriptResults,
    finding,
    hp,
    is_tls,
    nmap_repro,
    nsedoc,
    product,
    service_name,
)
from portgoblin.core.models import Finding, Host, Port, Status

NAME_LIMIT = 30


def _names(names: list[str]) -> str:
    shown = ", ".join(names[:NAME_LIMIT]) or "none"
    if len(names) > NAME_LIMIT:
        shown += f" (+{len(names) - NAME_LIMIT} more)"
    return shown


class RedisUnauthenticated(ScriptCheck):
    check_id = "redis-auth"
    name = "Redis authentication"
    scripts = ("redis-info",)

    def matches(self, port: Port) -> bool:
        return service_name(port) == "redis" or port.portid == 6379

    def evaluate(self, host: Host, ports: list[Port], results: ScriptResults) -> list[Finding]:
        out: list[Finding] = []
        for port in ports:
            target = hp(host, port)
            output = results.port_output(port, "redis-info")
            repro = [
                nmap_repro(host, [port], self.scripts),
                f"redis-cli -h {host.address} -p {port.portid} INFO server",
            ]
            version = re.search(r"Version:?\s+(\S+)", output or "")
            if output and version:
                out.append(
                    finding(
                        "REDIS-001",
                        self.check_id,
                        "Unauthenticated Redis",
                        Status.ISSUE,
                        [target],
                        "Anyone who can reach the port can read and change all data, and Redis "
                        "commands can often be used to write files on the server.",
                        observed=f"{target}: INFO answered without authentication "
                        f"(Redis {version.group(1)})",
                        fix="Set requirepass or ACL users, bind to trusted interfaces only, and "
                        "keep protected-mode on.",
                        reproduce=repro,
                        refs=[nsedoc("redis-info")],
                    )
                )
            elif "redis-info" in results.ran and service_name(port) == "redis":
                out.append(
                    finding(
                        "REDIS-001",
                        self.check_id,
                        "Unauthenticated Redis",
                        Status.OK,
                        [target],
                        "redis-info got no answer without credentials (authentication appears "
                        "to be required).",
                        reproduce=repro,
                    )
                )
        return out


def mongodb_names(output: str) -> list[str]:
    return re.findall(r"^\s*name\s*=\s*(\S+)\s*$", output, re.MULTILINE)


class MongoDbUnauthenticated(ScriptCheck):
    check_id = "mongodb-auth"
    name = "MongoDB authentication"
    scripts = ("mongodb-databases",)

    def matches(self, port: Port) -> bool:
        return service_name(port) in ("mongodb", "mongod") or port.portid == 27017

    def evaluate(self, host: Host, ports: list[Port], results: ScriptResults) -> list[Finding]:
        out: list[Finding] = []
        for port in ports:
            target = hp(host, port)
            output = results.port_output(port, "mongodb-databases") or ""
            names = mongodb_names(output)
            repro = [nmap_repro(host, [port], self.scripts)]
            if names:
                out.append(
                    finding(
                        "MONGO-001",
                        self.check_id,
                        "Unauthenticated MongoDB",
                        Status.ISSUE,
                        [target],
                        "Database names were listed without credentials, so the data is likely "
                        "readable and writable by anyone who can reach the port.",
                        observed=f"{target}: databases {_names(names)}",
                        fix="Enable authorisation (security.authorization: enabled) and bind to "
                        "trusted interfaces only.",
                        reproduce=repro,
                        refs=[nsedoc("mongodb-databases")],
                    )
                )
            elif "mongodb-databases" in results.ran:
                out.append(
                    finding(
                        "MONGO-001",
                        self.check_id,
                        "Unauthenticated MongoDB",
                        Status.OK,
                        [target],
                        "Databases were not listed without credentials.",
                        observed=f"{target}: {output.strip()}" if output.strip() else None,
                        reproduce=repro,
                    )
                )
        return out


class ElasticsearchUnauthenticated(DirectCheck):
    """One GET / and one GET /_cat/indices?h=index. Index names only, never documents."""

    check_id = "elasticsearch-auth"
    name = "Elasticsearch authentication"

    def matches(self, port: Port) -> bool:
        return "elasticsearch" in product(port) or port.portid in (9200, 9201)

    async def run(self, ctx: CheckContext, host: Host, ports: list[Port]) -> list[Finding]:
        out: list[Finding] = []
        for port in ports:
            target = hp(host, port)
            base = f"{'https' if is_tls(port) else 'http'}://{host.address}:{port.portid}"
            root = await ctx.http_get(self.check_id, target, f"{base}/")
            repro = [f"curl -sk {base}/", f"curl -sk '{base}/_cat/indices?h=index'"]
            if root.error or root.status is None:
                out.append(self.not_assessed(host, [port], f"no HTTP answer ({root.error})"))
                continue
            if root.status in (401, 403):
                out.append(
                    finding(
                        "ES-001",
                        self.check_id,
                        "Unauthenticated Elasticsearch",
                        Status.OK,
                        [target],
                        f"Elasticsearch asked for authentication (HTTP {root.status}).",
                        reproduce=repro,
                    )
                )
                continue
            version = None
            with contextlib.suppress(ValueError, AttributeError):
                version = json.loads(root.body).get("version", {}).get("number")
            if root.status != 200 or not version:
                out.append(
                    self.not_assessed(
                        host, [port], f"not an Elasticsearch answer (HTTP {root.status})"
                    )
                )
                continue
            indices = await ctx.http_get(self.check_id, target, f"{base}/_cat/indices?h=index")
            names = []
            if indices.status == 200:
                text = indices.body.decode("utf-8", "replace")
                names = sorted({line.strip() for line in text.splitlines() if line.strip()})
            listed = f"; indices {_names(names)}" if indices.status == 200 else ""
            out.append(
                finding(
                    "ES-001",
                    self.check_id,
                    "Unauthenticated Elasticsearch",
                    Status.ISSUE,
                    [target],
                    "The REST API answers without credentials, so indexed data can be read and "
                    "changed by anyone who can reach it.",
                    observed=f"{target}: version {version} without authentication{listed}",
                    fix="Enable security (xpack.security.enabled: true) with authentication and "
                    "TLS, and restrict access to the port.",
                    reproduce=repro,
                )
            )
        return out
