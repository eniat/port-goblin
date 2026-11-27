"""Docker Engine API: unauthenticated access (one GET /version)."""

from __future__ import annotations

import contextlib
import json

from portgoblin.checks.base import CheckContext, DirectCheck, finding, hp, is_tls, product
from portgoblin.core.models import Finding, Host, Port, Status


class DockerApiUnauthenticated(DirectCheck):
    check_id = "docker-api"
    name = "Docker API authentication"

    def matches(self, port: Port) -> bool:
        return port.portid in (2375, 2376) or "docker" in product(port)

    async def run(self, ctx: CheckContext, host: Host, ports: list[Port]) -> list[Finding]:
        out: list[Finding] = []
        for port in ports:
            target = hp(host, port)
            tls = is_tls(port) or port.portid == 2376
            url = f"{'https' if tls else 'http'}://{host.address}:{port.portid}/version"
            result = await ctx.http_get(self.check_id, target, url)
            repro = [f"curl -sk {url}"]
            if result.error and tls:
                # A Docker daemon with --tlsverify refuses clients without a certificate.
                out.append(
                    finding(
                        "DOCKER-001",
                        self.check_id,
                        "Unauthenticated Docker API",
                        Status.OK,
                        [target],
                        "The TLS connection was refused without a client certificate.",
                        observed=f"{target}: {result.error}",
                        reproduce=repro,
                    )
                )
                continue
            if result.error or result.status is None:
                out.append(self.not_assessed(host, [port], f"no HTTP answer ({result.error})"))
                continue
            data = {}
            with contextlib.suppress(ValueError):
                data = json.loads(result.body)
            if result.status == 200 and isinstance(data, dict) and "ApiVersion" in data:
                out.append(
                    finding(
                        "DOCKER-001",
                        self.check_id,
                        "Unauthenticated Docker API",
                        Status.ISSUE,
                        [target],
                        "Anyone who can reach this API can start containers, which normally "
                        "means root on the host.",
                        observed=f"{target}: Docker {data.get('Version', '?')} (API "
                        f"{data.get('ApiVersion')}) answered without authentication",
                        fix="Do not expose the daemon on TCP without --tlsverify and client "
                        "certificates; prefer the local socket.",
                        reproduce=repro,
                    )
                )
            elif result.status in (401, 403):
                out.append(
                    finding(
                        "DOCKER-001",
                        self.check_id,
                        "Unauthenticated Docker API",
                        Status.OK,
                        [target],
                        f"Access was refused (HTTP {result.status}).",
                        reproduce=repro,
                    )
                )
            else:
                out.append(
                    self.not_assessed(
                        host, [port], f"not a Docker API answer (HTTP {result.status})"
                    )
                )
        return out
