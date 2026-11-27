"""File cache for intelligence lookups (~/.cache/portgoblin), with a time to live."""

from __future__ import annotations

import hashlib
import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

from portgoblin import __version__

USER_AGENT = f"PortGoblin/{__version__}"


class FetchError(Exception):
    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


def fetch_json(url: str, timeout: float, headers: dict[str, str] | None = None) -> Any:
    """GET a public API. Uses the environment's proxy settings, unlike checks on targets."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as exc:
        raise FetchError(f"HTTP {exc.code}", exc.code) from exc
    except (urllib.error.URLError, OSError) as exc:
        raise FetchError(str(getattr(exc, "reason", exc))) from exc
    except ValueError as exc:
        raise FetchError(f"not JSON: {exc}") from exc


Fetcher = Callable[[str, float, dict[str, str] | None], Any]


class JsonCache:
    def __init__(self, directory: Path, ttl_hours: float, clock: Callable[[], float] = time.time):
        self.directory = directory
        self.ttl = ttl_hours * 3600
        self.clock = clock

    def _path(self, namespace: str, key: str) -> Path:
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]
        return self.directory / namespace / f"{digest}.json"

    def get(self, namespace: str, key: str, allow_stale: bool = False) -> Any | None:
        path = self._path(namespace, key)
        try:
            entry = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if entry.get("key") != key:
            return None
        if not allow_stale and self.clock() - entry.get("saved", 0) > self.ttl:
            return None
        return entry.get("data")

    def saved_at(self, namespace: str, key: str) -> float | None:
        try:
            entry = json.loads(self._path(namespace, key).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return entry.get("saved")

    def set(self, namespace: str, key: str, data: Any) -> None:
        path = self._path(namespace, key)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"key": key, "saved": self.clock(), "data": data}), "utf-8")
        tmp.replace(path)
