"""Metasploit module metadata (modules_metadata_base.json), indexed by CVE."""

from __future__ import annotations

import json
from pathlib import Path

INSTALL = "sudo apt install metasploit-framework"


class MetasploitIndex:
    def __init__(self, by_cve: dict[str, list[str]], path: Path | None = None) -> None:
        self.by_cve = by_cve
        self.path = path

    def modules(self, cve_id: str) -> list[str]:
        return self.by_cve.get(cve_id, [])

    @classmethod
    def load(cls, path: Path) -> MetasploitIndex:
        """Raises OSError or ValueError if the file cannot be read or parsed."""
        data = json.loads(path.read_text(encoding="utf-8"))
        by_cve: dict[str, list[str]] = {}
        for key, module in data.items():
            name = module.get("fullname") or key
            for reference in module.get("references", []):
                if isinstance(reference, str) and reference.startswith("CVE-"):
                    by_cve.setdefault(reference, [])
                    if name not in by_cve[reference]:
                        by_cve[reference].append(name)
        return cls(by_cve, path)
