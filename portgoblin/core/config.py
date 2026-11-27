"""Configuration loading. Built-in defaults match config/portgoblin.toml."""

from __future__ import annotations

import os
import tomllib
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError

REPO_CONFIG = Path(__file__).resolve().parents[2] / "config" / "portgoblin.toml"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RatesConfig(StrictModel):
    internal: int = Field(300, gt=0)
    external: int = Field(100, gt=0)


class ScanConfig(StrictModel):
    chunk_prefix: int = Field(24, ge=16, le=32)
    top_udp: int = Field(200, gt=0, le=65535)
    udp_parallel: bool = True
    stats_every: str = "30s"
    max_hosts: int = Field(65536, gt=0)
    interrupt_grace_seconds: int = Field(30, gt=0)


class NseConfig(StrictModel):
    allowlist: list[str] = Field(
        default_factory=lambda: [
            "ftp-anon",
            "ssh2-enum-algos",
            "smb2-security-mode",
            "smb-security-mode",
            "smb-protocols",
            "rdp-enum-encryption",
            "rdp-ntlm-info",
            "snmp-info",
            "snmp-sysdescr",
            "nfs-showmount",
            "ldap-rootdse",
            "ldap-search",
            "redis-info",
            "mongodb-info",
            "mongodb-databases",
            "rsync-list-modules",
            "vnc-info",
            "x11-access",
            "ipmi-version",
            "ipmi-cipher-zero",
            "ssl-cert",
            "ssl-enum-ciphers",
        ]
    )
    confirmed_non_safe: list[str] = Field(default_factory=lambda: ["ssl-enum-ciphers"])


class TimeoutsConfig(StrictModel):
    default: int = Field(60, gt=0)
    reachability: int = Field(3, gt=0)
    http: int = Field(10, gt=0)


class Config(StrictModel):
    rates: RatesConfig = Field(default_factory=RatesConfig)
    scan: ScanConfig = Field(default_factory=ScanConfig)
    nse: NseConfig = Field(default_factory=NseConfig)
    timeouts: TimeoutsConfig = Field(default_factory=TimeoutsConfig)


class ConfigError(Exception):
    pass


def candidate_paths(explicit: Path | None = None) -> list[Path]:
    paths: list[Path] = []
    if explicit:
        return [explicit]
    env = os.environ.get("PORTGOBLIN_CONFIG")
    if env:
        return [Path(env)]
    xdg = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    paths.append(Path(xdg) / "portgoblin" / "portgoblin.toml")
    paths.append(REPO_CONFIG)
    return paths


def load_config(explicit: Path | None = None) -> tuple[Config, Path | None]:
    """Load the first config file found, or the built-in defaults if none exists."""
    for path in candidate_paths(explicit):
        if path.is_file():
            try:
                data = tomllib.loads(path.read_text(encoding="utf-8"))
                return Config.model_validate(data), path
            except (tomllib.TOMLDecodeError, ValidationError) as exc:
                raise ConfigError(f"Invalid config file {path}: {exc}") from exc
        if explicit:
            raise ConfigError(f"Config file not found: {path}")
    return Config(), None


def data_dir() -> Path:
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "portgoblin"


def runs_dir() -> Path:
    return data_dir() / "runs"


def cache_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "portgoblin"
