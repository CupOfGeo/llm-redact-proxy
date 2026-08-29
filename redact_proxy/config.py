"""Configuration: defaults ← config.toml ← OPF_PROXY_* env ← explicit overrides.

The TOML file is the primary interface once installed as a service (a
launchd/brew-services daemon has no sane way to take env vars). Env vars
stay as overrides for compatibility and one-off runs.
"""

from __future__ import annotations

import os
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field, fields, replace
from pathlib import Path
from typing import Any

from redact_proxy.redactor import DEFAULT_CATEGORIES, DEFAULT_MODEL

DEFAULT_PORT = 8787
DEFAULT_UPSTREAM = "https://api.anthropic.com"
DEFAULT_LOG_FILE = "~/Library/Logs/redact-proxy.log"

# TOML key -> env var. Every setting is reachable both ways.
ENV_VARS = {
    "port": "OPF_PROXY_PORT",
    "upstream": "OPF_PROXY_UPSTREAM",
    "categories": "OPF_PROXY_CATEGORIES",
    "unredact": "OPF_PROXY_UNREDACT",
    "model": "OPF_PROXY_MODEL",
    "log_file": "OPF_PROXY_LOG_FILE",
    "log_level": "OPF_PROXY_LOG_LEVEL",
}


def config_path() -> Path:
    """`OPF_PROXY_CONFIG`, else `$XDG_CONFIG_HOME/llm-redact-proxy/config.toml`."""
    if explicit := os.environ.get("OPF_PROXY_CONFIG"):
        return Path(explicit).expanduser()
    base = Path(os.environ.get("XDG_CONFIG_HOME") or "~/.config").expanduser()
    return base / "llm-redact-proxy" / "config.toml"


@dataclass(frozen=True)
class Config:
    port: int = DEFAULT_PORT
    upstream: str = DEFAULT_UPSTREAM
    categories: frozenset[str] = field(default_factory=lambda: DEFAULT_CATEGORIES)
    unredact: str = "stream"  # stream | hook | off (bools coerce for compat)
    model: str = DEFAULT_MODEL
    log_file: str = DEFAULT_LOG_FILE
    log_level: str = "info"  # debug adds per-redaction and per-chunk events

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def log_path(self) -> Path:
        return Path(self.log_file).expanduser()

    def to_toml(self) -> str:
        """Flat TOML. Hand-rolled: stdlib parses TOML but doesn't write it."""
        cats = ", ".join(f'"{c}"' for c in sorted(self.categories))
        return (
            f"port = {self.port}\n"
            f'upstream = "{self.upstream}"\n'
            f"categories = [{cats}]\n"
            f'unredact = "{self.unredact}"\n'
            f'model = "{self.model}"\n'
            f'log_file = "{self.log_file}"\n'
            f'log_level = "{self.log_level}"\n'
        )


_KEYS = {f.name for f in fields(Config)}


def _coerce(key: str, value: Any) -> Any:
    """Normalize a raw TOML/env/CLI value into the field's type."""
    if key == "port":
        return int(value)
    if key == "categories":
        if isinstance(value, str):
            value = value.split(",")
        return frozenset(c.strip() for c in value if str(c).strip())
    if key == "unredact":
        if isinstance(value, bool):  # pre-0.4 TOML booleans
            return "stream" if value else "off"
        v = str(value).strip().lower()
        if v in {"1", "true", "yes", "on"}:
            return "stream"
        if v in {"0", "false", "no", ""}:
            return "off"
        return v
    return str(value)


def _validate(cfg: Config) -> Config:
    if not 1 <= cfg.port <= 65535:
        raise ValueError(f"port out of range: {cfg.port}")
    if not cfg.upstream.startswith(("http://", "https://")):
        raise ValueError(f"upstream must be an http(s) URL: {cfg.upstream!r}")
    if not cfg.categories:
        raise ValueError("categories must not be empty")
    if cfg.unredact not in ("stream", "hook", "off"):
        raise ValueError(f"unredact must be stream/hook/off: {cfg.unredact!r}")
    if cfg.log_level not in ("debug", "info", "warning", "error"):
        raise ValueError(
            f"log_level must be debug/info/warning/error: {cfg.log_level!r}"
        )
    return cfg


def load(
    path: Path | None = None,
    env: Mapping[str, str] | None = None,
    **overrides: Any,
) -> Config:
    """Resolve the effective config. `overrides` (CLI flags) win; None skips."""
    path = config_path() if path is None else path
    environ: Mapping[str, str] = os.environ if env is None else env
    values: dict[str, Any] = {}
    if path.exists():
        with path.open("rb") as fh:
            data = tomllib.load(fh)
        unknown = set(data) - _KEYS
        if unknown:
            raise ValueError(f"unknown key(s) in {path}: {', '.join(sorted(unknown))}")
        values.update(data)
    for key, var in ENV_VARS.items():
        if (raw := environ.get(var)) is not None:
            values[key] = raw
    values.update({k: v for k, v in overrides.items() if v is not None})
    cfg = replace(Config(), **{k: _coerce(k, v) for k, v in values.items()})
    return _validate(cfg)
