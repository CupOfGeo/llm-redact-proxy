"""Route Claude Code through the proxy via ~/.claude/settings.json `env`.

Claude Code applies the settings-file `env` block to every session — CLI,
desktop app, IDE extensions — and it overrides the shell environment, so
this is the one switch that covers every launcher. It is fail-closed by
construction: proxy down means connection refused, never an unredacted
request. (Documented side effects of a non-first-party base URL: MCP tool
search is disabled unless ENABLE_TOOL_SEARCH=true — we set it — and Remote
Control is disabled.)
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

BASE_URL_KEY = "ANTHROPIC_BASE_URL"
TOOL_SEARCH_KEY = "ENABLE_TOOL_SEARCH"
_LOCAL_PROXY = re.compile(r"^http://127\.0\.0\.1:\d+/?$")

CAVEATS = (
    "Applies to new Claude Code sessions (CLI, desktop, IDE); restart running ones.\n"
    "While routed, Remote Control is disabled (Claude Code disables it for any\n"
    "non-api.anthropic.com base URL). MCP tool search stays on via ENABLE_TOOL_SEARCH."
)


class RouteConflict(Exception):
    """ANTHROPIC_BASE_URL already points somewhere that is not this proxy."""


def settings_path() -> Path:
    return Path.home() / ".claude" / "settings.json"


@dataclass
class RouteResult:
    changed: bool
    backup: Path | None = None
    removed: list[str] = field(default_factory=list)
    previous: str | None = None


def read_settings(path: Path) -> dict:
    if not path.exists():
        return {}
    data = json.loads(path.read_text())
    if not isinstance(data, dict):
        raise ValueError(f"{path} is not a JSON object")  # noqa: TRY004 - one error type for every settings fault
    return data


def _write(path: Path, data: dict) -> Path | None:
    """Write with a timestamped backup of the previous file (if any)."""
    backup = None
    if path.exists():
        backup = path.with_name(f"{path.name}.bak-{time.strftime('%Y%m%d-%H%M%S')}")
        backup.write_bytes(path.read_bytes())
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")
    return backup


def _env_block(data: dict) -> dict:
    env = data.get("env")
    if env is None:
        return {}
    if not isinstance(env, dict):
        raise ValueError('settings "env" is not an object')  # noqa: TRY004 - one error type for every settings fault
    return dict(env)


def status(path: Path, base_url: str) -> str:
    """'routed' | 'unrouted' | 'elsewhere:<url>'."""
    current = _env_block(read_settings(path)).get(BASE_URL_KEY)
    if current is None:
        return "unrouted"
    return "routed" if current.rstrip("/") == base_url else f"elsewhere:{current}"


def route_on(path: Path, base_url: str, force: bool = False) -> RouteResult:
    data = read_settings(path)
    env = _env_block(data)
    current = env.get(BASE_URL_KEY)
    foreign = (
        current and current.rstrip("/") != base_url and not _LOCAL_PROXY.match(current)
    )
    if foreign and not force:  # a corporate proxy, Bedrock, ...
        raise RouteConflict(
            f"{BASE_URL_KEY} is already {current!r} in {path}. "
            "Re-run with --force to replace it (set `upstream` in the proxy "
            "config to that URL first if requests must still go through it)."
        )
    desired = dict(env)
    if not (current and current.rstrip("/") == base_url):  # equivalent → keep
        desired[BASE_URL_KEY] = base_url
    desired.setdefault(TOOL_SEARCH_KEY, "true")
    if desired == env:
        return RouteResult(changed=False, previous=current)
    data["env"] = desired
    return RouteResult(changed=True, backup=_write(path, data), previous=current)


def route_off(path: Path, base_url: str) -> RouteResult:
    data = read_settings(path)
    env = _env_block(data)
    current = env.get(BASE_URL_KEY)
    removed: list[str] = []
    if current and (current.rstrip("/") == base_url or _LOCAL_PROXY.match(current)):
        del env[BASE_URL_KEY]
        removed.append(BASE_URL_KEY)
        if env.get(TOOL_SEARCH_KEY) == "true":  # the value route_on adds
            del env[TOOL_SEARCH_KEY]
            removed.append(TOOL_SEARCH_KEY)
    if not removed:
        return RouteResult(changed=False, previous=current)
    if env:
        data["env"] = env
    else:
        data.pop("env", None)
    return RouteResult(
        changed=True, backup=_write(path, data), removed=removed, previous=current
    )
