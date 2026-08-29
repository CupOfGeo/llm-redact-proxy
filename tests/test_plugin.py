"""Plugin packaging stays consistent with the Python package."""

from __future__ import annotations

import json
import os
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_plugin_version_matches_package() -> None:
    with (ROOT / "pyproject.toml").open("rb") as fh:
        package = tomllib.load(fh)["project"]["version"]
    plugin = json.loads((ROOT / "plugin/.claude-plugin/plugin.json").read_text())
    assert plugin["version"] == package


def test_marketplace_points_at_plugin() -> None:
    market = json.loads((ROOT / ".claude-plugin/marketplace.json").read_text())
    [entry] = market["plugins"]
    assert entry["name"] == "redact-proxy"
    assert (ROOT / entry["source"] / ".claude-plugin/plugin.json").exists()


def test_hooks_json_references_existing_executable() -> None:
    hooks = json.loads((ROOT / "plugin/hooks/hooks.json").read_text())
    events = set(hooks["hooks"])
    assert events == {"PreToolUse", "SessionStart"}
    for event in events:
        for group in hooks["hooks"][event]:
            for h in group["hooks"]:
                rel = h["command"].replace("${CLAUDE_PLUGIN_ROOT}/", "").split()[0]
                script = ROOT / "plugin" / rel
                assert script.exists() and os.access(script, os.X_OK)
                assert h["command"].split()[-1] in ("pre-tool-use", "session-start")
