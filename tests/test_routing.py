"""settings.json routing: merge, backup, idempotence, conflicts, removal."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from redact_proxy import routing

URL = "http://127.0.0.1:8787"


def read(path: Path) -> dict:
    return json.loads(path.read_text())


def test_route_on_creates_file(tmp_path: Path) -> None:
    path = tmp_path / ".claude" / "settings.json"
    res = routing.route_on(path, URL)
    assert res.changed and res.backup is None
    assert read(path) == {
        "env": {"ANTHROPIC_BASE_URL": URL, "ENABLE_TOOL_SEARCH": "true"}
    }
    assert routing.status(path, URL) == "routed"


def test_route_on_preserves_other_settings_and_backs_up(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    path.write_text(
        json.dumps(
            {"model": "opus", "env": {"FOO": "1", "ENABLE_TOOL_SEARCH": "false"}}
        )
    )
    res = routing.route_on(path, URL)
    assert res.changed and res.backup and res.backup.exists()
    assert read(res.backup)["env"] == {"FOO": "1", "ENABLE_TOOL_SEARCH": "false"}
    data = read(path)
    assert data["model"] == "opus"
    assert data["env"]["FOO"] == "1"
    assert data["env"]["ANTHROPIC_BASE_URL"] == URL
    assert data["env"]["ENABLE_TOOL_SEARCH"] == "false"  # user's explicit value kept


def test_route_on_is_idempotent(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    routing.route_on(path, URL)
    before = path.read_text()
    res = routing.route_on(path, URL)
    assert not res.changed and res.backup is None
    assert path.read_text() == before
    assert list(tmp_path.glob("settings.json.bak-*")) == []


def test_route_on_refuses_foreign_url_unless_forced(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    path.write_text(
        json.dumps({"env": {"ANTHROPIC_BASE_URL": "https://corp-proxy.example"}})
    )
    with pytest.raises(routing.RouteConflict):
        routing.route_on(path, URL)
    assert routing.status(path, URL) == "elsewhere:https://corp-proxy.example"
    res = routing.route_on(path, URL, force=True)
    assert res.changed and res.previous == "https://corp-proxy.example"
    assert read(path)["env"]["ANTHROPIC_BASE_URL"] == URL


def test_route_on_replaces_other_local_port_without_force(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    path.write_text(
        json.dumps({"env": {"ANTHROPIC_BASE_URL": "http://127.0.0.1:9999"}})
    )
    assert routing.route_on(path, URL).changed
    assert routing.status(path, URL) == "routed"


def test_status_tolerates_trailing_slash(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    env = {"ANTHROPIC_BASE_URL": URL + "/", "ENABLE_TOOL_SEARCH": "true"}
    path.write_text(json.dumps({"env": env}))
    assert routing.status(path, URL) == "routed"
    assert not routing.route_on(path, URL).changed  # equivalent value kept as is


def test_route_off_removes_only_ours(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"env": {"FOO": "1"}, "model": "opus"}))
    routing.route_on(path, URL)
    res = routing.route_off(path, URL)
    assert res.changed and res.removed == ["ANTHROPIC_BASE_URL", "ENABLE_TOOL_SEARCH"]
    assert read(path) == {"env": {"FOO": "1"}, "model": "opus"}
    # env block dropped entirely when it becomes empty
    path.write_text(json.dumps({"env": {"ANTHROPIC_BASE_URL": URL}}))
    routing.route_off(path, URL)
    assert read(path) == {}


def test_route_off_leaves_foreign_url_alone(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    path.write_text(
        json.dumps({"env": {"ANTHROPIC_BASE_URL": "https://corp-proxy.example"}})
    )
    res = routing.route_off(path, URL)
    assert not res.changed and res.previous == "https://corp-proxy.example"
    assert not routing.route_off(tmp_path / "missing.json", URL).changed


def test_malformed_settings_raise(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    path.write_text("{not json")
    with pytest.raises(ValueError):
        routing.route_on(path, URL)
    path.write_text(json.dumps({"env": ["not", "an", "object"]}))
    with pytest.raises(ValueError):
        routing.status(path, URL)
    path.write_text("[]")
    with pytest.raises(ValueError):
        routing.read_settings(path)
