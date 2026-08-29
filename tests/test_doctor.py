"""doctor checks with every probe stubbed."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from redact_proxy import doctor
from redact_proxy.config import Config

CFG = Config()
READY = {
    "state": "ready",
    "pid": 1,
    "unredact": True,
    "upstream": "https://api.anthropic.com",
}


def probes(tmp_path: Path, **over):
    settings = tmp_path / "settings.json"
    if "routed" in over:
        env = {"ANTHROPIC_BASE_URL": CFG.base_url} if over.pop("routed") else {}
        settings.write_text(json.dumps({"env": env}))
    base: dict[str, Any] = {
        "system": lambda: "Darwin",
        "machine": lambda: "arm64",
        "model_cache_dir": lambda model: tmp_path / "cache",
        "health": lambda url: READY,
        "port_open": lambda port: False,
        "settings_path": lambda: settings,
        "launchd_loaded": lambda label: False,
        "which": lambda cmd: "/usr/local/bin/claude",
        "shell_base_url": lambda: None,
        "plugin_installed": lambda: False,
    }
    base.update(over)
    return doctor.Probes(**base)


def failed(checks: list[doctor.Check]) -> list[str]:
    return [c.name for c in checks if c.ok is False]


def test_all_good(tmp_path: Path) -> None:
    checks = doctor.run_checks(CFG, probes(tmp_path, routed=True))
    assert failed(checks) == []
    assert {c.name for c in checks} >= {
        "platform",
        "model cached",
        "service",
        "claude routing",
        "launchd",
    }


def test_not_apple_silicon(tmp_path: Path) -> None:
    checks = doctor.run_checks(
        CFG, probes(tmp_path, routed=True, machine=lambda: "x86_64")
    )
    assert failed(checks) == ["platform"]


def test_model_missing_hints_setup(tmp_path: Path) -> None:
    checks = doctor.run_checks(
        CFG, probes(tmp_path, routed=True, model_cache_dir=lambda m: None)
    )
    [c] = [c for c in checks if c.name == "model cached"]
    assert c.ok is False and "redact-proxy setup" in c.hint


def test_service_down_and_port_busy(tmp_path: Path) -> None:
    checks = doctor.run_checks(
        CFG,
        probes(
            tmp_path, routed=True, health=lambda url: None, port_open=lambda p: True
        ),
    )
    [c] = [c for c in checks if c.name == "service"]
    assert (
        c.ok is False
        and "something else" in c.detail
        and "brew services start" in c.hint
    )


def test_service_loading_and_error(tmp_path: Path) -> None:
    loading = {"state": "loading", "pid": 2}
    [c] = [
        c
        for c in doctor.run_checks(
            CFG, probes(tmp_path, routed=True, health=lambda u: loading)
        )
        if c.name == "service"
    ]
    assert c.ok is False and "loading" in c.detail
    err = {"state": "error", "pid": 2, "load_error": "RuntimeError: no metal"}
    [c] = [
        c
        for c in doctor.run_checks(
            CFG, probes(tmp_path, routed=True, health=lambda u: err)
        )
        if c.name == "service"
    ]
    assert c.ok is False and "no metal" in c.hint


def test_routing_states(tmp_path: Path) -> None:
    [c] = [
        c
        for c in doctor.run_checks(CFG, probes(tmp_path, routed=False))
        if c.name == "claude routing"
    ]
    assert c.ok is False and "redact-proxy route" in c.hint
    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps({"env": {"ANTHROPIC_BASE_URL": "https://corp"}}))
    [c] = [
        c
        for c in doctor.run_checks(CFG, probes(tmp_path))
        if c.name == "claude routing"
    ]
    assert c.ok is False and "points elsewhere" in c.detail and "--force" in c.hint
    settings.write_text("{broken")
    [c] = [
        c
        for c in doctor.run_checks(CFG, probes(tmp_path))
        if c.name == "claude routing"
    ]
    assert c.ok is False and "broken" in c.detail


def test_launchd_conflict(tmp_path: Path) -> None:
    both = probes(tmp_path, routed=True, launchd_loaded=lambda label: True)
    [c] = [c for c in doctor.run_checks(CFG, both) if c.name == "launchd"]
    assert c.ok is False and "--fix" in c.hint
    legacy_only = probes(
        tmp_path, routed=True, launchd_loaded=lambda label: label == doctor.LEGACY_LABEL
    )
    [c] = [c for c in doctor.run_checks(CFG, legacy_only) if c.name == "launchd"]
    assert c.ok is None and "legacy" in c.detail


def test_shell_env_is_informational(tmp_path: Path) -> None:
    checks = doctor.run_checks(
        CFG,
        probes(tmp_path, routed=True, shell_base_url=lambda: "http://127.0.0.1:8787"),
    )
    [c] = [c for c in checks if c.name == "shell env"]
    assert c.ok is None and "8787" in c.detail


HOOK_HEALTH = READY | {"unredact": "hook"}
STREAM_HEALTH = READY | {"unredact": "stream"}


def hook_check(checks):
    found = [c for c in checks if c.name == "hook mode"]
    return found[0] if found else None


def test_hook_mode_without_plugin_fails(tmp_path: Path) -> None:
    c = hook_check(
        doctor.run_checks(
            CFG, probes(tmp_path, routed=True, health=lambda u: HOOK_HEALTH)
        )
    )
    assert c is not None and c.ok is False and "/plugin install" in c.hint


def test_hook_mode_with_plugin_ok(tmp_path: Path) -> None:
    pr = probes(
        tmp_path,
        routed=True,
        health=lambda u: HOOK_HEALTH,
        plugin_installed=lambda: True,
    )
    c = hook_check(doctor.run_checks(CFG, pr))
    assert c is not None and c.ok is True


def test_stream_mode_with_plugin_warns(tmp_path: Path) -> None:
    pr = probes(
        tmp_path,
        routed=True,
        health=lambda u: STREAM_HEALTH,
        plugin_installed=lambda: True,
    )
    c = hook_check(doctor.run_checks(CFG, pr))
    assert c is not None and c.ok is None and "never engages" in c.detail


def test_no_hook_check_without_mode_signal(tmp_path: Path) -> None:
    assert hook_check(doctor.run_checks(CFG, probes(tmp_path, routed=True))) is None
