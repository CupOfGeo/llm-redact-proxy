"""`redact-proxy` CLI via click's runner; network and server are stubbed."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from redact_proxy import cli, server


@pytest.fixture
def env(monkeypatch, tmp_path: Path) -> Path:
    """Isolated config file + no OPF_PROXY_* env leaking in from the shell."""
    for var in cli.cfgmod.ENV_VARS.values():
        monkeypatch.delenv(var, raising=False)
    cfg = tmp_path / "config.toml"
    monkeypatch.setenv("OPF_PROXY_CONFIG", str(cfg))
    monkeypatch.setenv("OPF_PROXY_LOG_FILE", str(tmp_path / "proxy.log"))
    return cfg


def invoke(*args: str):
    return CliRunner().invoke(cli.cli, args)


def test_version_and_help() -> None:
    assert "redact-proxy, version" in invoke("--version").output
    out = invoke("--help").output
    for cmd in ("run", "status", "logs", "config", "shellenv"):
        assert cmd in out


def test_run_passes_flags_to_serve(monkeypatch, env) -> None:
    seen = {}
    monkeypatch.setattr(server, "serve", lambda cfg: seen.update(cfg=cfg))
    res = invoke(
        "run", "--port", "9999", "--unredact", "hook", "--categories", "secret,email"
    )
    assert res.exit_code == 0, res.output
    assert seen["cfg"].port == 9999
    assert seen["cfg"].unredact == "hook"
    assert seen["cfg"].categories == frozenset({"secret", "email"})


@pytest.mark.parametrize(
    "health,code,word",
    [
        (None, cli.EXIT_DOWN, "DOWN"),
        (
            {"state": "ready", "pid": 1, "categories": ["secret"]},
            cli.EXIT_READY,
            "ready",
        ),
        ({"state": "loading", "pid": 1}, cli.EXIT_LOADING, "loading"),
        ({"state": "error", "pid": 1, "load_error": "boom"}, cli.EXIT_ERROR, "boom"),
    ],
)
def test_status_exit_codes(monkeypatch, env, health, code, word) -> None:
    monkeypatch.setattr(cli, "fetch_health", lambda url, timeout=2.0: health)
    res = invoke("status")
    assert res.exit_code == code, res.output
    assert word in res.output
    as_json = json.loads(invoke("status", "--json").output)
    assert as_json["state"] == (health or {}).get("state", "down")


def test_status_probes_configured_port(monkeypatch, env) -> None:
    env.write_text("port = 4242\n")
    urls = []
    monkeypatch.setattr(cli, "fetch_health", lambda url, timeout=2.0: urls.append(url))
    invoke("status")
    assert urls == ["http://127.0.0.1:4242"]


def test_logs_tail(env, tmp_path: Path) -> None:
    log = tmp_path / "proxy.log"
    log.write_text("".join(f"line {i}\n" for i in range(100)))
    out = invoke("logs", "-n", "3").output
    assert out == "line 97\nline 98\nline 99\n"
    log.unlink()
    assert invoke("logs").exit_code != 0


def test_config_show_init_get_set(env) -> None:
    assert "port = 8787" in invoke("config").output
    assert invoke("config", "path").output.strip() == str(env)
    assert invoke("config", "init").exit_code == 0 and env.exists()
    assert invoke("config", "init").exit_code != 0  # refuses to overwrite
    assert invoke("config", "set", "port", "9100").exit_code == 0
    assert "port = 9100" in env.read_text()
    assert invoke("config", "get", "port").output.strip() == "9100"
    assert invoke("config", "set", "port", "99999").exit_code != 0  # validated
    assert "port = 9100" in env.read_text()  # bad value not written
    assert invoke("config", "set", "categories", "secret,email").exit_code == 0
    assert invoke("config", "get", "categories").output.strip() == "email,secret"


def test_shellenv_uses_configured_port(env) -> None:
    env.write_text("port = 4242\n")
    out = invoke("shellenv").output
    assert "ANTHROPIC_BASE_URL=http://127.0.0.1:4242" in out
    assert "claude-raw()" in out


@pytest.fixture
def settings(monkeypatch, tmp_path: Path) -> Path:
    path = tmp_path / "claude" / "settings.json"
    monkeypatch.setattr(cli.routing, "settings_path", lambda: path)
    return path


def test_route_on_and_off(env, settings) -> None:
    res = invoke("route")
    assert res.exit_code == 0, res.output
    assert "routed:" in res.output and "Remote Control" in res.output
    assert (
        json.loads(settings.read_text())["env"]["ANTHROPIC_BASE_URL"]
        == "http://127.0.0.1:8787"
    )
    assert "already routed" in invoke("route").output
    res = invoke("route", "--off")
    assert res.exit_code == 0 and "unrouted:" in res.output
    assert "env" not in json.loads(settings.read_text())
    assert "already unrouted" in invoke("route", "--off").output


def test_route_conflict_needs_force(env, settings) -> None:
    settings.parent.mkdir(parents=True)
    settings.write_text(json.dumps({"env": {"ANTHROPIC_BASE_URL": "https://corp"}}))
    res = invoke("route")
    assert res.exit_code != 0 and "--force" in res.output
    assert invoke("route", "--force").exit_code == 0
    assert (
        "left alone" in invoke("route", "--off").output
        or "unrouted" in invoke("route", "--off").output
    )


def test_setup_downloads_writes_config_and_routes(monkeypatch, env, settings) -> None:
    monkeypatch.setattr(cli.doctormod.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(cli.doctormod.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(cli.doctormod, "model_cache_dir", lambda m: None)
    downloaded = []
    monkeypatch.setattr(
        cli, "download_model", lambda m: downloaded.append(m) or "/cache/x"
    )
    res = invoke("setup")
    assert res.exit_code == 0, res.output
    assert downloaded == ["OpenMed/privacy-filter-mlx-8bit"]
    assert env.exists() and "port = 8787" in env.read_text()
    assert (
        json.loads(settings.read_text())["env"]["ANTHROPIC_BASE_URL"]
        == "http://127.0.0.1:8787"
    )
    assert "redact-proxy doctor" in res.output
    # second run: cached model, existing config, already routed — no downloads
    monkeypatch.setattr(cli.doctormod, "model_cache_dir", lambda m: Path("/cache/x"))
    res = invoke("setup")
    assert res.exit_code == 0 and downloaded == ["OpenMed/privacy-filter-mlx-8bit"]
    assert "already cached" in res.output and "already routed" in res.output


def test_setup_refuses_non_apple_silicon(monkeypatch, env, settings) -> None:
    monkeypatch.setattr(cli.doctormod.platform, "machine", lambda: "x86_64")
    res = invoke("setup", "--no-download", "--no-route")
    assert res.exit_code != 0 and "Apple Silicon" in res.output


def test_doctor_output_and_exit(monkeypatch, env) -> None:
    from redact_proxy.doctor import Check

    good = [Check("service", True, "ready"), Check("launchd", None, "none")]
    bad = good + [
        Check(
            "claude routing", False, "no ANTHROPIC_BASE_URL", "run: redact-proxy route"
        )
    ]
    monkeypatch.setattr(cli.doctormod, "run_checks", lambda cfg, probes: bad)
    res = invoke("doctor")
    assert (
        res.exit_code == 1
        and "1 problem" in res.output
        and "↳ run: redact-proxy route" in res.output
    )
    parsed = json.loads(invoke("doctor", "--json").output)
    assert [c["name"] for c in parsed] == ["service", "launchd", "claude routing"]
    monkeypatch.setattr(cli.doctormod, "run_checks", lambda cfg, probes: good)
    res = invoke("doctor")
    assert res.exit_code == 0 and "all good" in res.output


def test_doctor_fix_routes(monkeypatch, env, settings) -> None:
    from redact_proxy.doctor import Check

    calls = []

    def run_checks(cfg, probes):
        calls.append(1)
        routed = settings.exists()
        return [
            Check("launchd", None, "x"),
            Check("claude routing", routed, "...", "run: redact-proxy route"),
        ]

    monkeypatch.setattr(cli.doctormod, "run_checks", run_checks)
    res = invoke("doctor", "--fix")
    assert res.exit_code == 0, res.output
    assert "fixed: routed" in res.output and settings.exists()


def test_hook_snippet_is_valid_json(env) -> None:
    res = invoke("hook-snippet")
    assert res.exit_code == 0
    snippet = json.loads(res.stdout)
    assert "SessionStart" in snippet["hooks"]
    assert (
        "redact-proxy status"
        in snippet["hooks"]["SessionStart"][0]["hooks"][0]["command"]
    )
