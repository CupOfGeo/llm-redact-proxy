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
        "run", "--port", "9999", "--no-unredact", "--categories", "secret,email"
    )
    assert res.exit_code == 0, res.output
    assert seen["cfg"].port == 9999
    assert seen["cfg"].unredact is False
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
