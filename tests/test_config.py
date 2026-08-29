"""Config resolution: defaults ← file ← env ← overrides, validation, paths."""

from __future__ import annotations

from pathlib import Path

import pytest

from redact_proxy import config as cfgmod
from redact_proxy.config import Config
from redact_proxy.redactor import DEFAULT_CATEGORIES


def test_defaults_without_file(tmp_path: Path) -> None:
    cfg = cfgmod.load(path=tmp_path / "missing.toml", env={})
    assert cfg == Config()
    assert cfg.port == 8787 and cfg.unredact == "stream"
    assert cfg.categories == DEFAULT_CATEGORIES
    assert cfg.base_url == "http://127.0.0.1:8787"


def test_file_values(tmp_path: Path) -> None:
    f = tmp_path / "c.toml"
    f.write_text('port = 9000\ncategories = ["secret", "person"]\nunredact = false\n')
    cfg = cfgmod.load(path=f, env={})
    assert cfg.port == 9000
    assert cfg.categories == frozenset({"secret", "person"})
    assert cfg.unredact == "off"  # TOML boolean false coerces
    assert cfg.upstream == "https://api.anthropic.com"  # untouched default


def test_env_beats_file_and_override_beats_env(tmp_path: Path) -> None:
    f = tmp_path / "c.toml"
    f.write_text("port = 9000\n")
    env = {"OPF_PROXY_PORT": "9001", "OPF_PROXY_UNREDACT": "0"}
    assert cfgmod.load(path=f, env=env).port == 9001
    assert cfgmod.load(path=f, env=env).unredact == "off"
    cfg = cfgmod.load(path=f, env=env, port=9002, unredact=None)  # None = skip
    assert cfg.port == 9002 and cfg.unredact == "off"


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("1", "stream"),
        ("true", "stream"),
        ("stream", "stream"),
        ("hook", "hook"),
        ("0", "off"),
        ("off", "off"),
        ("", "off"),
    ],
)
def test_unredact_env_parsing(raw: str, expected: str, tmp_path: Path) -> None:
    cfg = cfgmod.load(path=tmp_path / "x", env={"OPF_PROXY_UNREDACT": raw})
    assert cfg.unredact == expected


def test_unredact_bad_value_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        cfgmod.load(path=tmp_path / "x", env={"OPF_PROXY_UNREDACT": "sideways"})


def test_categories_csv_env(tmp_path: Path) -> None:
    cfg = cfgmod.load(
        path=tmp_path / "x", env={"OPF_PROXY_CATEGORIES": " secret, email ,"}
    )
    assert cfg.categories == frozenset({"secret", "email"})


@pytest.mark.parametrize(
    "content",
    ["port = 70000\n", 'upstream = "ftp://x"\n', "categories = []\n", "bogus = 1\n"],
)
def test_validation_errors(content: str, tmp_path: Path) -> None:
    f = tmp_path / "c.toml"
    f.write_text(content)
    with pytest.raises(ValueError):
        cfgmod.load(path=f, env={})


def test_to_toml_round_trips(tmp_path: Path) -> None:
    cfg = Config(port=1234, categories=frozenset({"secret", "phone"}), unredact="hook")
    f = tmp_path / "c.toml"
    f.write_text(cfg.to_toml())
    assert cfgmod.load(path=f, env={}) == cfg


def test_config_path_resolution(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("OPF_PROXY_CONFIG", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    assert cfgmod.config_path() == tmp_path / "llm-redact-proxy" / "config.toml"
    monkeypatch.setenv("OPF_PROXY_CONFIG", str(tmp_path / "explicit.toml"))
    assert cfgmod.config_path() == tmp_path / "explicit.toml"
