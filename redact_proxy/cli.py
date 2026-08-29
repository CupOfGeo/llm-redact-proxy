"""`redact-proxy` command line: run, status, logs, config, shellenv."""

from __future__ import annotations

import json
import sys
import time
from importlib.metadata import PackageNotFoundError, version
from typing import Any

import click
import httpx

from redact_proxy import config as cfgmod
from redact_proxy.config import Config

try:
    __version__ = version("llm-redact-proxy")
except PackageNotFoundError:  # running from a checkout without install
    __version__ = "0.0.0-dev"

# `status` exit codes — scriptable ("is it safe to launch claude?").
EXIT_READY, EXIT_DOWN, EXIT_LOADING, EXIT_ERROR = 0, 1, 2, 3

_CONFIG_OPTS = [
    click.option("--port", type=int, help="Listen port (default 8787)."),
    click.option("--upstream", help="Upstream API base URL."),
    click.option(
        "--categories", help="Comma-separated OPF categories (e.g. secret,person)."
    ),
    click.option(
        "--unredact/--no-unredact",
        default=None,
        help="Restore real values in responses (default on; off = awareness mode).",
    ),
]


def config_options(fn):
    for opt in reversed(_CONFIG_OPTS):
        fn = opt(fn)
    return fn


def load_config(**overrides: Any) -> Config:
    try:
        return cfgmod.load(**overrides)
    except (ValueError, OSError) as exc:
        raise click.ClickException(f"config: {exc}") from exc


def fetch_health(base_url: str, timeout: float = 2.0) -> dict | None:
    """/health JSON, or None when nothing answers."""
    try:
        resp = httpx.get(f"{base_url}/health", timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except (httpx.HTTPError, ValueError):
        return None


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="redact-proxy")
def cli() -> None:
    """Local PII/secret-redacting proxy for LLM APIs."""


@cli.command()
@config_options
def run(**overrides: Any) -> None:
    """Run the proxy in the foreground (what `brew services` executes)."""
    from redact_proxy import server

    server.serve(load_config(**overrides))


@cli.command()
@click.option("--json", "as_json", is_flag=True, help="Machine-readable output.")
@click.option("--port", type=int, help="Port to probe (default from config).")
def status(as_json: bool, port: int | None) -> None:
    """Health of the running proxy. Exit 0 ready, 1 down, 2 loading, 3 error."""
    cfg = load_config(port=port)
    health = fetch_health(cfg.base_url)
    if health is None:
        state, code = "down", EXIT_DOWN
    else:
        state = health.get(
            "state", "ready" if health.get("status") == "ok" else "error"
        )
        code = {"ready": EXIT_READY, "loading": EXIT_LOADING}.get(state, EXIT_ERROR)
    if as_json:
        click.echo(json.dumps({"state": state, "url": cfg.base_url, **(health or {})}))
        sys.exit(code)
    if health is None:
        click.echo(f"⛔ redact-proxy is DOWN at {cfg.base_url}")
        click.echo(f"   log: {cfg.log_path}")
        sys.exit(code)
    icon = {"ready": "✅", "loading": "⏳"}.get(state, "❌")
    click.echo(
        f"{icon} redact-proxy {state} at {cfg.base_url} (pid {health.get('pid')})"
    )
    click.echo(f"   model:      {health.get('model')}")
    click.echo(f"   categories: {', '.join(health.get('categories', []))}")
    click.echo(
        f"   unredact:   {'on' if health.get('unredact') else 'off (awareness mode)'}"
    )
    click.echo(f"   upstream:   {health.get('upstream')}")
    if health.get("load_error"):
        click.echo(f"   error:      {health['load_error']}")
    sys.exit(code)


@cli.command()
@click.option("-n", "lines", default=50, show_default=True, help="Lines to show.")
@click.option("-f", "follow", is_flag=True, help="Keep printing as the log grows.")
def logs(lines: int, follow: bool) -> None:
    """Show the proxy log."""
    path = load_config().log_path
    if not path.exists():
        raise click.ClickException(f"no log file at {path}")
    with path.open("rb") as fh:
        tail = fh.read().splitlines()[-lines:]
        for line in tail:
            click.echo(line.decode("utf-8", "replace"))
        if not follow:
            return
        try:
            while True:
                chunk = fh.read()
                if chunk:
                    click.echo(chunk.decode("utf-8", "replace"), nl=False)
                else:
                    time.sleep(0.5)
        except KeyboardInterrupt:
            pass


@cli.group(invoke_without_command=True)
@click.pass_context
def config(ctx: click.Context) -> None:
    """Show or edit ~/.config/llm-redact-proxy/config.toml."""
    if ctx.invoked_subcommand is None:
        cfg = load_config()
        click.echo(f"# {cfgmod.config_path()}")
        click.echo(cfg.to_toml(), nl=False)


@config.command("path")
def config_path_cmd() -> None:
    """Print the config file path."""
    click.echo(str(cfgmod.config_path()))


@config.command("init")
@click.option("--force", is_flag=True, help="Overwrite an existing file.")
def config_init(force: bool) -> None:
    """Write a config file with the current effective values."""
    path = cfgmod.config_path()
    if path.exists() and not force:
        raise click.ClickException(f"{path} exists (use --force to overwrite)")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(load_config().to_toml())
    click.echo(f"wrote {path}")


@config.command("get")
@click.argument("key", type=click.Choice(sorted(cfgmod.ENV_VARS)))
def config_get(key: str) -> None:
    """Print one effective value."""
    value = getattr(load_config(), key)
    click.echo(",".join(sorted(value)) if isinstance(value, frozenset) else value)


@config.command("set")
@click.argument("key", type=click.Choice(sorted(cfgmod.ENV_VARS)))
@click.argument("value")
def config_set(key: str, value: str) -> None:
    """Set one value in the config file (creating it if needed)."""
    path = cfgmod.config_path()
    try:  # file values (or defaults) + this one change, validated as a whole
        updated = cfgmod.load(path=path, env={}, **{key: value})
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(updated.to_toml())
    click.echo(f"{key} = {getattr(updated, key)}  ({path})")
    click.echo("restart the proxy for this to take effect")


SHELLENV = """# redact-proxy: fail-closed wrapper. Plain `claude` routes through the
# proxy and refuses to run while it is down; `claude-raw` bypasses it.
claude() {{
  local state
  state=$(curl -s --max-time 1 {base_url}/health 2>/dev/null | sed -n 's/.*"state":"\\([a-z]*\\)".*/\\1/p')
  case "$state" in
    ready) ANTHROPIC_BASE_URL={base_url} command claude "$@" ;;
    loading) echo "⏳ redact-proxy is still loading its model — try again shortly." >&2; return 1 ;;
    *) echo "⛔ redact-proxy is not running — requests would go to Anthropic UNREDACTED." >&2
       echo "   status: redact-proxy status    bypass: claude-raw (unprotected)" >&2; return 1 ;;
  esac
}}
claude-raw() {{ command claude "$@"; }}
"""


@cli.command()
def shellenv() -> None:
    """Print a fail-closed `claude` shell wrapper: eval "$(redact-proxy shellenv)"."""
    click.echo(SHELLENV.format(base_url=load_config().base_url), nl=False)


def main() -> None:
    cli(prog_name="redact-proxy")


if __name__ == "__main__":
    main()
