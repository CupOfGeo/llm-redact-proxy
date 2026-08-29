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
from redact_proxy import doctor as doctormod
from redact_proxy import routing
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
        "--log-level",
        type=click.Choice(["debug", "info", "warning", "error"]),
        help="debug adds per-redaction and per-chunk OPF events.",
    ),
    click.option(
        "--unredact",
        type=click.Choice(["stream", "hook", "off"]),
        help="stream: restore in responses; hook: restore at tool execution "
        "via the plugin; off: awareness mode.",
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
    click.echo(f"   unredact:   {health.get('unredact', '?')}")
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


def _route_on(cfg: Config, force: bool) -> None:
    path = routing.settings_path()
    try:
        result = routing.route_on(path, cfg.base_url, force=force)
    except routing.RouteConflict as exc:
        raise click.ClickException(str(exc)) from exc
    except ValueError as exc:
        raise click.ClickException(f"{path}: {exc}") from exc
    if result.changed:
        click.echo(f"routed: {path} env.ANTHROPIC_BASE_URL = {cfg.base_url}")
        if result.backup:
            click.echo(f"backup: {result.backup}")
    else:
        click.echo(f"already routed via {path}")
    click.echo(routing.CAVEATS)


@cli.command()
@click.option("--off", is_flag=True, help="Remove the routing this command added.")
@click.option("--force", is_flag=True, help="Replace a foreign ANTHROPIC_BASE_URL.")
def route(off: bool, force: bool) -> None:
    """Route every Claude Code session through the proxy (~/.claude/settings.json)."""
    cfg = load_config()
    if not off:
        _route_on(cfg, force)
        return
    path = routing.settings_path()
    try:
        result = routing.route_off(path, cfg.base_url)
    except ValueError as exc:
        raise click.ClickException(f"{path}: {exc}") from exc
    if result.changed:
        click.echo(f"unrouted: removed {', '.join(result.removed)} from {path}")
        click.echo(f"backup: {result.backup}")
    elif result.previous:
        click.echo(
            f"left alone: ANTHROPIC_BASE_URL={result.previous!r} is not this proxy"
        )
    else:
        click.echo("already unrouted")


def download_model(model: str) -> str:
    from huggingface_hub import snapshot_download

    return snapshot_download(model)


@cli.command()
@click.option("--no-download", is_flag=True, help="Skip the model download.")
@click.option("--no-route", is_flag=True, help="Don't touch ~/.claude/settings.json.")
@click.option("--force", is_flag=True, help="Replace a foreign ANTHROPIC_BASE_URL.")
def setup(no_download: bool, no_route: bool, force: bool) -> None:
    """First-run: download the model, write config, route Claude Code."""
    cfg = load_config()
    if not (
        doctormod.platform.system() == "Darwin"
        and doctormod.platform.machine() == "arm64"
    ):
        raise click.ClickException(
            "Apple Silicon Mac required (the OPF model runs on MLX)"
        )
    path = cfgmod.config_path()
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(cfg.to_toml())
        click.echo(f"config: wrote {path}")
    else:
        click.echo(f"config: {path}")
    if no_download:
        click.echo("model: skipped")
    elif doctormod.model_cache_dir(cfg.model):
        click.echo(f"model: {cfg.model} already cached")
    else:
        click.echo(f"model: downloading {cfg.model} (~1.4 GB) ...")
        try:
            where = download_model(cfg.model)
        except Exception as exc:
            raise click.ClickException(f"download failed: {exc}") from exc
        click.echo(f"model: {where}")
    if no_route:
        click.echo("routing: skipped")
    else:
        _route_on(cfg, force)
    click.echo(
        "\nnext:\n"
        "  brew services start llm-redact-proxy    # or: redact-proxy run\n"
        "  redact-proxy doctor\n"
        "optional guarded rehydration (see README threat model):\n"
        "  /plugin marketplace add CupOfGeo/llm-redact-proxy   # inside Claude Code\n"
        "  /plugin install redact-proxy@cupofgeo\n"
        "  redact-proxy config set unredact hook"
    )


@cli.command()
@click.option("--json", "as_json", is_flag=True, help="Machine-readable output.")
@click.option(
    "--fix", is_flag=True, help="Apply safe fixes (route; remove legacy service)."
)
def doctor(as_json: bool, fix: bool) -> None:
    """Check platform, model, service, and Claude Code routing. Exit 1 on failure."""
    cfg = load_config()
    probes = doctormod.Probes(health=fetch_health)
    checks = doctormod.run_checks(cfg, probes)
    if fix:
        fixes = []
        by_name = {c.name: c for c in checks}
        if by_name["launchd"].ok is False:
            fixes += doctormod.remove_legacy_service()
        if by_name["claude routing"].ok is False and not by_name[
            "claude routing"
        ].detail.startswith("ANTHROPIC_BASE_URL points elsewhere"):
            routing.route_on(routing.settings_path(), cfg.base_url)
            fixes.append("routed via settings.json")
        for f in fixes:
            click.echo(f"fixed: {f}")
        checks = doctormod.run_checks(cfg, probes)
    failed = [c for c in checks if c.ok is False]
    if as_json:
        click.echo(json.dumps([c.__dict__ for c in checks]))
    else:
        for c in checks:
            click.echo(f"{c.icon} {c.name:<15} {c.detail}")
            if c.hint and c.ok is False:
                click.echo(f"   ↳ {c.hint}")
        click.echo("all good" if not failed else f"{len(failed)} problem(s)")
    sys.exit(1 if failed else 0)


HOOK_SNIPPET = {
    "hooks": {
        "SessionStart": [
            {
                "hooks": [
                    {
                        "type": "command",
                        "command": (
                            "redact-proxy status >/dev/null 2>&1 || echo "
                            "'⛔ redact-proxy is not ready: this session is NOT redacting "
                            "(run: redact-proxy doctor)'"
                        ),
                    }
                ]
            }
        ]
    }
}


@cli.command("hook-snippet")
def hook_snippet() -> None:
    """Print a SessionStart hook that warns when the proxy is down (advisory only)."""
    click.echo(json.dumps(HOOK_SNIPPET, indent=2))
    click.echo(
        "# merge into ~/.claude/settings.json. Hooks can warn but cannot block a "
        "session; routing itself is fail-closed.",
        err=True,
    )


@cli.group()
def hook() -> None:
    """Claude Code hook entry points (used by the redact-proxy plugin)."""


def _run_hook(event: str) -> None:
    from redact_proxy import hook as hookmod

    sys.exit(hookmod.main([event]))


@hook.command("pre-tool-use")
def hook_pre_tool_use() -> None:
    """Restore placeholders in tool input via /restore, under exfil policy."""
    _run_hook("pre-tool-use")


@hook.command("session-start")
def hook_session_start() -> None:
    """Warn (advisory) when the proxy is not ready at session start."""
    _run_hook("session-start")


def main() -> None:
    cli(prog_name="redact-proxy")


if __name__ == "__main__":
    main()
