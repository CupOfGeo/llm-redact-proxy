"""`redact-proxy doctor`: is this machine actually protected?

Every probe is injectable so the checks are unit-testable without a Mac,
a model download, or a running service.
"""

from __future__ import annotations

import os
import platform
import shutil
import socket
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from redact_proxy import routing
from redact_proxy.config import Config

LEGACY_LABEL = "com.llm.redact-proxy"  # `just proxy-install` era launchd service
BREW_LABEL = "homebrew.mxcl.llm-redact-proxy"


@dataclass
class Check:
    name: str
    ok: bool | None  # None = informational / warning, never fails doctor
    detail: str
    hint: str = ""

    @property
    def icon(self) -> str:
        return {True: "✅", False: "❌", None: "•"}[self.ok]


def model_cache_dir(model: str) -> Path | None:
    """Snapshot dir if the HF cache holds the model, else None."""
    from huggingface_hub import constants

    repo = Path(constants.HF_HUB_CACHE) / ("models--" + model.replace("/", "--"))
    snapshots = repo / "snapshots"
    if snapshots.is_dir() and any(snapshots.iterdir()):
        return repo
    return None


def dir_size(path: Path) -> int:
    return sum(
        p.stat().st_size for p in path.rglob("*") if p.is_file() and not p.is_symlink()
    )


def port_open(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


def upstream_tls(cfg) -> tuple[bool, str]:
    """(ok, detail): can we TLS-handshake with the upstream? Recognizes the
    corporate-MITM cert failure (Netskope/Zscaler) and hints at the fix."""
    import ssl
    import urllib.error
    import urllib.request

    context = None
    if not cfg.verify_tls:
        context = ssl._create_unverified_context()
    elif cfg.ca_bundle:
        context = ssl.create_default_context(cafile=cfg.ca_bundle)
    else:
        try:
            import truststore

            context = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        except Exception:  # noqa: BLE001
            context = None  # urllib default (certifi-less system store on mac)
    try:
        urllib.request.urlopen(cfg.upstream, timeout=8, context=context)
        return True, f"{cfg.upstream} reachable"
    except urllib.error.HTTPError:
        return True, f"{cfg.upstream} reachable (TLS ok)"  # 4xx = handshake fine
    except ssl.SSLError as exc:
        return (
            False,
            f"TLS verification failed: {exc.reason if hasattr(exc, 'reason') else exc}",
        )
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"


def plugin_installed() -> bool:
    """Is the redact-proxy Claude Code plugin installed for this user?"""
    manifest = Path.home() / ".claude" / "plugins" / "installed_plugins.json"
    try:
        return "redact-proxy" in manifest.read_text()
    except OSError:
        return False


def launchd_loaded(label: str) -> bool:
    try:
        return (
            subprocess.run(
                ["launchctl", "print", f"gui/{os.getuid()}/{label}"],
                capture_output=True,
                timeout=5,
                check=False,
            ).returncode
            == 0
        )
    except (OSError, subprocess.SubprocessError):
        return False


@dataclass
class Probes:
    system: Callable[[], str] = platform.system
    machine: Callable[[], str] = platform.machine
    model_cache_dir: Callable[[str], Path | None] = model_cache_dir
    health: Callable[[str], dict | None] = lambda url: None
    port_open: Callable[[int], bool] = port_open
    settings_path: Callable[[], Path] = routing.settings_path
    launchd_loaded: Callable[[str], bool] = launchd_loaded
    which: Callable[[str], str | None] = shutil.which
    plugin_installed: Callable[[], bool] = plugin_installed
    shell_base_url: Callable[[], str | None] = lambda: os.environ.get(
        "ANTHROPIC_BASE_URL"
    )
    upstream_tls: Callable = upstream_tls


def run_checks(cfg: Config, probes: Probes) -> list[Check]:
    checks: list[Check] = []

    apple_silicon = probes.system() == "Darwin" and probes.machine() == "arm64"
    checks.append(
        Check(
            "platform",
            apple_silicon,
            f"{probes.system()} {probes.machine()}",
            ""
            if apple_silicon
            else "the OPF model runs on MLX: Apple Silicon Mac required",
        )
    )
    checks.append(
        Check("python", sys.version_info >= (3, 11), platform.python_version())
    )

    cache = probes.model_cache_dir(cfg.model)
    checks.append(
        Check(
            "model cached",
            cache is not None,
            f"{cfg.model} at {cache}" if cache else f"{cfg.model} not downloaded",
            "" if cache else "run: redact-proxy setup",
        )
    )

    health = probes.health(cfg.base_url)
    if health is None:
        busy = probes.port_open(cfg.port)
        checks.append(
            Check(
                "service",
                False,
                f"nothing answering at {cfg.base_url}"
                + (" (port is open — something else owns it?)" if busy else ""),
                "run: brew services start llm-redact-proxy   (or: redact-proxy run)",
            )
        )
    else:
        state = health.get("state", "ready")
        checks.append(
            Check(
                "service",
                state == "ready",
                f"{state} (pid {health.get('pid')}, unredact "
                f"{'on' if health.get('unredact') else 'off'}, upstream {health.get('upstream')})",
                {
                    "loading": "model still loading — wait a moment",
                    "error": str(health.get("load_error")),
                }.get(state, ""),
            )
        )

    settings = probes.settings_path()
    try:
        route = routing.status(settings, cfg.base_url)
    except ValueError as exc:
        route = f"broken:{exc}"
    if route == "routed":
        checks.append(Check("claude routing", True, f"{settings} env → {cfg.base_url}"))
    elif route == "unrouted":
        checks.append(
            Check(
                "claude routing",
                False,
                f"no ANTHROPIC_BASE_URL in {settings}",
                "run: redact-proxy route   (covers CLI, desktop and IDE sessions)",
            )
        )
    else:
        checks.append(
            Check(
                "claude routing",
                False,
                route.replace("elsewhere:", "ANTHROPIC_BASE_URL points elsewhere: "),
                "run: redact-proxy route --force   (after checking that URL)",
            )
        )

    shell_url = probes.shell_base_url()
    checks.append(
        Check(
            "shell env",
            None,
            f"ANTHROPIC_BASE_URL={shell_url}"
            if shell_url
            else "ANTHROPIC_BASE_URL not exported (fine when routed via settings.json)",
        )
    )

    legacy, brew = (
        probes.launchd_loaded(LEGACY_LABEL),
        probes.launchd_loaded(BREW_LABEL),
    )
    if legacy and brew:
        checks.append(
            Check(
                "launchd",
                False,
                f"both {LEGACY_LABEL} (just proxy-install) and {BREW_LABEL} are loaded",
                "run: redact-proxy doctor --fix   (removes the legacy service)",
            )
        )
    elif legacy:
        checks.append(
            Check(
                "launchd", None, f"legacy {LEGACY_LABEL} service (just proxy-install)"
            )
        )
    elif brew:
        checks.append(Check("launchd", None, f"{BREW_LABEL} (brew services)"))
    else:
        checks.append(
            Check(
                "launchd",
                None,
                "no login service installed (foreground `redact-proxy run` only)",
            )
        )

    mode = (health or {}).get("unredact")
    plugin = probes.plugin_installed()
    if mode == "hook" and not plugin:
        checks.append(
            Check(
                "hook mode",
                False,
                "unredact=hook but the redact-proxy plugin is not installed — "
                "placeholders will NEVER be restored",
                "in Claude Code: /plugin marketplace add CupOfGeo/llm-redact-proxy, "
                "then /plugin install redact-proxy@cupofgeo "
                "(or: redact-proxy config set unredact stream)",
            )
        )
    elif mode == "stream" and plugin:
        checks.append(
            Check(
                "hook mode",
                None,
                "plugin installed but unredact=stream: responses are restored "
                "before the hook runs, so the exfil gate never engages",
                "redact-proxy config set unredact hook && brew services restart llm-redact-proxy",
            )
        )
    elif mode == "hook":
        checks.append(
            Check(
                "hook mode",
                True,
                "unredact=hook + plugin installed (guarded rehydration)",
            )
        )

    tls_ok, tls_detail = probes.upstream_tls(cfg)
    checks.append(
        Check(
            "upstream tls",
            tls_ok,
            tls_detail,
            ""
            if tls_ok
            else "corporate TLS inspection? the OS trust store is used by "
            "default; if it still fails, point at the corporate CA: "
            "redact-proxy config set ca_bundle /path/to/corp-ca.pem "
            "(then restart the service)",
        )
    )

    claude = probes.which("claude")
    checks.append(Check("claude cli", None, claude or "claude not on PATH"))
    return checks


def remove_legacy_service() -> list[str]:
    """`--fix`: unload and delete the just-era launchd service."""
    actions = []
    plist = Path.home() / "Library" / "LaunchAgents" / f"{LEGACY_LABEL}.plist"
    subprocess.run(
        ["launchctl", "bootout", f"gui/{os.getuid()}/{LEGACY_LABEL}"],
        capture_output=True,
        check=False,  # not loaded is fine
    )
    actions.append(f"launchctl bootout {LEGACY_LABEL}")
    if plist.exists():
        plist.unlink()
        actions.append(f"removed {plist}")
    return actions
