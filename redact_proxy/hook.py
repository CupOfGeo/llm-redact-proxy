"""Claude Code hook entry points: `python -m redact_proxy.hook <event>`.

STDLIB-ONLY (see grammar.py): this runs on every matched tool call. The
fast path — no placeholder anywhere in the tool input — must cost only
interpreter startup: scan strings, print nothing, exit 0.

pre-tool-use, when a placeholder IS present:
  1. Exfil check first: any external URL/hostname in the same tool input
     (outside `restore_allow_hosts`) → emit permissionDecision per
     `restore_policy` ("ask"/"deny") with a reason, and do NOT restore.
     If the user allows an "ask", the tool runs with placeholders — safe.
  2. Clean input → POST /restore on the proxy → emit `updatedInput` with
     real values. No permissionDecision: the normal permission flow is
     untouched; only the input is rewritten.
  3. Proxy unreachable → passthrough with a systemMessage warning (fail
     toward awareness: placeholders stay placeholders).

Never exits non-zero: a broken hook must not break tool use.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import tomllib
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from redact_proxy.grammar import PLACEHOLDER_RE, install_key

# Hosts that never count as exfil targets.
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}

# scheme://host — any TLD once a scheme is present.
_URL_HOST_RE = re.compile(r"\b[a-z][a-z0-9+.-]{1,20}://([^/\s:'\"@\]]+)", re.IGNORECASE)
# user@host (ssh remotes, curl -u style riders on real egress).
_AT_HOST_RE = re.compile(r"[\w.+-]+@((?:[a-z0-9-]+\.)+[a-z]{2,})", re.IGNORECASE)
# Bare domains: common TLDs only, and not inside a filesystem path
# (lookbehind bars a preceding / . or word char: /tmp/x.com.txt is a path).
_BARE_HOST_RE = re.compile(
    r"(?<![/\w.@-])((?:[a-z0-9-]+\.)+"
    r"(?:com|net|org|io|ai|dev|app|cloud|co|sh|xyz|me|info|gg|so|to|is))"
    r"(?![\w-])",
    re.IGNORECASE,
)


def _config_path() -> Path:
    """Mirrors config.config_path(); duplicated because config.py imports
    the structlog-heavy redactor (a sync test pins the two together)."""
    if explicit := os.environ.get("OPF_PROXY_CONFIG"):
        return Path(explicit).expanduser()
    base = Path(os.environ.get("XDG_CONFIG_HOME") or "~/.config").expanduser()
    return base / "llm-redact-proxy" / "config.toml"


def _settings() -> dict[str, Any]:
    data: dict[str, Any] = {}
    path = _config_path()
    if path.exists():
        try:
            with path.open("rb") as fh:
                data = tomllib.load(fh)
        except (OSError, tomllib.TOMLDecodeError):
            data = {}
    port = os.environ.get("OPF_PROXY_PORT") or data.get("port") or 8787
    policy = (
        os.environ.get("OPF_PROXY_RESTORE_POLICY")
        or data.get("restore_policy")
        or "ask"
    )
    hosts = os.environ.get("OPF_PROXY_RESTORE_ALLOW_HOSTS")
    allow = (
        [h.strip() for h in hosts.split(",") if h.strip()]
        if hosts is not None
        else list(data.get("restore_allow_hosts") or [])
    )
    return {
        "base_url": f"http://127.0.0.1:{int(port)}",
        "policy": policy if policy in ("ask", "deny") else "ask",
        "allow": [h.lower().lstrip(".") for h in allow],
    }


def _strings(node: Any):
    if isinstance(node, str):
        yield node
    elif isinstance(node, list):
        for item in node:
            yield from _strings(item)
    elif isinstance(node, dict):
        for value in node.values():
            yield from _strings(value)


def _allowed(host: str, allow: list[str]) -> bool:
    host = host.lower().rstrip(".")
    if host in _LOCAL_HOSTS or host.endswith(".local"):
        return True
    return any(host == a or host.endswith("." + a) for a in allow)


def external_hosts(tool_input: Any, allow: list[str]) -> list[str]:
    hosts: set[str] = set()
    for text in _strings(tool_input):
        for pattern in (_URL_HOST_RE, _AT_HOST_RE, _BARE_HOST_RE):
            for m in pattern.finditer(text):
                host = m.group(1).split(":")[0]  # strip :port
                if not _allowed(host, allow):
                    hosts.add(host.lower())
    return sorted(hosts)


def _restore_request(base_url: str, payload: dict) -> dict:
    token = hashlib.sha256(install_key()).hexdigest()
    req = urllib.request.Request(
        f"{base_url}/restore",
        data=json.dumps(payload, ensure_ascii=False).encode(),
        headers={"content-type": "application/json", "x-redact-auth": token},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.load(resp)


def pre_tool_use(payload: dict) -> dict | None:
    """Returns the hook JSON output, or None for silent passthrough."""
    tool_input = payload.get("tool_input")
    if not any(PLACEHOLDER_RE.search(s) for s in _strings(tool_input)):
        return None
    cfg = _settings()
    hosts = external_hosts(tool_input, cfg["allow"])
    if hosts:
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": cfg["policy"],
                "permissionDecisionReason": (
                    "redact-proxy: this tool input contains redacted secret(s) "
                    f"AND external host(s): {', '.join(hosts)}. Restoration "
                    "withheld (possible exfiltration). Allowing runs it with "
                    "placeholders; trusted hosts go in restore_allow_hosts."
                ),
            }
        }
    try:
        result = _restore_request(
            cfg["base_url"], {"input": tool_input, "tool": payload.get("tool_name")}
        )
    except (urllib.error.URLError, OSError, ValueError, TimeoutError):
        return {
            "systemMessage": (
                "redact-proxy is not reachable — placeholders were NOT restored "
                "in this tool call (run: redact-proxy status)"
            )
        }
    if not result.get("restored"):
        return None  # only unknown placeholders: nothing to rewrite
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "updatedInput": result["input"],
        }
    }


def session_start(_payload: dict) -> dict | None:
    cfg = _settings()
    try:
        with urllib.request.urlopen(f"{cfg['base_url']}/health", timeout=2) as resp:
            state = json.load(resp).get("state")
    except (urllib.error.URLError, OSError, ValueError, TimeoutError):
        state = "down"
    if state == "ready":
        return None
    return {
        "systemMessage": (
            f"⛔ redact-proxy is {state}: this session is NOT redacting "
            "(run: redact-proxy doctor)"
        )
    }


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    handlers = {"pre-tool-use": pre_tool_use, "session-start": session_start}
    handler = handlers.get(argv[0] if argv else "")
    if handler is None:
        print(
            f"usage: python -m redact_proxy.hook [{'|'.join(handlers)}]",
            file=sys.stderr,
        )
        return 0  # never break a tool call over a wiring mistake
    try:
        payload = json.loads(sys.stdin.read() or "{}")
    except ValueError:
        payload = {}
    try:
        out = handler(payload)
    except Exception as exc:  # noqa: BLE001 - a broken hook must not block tools
        print(f"redact-proxy hook error: {exc}", file=sys.stderr)
        return 0
    if out is not None:
        print(json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
