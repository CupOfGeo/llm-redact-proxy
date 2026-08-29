"""Placeholder grammar and the per-install hash key.

STDLIB-ONLY on purpose: redact_proxy.hook runs on every matched tool call
and must not drag in structlog/click/httpx (~150 ms of imports). Anything
both the hook and the redactor need lives here.
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
from functools import lru_cache
from pathlib import Path

# The full placeholder grammar. Unambiguous: nothing else in ordinary
# text or code produces this shape.
PLACEHOLDER_RE = re.compile(r"⟨REDACTED:[a-z0-9_]+:[0-9a-f]{12}⟩")


def _key_file() -> Path:
    """Where the per-install hash key lives (beside the config file).

    Duplicates config.config_path()'s XDG logic on purpose: config.py
    imports this module, so importing it back would be circular.
    """
    if explicit := os.environ.get("OPF_PROXY_KEY_FILE"):
        return Path(explicit).expanduser()
    base = Path(os.environ.get("XDG_CONFIG_HOME") or "~/.config").expanduser()
    return base / "llm-redact-proxy" / "install.key"


@lru_cache(maxsize=1)
def install_key() -> bytes:
    """32 random bytes, generated once per install.

    Keying the placeholder hash means the API side cannot precompute
    digests (no dictionary filtering of guessable secrets, no cross-install
    linkability). The key protects against the *cloud*, not local access —
    anyone who can read this file can read the actual secrets too.
    """
    path = _key_file()
    if path.exists():
        key = path.read_bytes()
        if len(key) < 16:
            raise ValueError(
                f"{path} is corrupt ({len(key)} bytes); delete to regenerate"
            )
        return key
    key = secrets.token_bytes(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(mode=0o600)
    path.write_bytes(key)
    return key


def _placeholder(category: str, value: str) -> str:
    # Keyed (see install_key) and 48 bits wide: collisions would make
    # restore() splice the wrong secret, so birthday-margin matters.
    digest = hashlib.blake2b(
        value.encode(), key=install_key(), digest_size=6
    ).hexdigest()
    return f"⟨REDACTED:{category}:{digest}⟩"
