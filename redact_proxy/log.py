"""structlog setup: JSON rows for the service, pretty console on a tty.

The daemon writes one JSON object per line to stdout (launchd/brew captures
it), so the log is jq-able:

    tail -f $(brew --prefix)/var/log/redact-proxy.log |
      jq -r 'select(.event=="request")'

Nothing sensitive is ever logged — categories, lengths and counts only.
"""

from __future__ import annotations

import logging
import sys

import structlog

LEVELS = ("debug", "info", "warning", "error")


def configure(level: str = "info", json_output: bool | None = None) -> None:
    """Call once at process start. `json_output=None` = auto (tty → console)."""
    if json_output is None:
        json_output = not sys.stdout.isatty()
    renderer = (
        structlog.processors.JSONRenderer()
        if json_output
        else structlog.dev.ConsoleRenderer()
    )
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=False),
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper())
        ),
        logger_factory=structlog.PrintLoggerFactory(sys.stdout),
        # Not cached: tests reconfigure via capture_logs.
        cache_logger_on_first_use=False,
    )


def get(name: str) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(module=name)
