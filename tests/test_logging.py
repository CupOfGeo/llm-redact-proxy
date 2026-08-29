"""Structured log events: request rows, refusals, upstream errors, debug detail."""

from __future__ import annotations

import json

import httpx
import pytest
from structlog.testing import capture_logs

from redact_proxy import log
from redact_proxy.redactor import Redactor

GH_TOKEN = "ghp_" + "A" * 36


def message_body(text: str) -> dict:
    return {
        "model": "claude-sonnet-5",
        "messages": [{"role": "user", "content": [{"type": "text", "text": text}]}],
    }


async def test_request_row_fields(proxy_client, upstream) -> None:
    with capture_logs() as logs:
        await proxy_client.post("/v1/messages", json=message_body(f"tok {GH_TOKEN}"))
    [row] = [e for e in logs if e["event"] == "request"]
    assert row["method"] == "POST" and row["path"] == "v1/messages"
    assert row["status"] == 200 and row["redactions"] == 1
    assert {"bytes", "scanned", "cached", "redact_ms", "ttfb_ms"} <= set(row)


async def test_refusal_and_upstream_error_events(
    proxy_client, upstream, monkeypatch
) -> None:
    from redact_proxy import server

    upstream.response = httpx.Response(
        429, json={"type": "error", "error": {"message": "rate limited"}}
    )
    with capture_logs() as logs:
        await proxy_client.post("/v1/messages", json=message_body("hi"))
    [err] = [e for e in logs if e["event"] == "upstream_error"]
    assert err["status"] == 429 and "rate limited" in err["body"]
    assert len(err["body"]) <= 300

    monkeypatch.setattr(server.redactor, "regex_redact", lambda text: text + "}")
    with capture_logs() as logs:
        await proxy_client.post("/v1/messages", json=message_body("hi"))
    assert [e for e in logs if e["event"] == "request_refused"]


def test_debug_redaction_and_chunk_events(redactor: Redactor) -> None:
    redactor._pipe = lambda chunk: (
        [{"entity_group": "secret", "start": 0, "end": 7}]
        if chunk.startswith("hunter2")
        else []
    )
    with capture_logs() as logs:
        redactor.redact(f"hunter2 and {GH_TOKEN}")
    events = {e["event"] for e in logs}
    assert {"redaction", "opf_scan"} <= events
    layers = {(e["layer"], e["category"]) for e in logs if e["event"] == "redaction"}
    assert layers == {("regex", "secret"), ("opf", "secret")}
    for e in logs:
        assert GH_TOKEN not in json.dumps(e)  # never the value
    [scan] = [e for e in logs if e["event"] == "opf_scan"]
    assert scan["chunks"] == 1 and "slowest_ms" in scan


@pytest.mark.parametrize("level,expect_debug", [("info", False), ("debug", True)])
def test_level_filtering(level: str, expect_debug: bool, capsys) -> None:
    import structlog

    log.configure(level, json_output=True)
    try:
        log.get("t").debug("quiet")
        log.get("t").info("loud")
        out = capsys.readouterr().out
        assert ("quiet" in out) is expect_debug
        assert "loud" in out
        row = json.loads(out.strip().splitlines()[-1])
        assert row["event"] == "loud" and "timestamp" in row and row["level"] == "info"
    finally:
        structlog.reset_defaults()
