"""Proxy e2e over ASGI with a mock upstream: scrubbing, headers, SSE passthrough."""

from __future__ import annotations

import json

import httpx

from redact_proxy.redactor import _placeholder

GH_TOKEN = "ghp_" + "A" * 36
GH_PLACEHOLDER = _placeholder("secret", GH_TOKEN)


def message_body(text: str) -> dict:
    return {
        "model": "claude-sonnet-5",
        "messages": [{"role": "user", "content": [{"type": "text", "text": text}]}],
    }


async def test_body_scrubbed_before_upstream(proxy_client, upstream) -> None:
    resp = await proxy_client.post(
        "/v1/messages", json=message_body(f"my token is {GH_TOKEN}")
    )
    assert resp.status_code == 200
    sent = upstream.requests[0].content.decode()
    assert GH_TOKEN not in sent
    assert GH_PLACEHOLDER in sent
    # Still valid JSON with the surrounding structure intact.
    payload = json.loads(sent)
    assert payload["messages"][0]["content"][0]["text"].endswith(GH_PLACEHOLDER)


async def test_health_is_never_proxied(proxy_client, upstream) -> None:
    resp = await proxy_client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
    assert upstream.requests == []


async def test_headers_and_query_forwarded(proxy_client, upstream) -> None:
    await proxy_client.post(
        "/v1/messages?beta=true",
        json=message_body("hello"),
        headers={"x-api-key": "test-key-value", "anthropic-version": "2023-06-01"},
    )
    req = upstream.requests[0]
    assert req.url.params["beta"] == "true"
    assert req.headers["x-api-key"] == "test-key-value"
    assert req.headers["anthropic-version"] == "2023-06-01"


async def test_non_streaming_response_verbatim(proxy_client, upstream) -> None:
    # Response bodies pass through untouched today — including placeholder-shaped
    # strings. (Phase 2 changes this behind OPF_PROXY_UNREDACT.)
    canned = {"id": "msg_1", "content": [{"type": "text", "text": GH_PLACEHOLDER}]}
    upstream.response = httpx.Response(200, json=canned, headers={"x-custom": "kept"})
    resp = await proxy_client.post("/v1/messages", json=message_body("hi"))
    assert resp.json() == canned
    assert resp.headers["x-custom"] == "kept"


async def test_sse_passthrough_byte_identical(proxy_client, upstream) -> None:
    events = (
        b'event: message_start\ndata: {"type":"message_start"}\n\n'
        b"event: content_block_delta\n"
        b'data: {"type":"content_block_delta","index":0,'
        b'"delta":{"type":"text_delta","text":"hello"}}\n\n'
        b'event: message_stop\ndata: {"type":"message_stop"}\n\n'
    )
    # Split at awkward boundaries: mid-line, mid-event.
    chunks = [events[:17], events[17:60], events[60:61], events[61:]]
    upstream.sse(chunks)
    resp = await proxy_client.post("/v1/messages", json=message_body("hi"))
    assert resp.headers["content-type"].startswith("text/event-stream")
    assert resp.content == events
