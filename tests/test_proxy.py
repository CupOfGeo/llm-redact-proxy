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
    assert resp.json()["unredact"] is True
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


def echo_placeholder_response(text: str) -> httpx.Response:
    return httpx.Response(
        200,
        json={"id": "msg_1", "content": [{"type": "text", "text": text}]},
        headers={"x-custom": "kept"},
    )


async def test_non_streaming_restore_on_by_default(proxy_client, upstream) -> None:
    # The request path records the mapping; upstream echoes the placeholder;
    # the client gets the real value back.
    upstream.response = echo_placeholder_response(f"run: {GH_PLACEHOLDER}")
    resp = await proxy_client.post(
        "/v1/messages", json=message_body(f"my token {GH_TOKEN}")
    )
    assert resp.json()["content"][0]["text"] == f"run: {GH_TOKEN}"
    assert resp.headers["x-custom"] == "kept"


async def test_non_streaming_unknown_placeholder_untouched(
    proxy_client, upstream
) -> None:
    unknown = _placeholder("secret", "minted-before-a-restart")
    upstream.response = echo_placeholder_response(unknown)
    resp = await proxy_client.post("/v1/messages", json=message_body("hi"))
    assert resp.json()["content"][0]["text"] == unknown


async def test_awareness_mode_flag_off(proxy_client, upstream, monkeypatch) -> None:
    from redact_proxy import server

    monkeypatch.setattr(server, "UNREDACT", False)
    upstream.response = echo_placeholder_response(f"run: {GH_PLACEHOLDER}")
    resp = await proxy_client.post(
        "/v1/messages", json=message_body(f"my token {GH_TOKEN}")
    )
    assert resp.json()["content"][0]["text"] == f"run: {GH_PLACEHOLDER}"


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


async def test_unmatched_pem_begin_cannot_eat_later_messages(
    proxy_client, upstream
) -> None:
    """Regression: the PEM rule runs over the raw JSON body. A BEGIN with
    fewer than 64 chars before its END (a test fixture, a grep hit) used to
    match lazily across string/message boundaries to the *next* END,
    deleting whole tool_use blocks while leaving valid JSON — the API then
    rejected the orphaned tool_result."""
    fixture = "pem = '-----BEGIN PRIVATE KEY-----' + 'A' * 64  # no END here"
    later = "-----END PRIVATE KEY-----"
    tool_id = "toolu_01ABCDEFGHIJKLMNOPQRSTUV"
    body = {
        "model": "claude-sonnet-5",
        "messages": [
            {"role": "user", "content": [{"type": "text", "text": fixture}]},
            {
                "role": "assistant",
                "content": [
                    {"type": "tool_use", "id": tool_id, "name": "Bash", "input": {}}
                ],
            },
            {
                "role": "user",
                "content": [
                    {"type": "tool_result", "tool_use_id": tool_id, "content": later}
                ],
            },
        ],
    }
    resp = await proxy_client.post("/v1/messages", json=body)
    assert resp.status_code == 200
    sent = json.loads(upstream.requests[0].content)["messages"]
    assert len(sent) == 3
    assert sent[1]["content"][0]["id"] == tool_id
    assert sent[2]["content"][0]["tool_use_id"] == tool_id
    assert sent[0]["content"][0]["text"] == fixture


def sse_with_placeholder() -> tuple[list[bytes], bytes]:
    events = (
        b'event: message_start\ndata: {"type":"message_start"}\n\n'
        b"event: content_block_start\n"
        b'data: {"type":"content_block_start","index":0,'
        b'"content_block":{"type":"text","text":""}}\n\n'
        b"event: content_block_delta\n"
        b'data: {"type":"content_block_delta","index":0,'
        b'"delta":{"type":"text_delta","text":"run '
        + GH_PLACEHOLDER[:9].encode()
        + b'"}}\n\n'
        b"event: content_block_delta\n"
        b'data: {"type":"content_block_delta","index":0,'
        b'"delta":{"type":"text_delta","text":"'
        + GH_PLACEHOLDER[9:].encode()
        + b' now"}}\n\n'
        b'event: content_block_stop\ndata: {"type":"content_block_stop","index":0}\n\n'
        b'event: message_stop\ndata: {"type":"message_stop"}\n\n'
    )
    cut = events.index("⟨".encode()) + 2  # mid-UTF-8, mid-placeholder
    return [events[:cut], events[cut : cut + 40], events[cut + 40 :]], events


async def test_sse_restore_across_deltas_and_chunks(proxy_client, upstream) -> None:
    chunks, _ = sse_with_placeholder()
    upstream.sse(chunks)
    resp = await proxy_client.post(
        "/v1/messages", json=message_body(f"my token {GH_TOKEN}")
    )
    body = resp.content.decode()
    assert GH_PLACEHOLDER not in body
    assert f'"text":"run {GH_TOKEN}' in body or f'"text":"{GH_TOKEN}' in body
    assert body.endswith('data: {"type":"message_stop"}\n\n')


async def test_sse_awareness_mode_byte_identical(
    proxy_client, upstream, monkeypatch
) -> None:
    from redact_proxy import server

    monkeypatch.setattr(server, "UNREDACT", False)
    chunks, events = sse_with_placeholder()
    upstream.sse(chunks)
    resp = await proxy_client.post(
        "/v1/messages", json=message_body(f"my token {GH_TOKEN}")
    )
    assert resp.content == events


def flag_pipe(needle: str):
    """Fake OPF pipe flagging every occurrence of `needle`."""

    def pipe(chunk: str):
        return [
            {"entity_group": "secret", "start": i, "end": i + len(needle)}
            for i in range(len(chunk))
            if chunk.startswith(needle, i)
        ]

    return pipe


def compact(body: dict) -> dict:
    """kwargs posting `body` in the SDK's compact wire format."""
    return {
        "content": json.dumps(body, separators=(",", ":")),
        "headers": {"content-type": "application/json"},
    }


TOOL_USE = {"type": "tool_use", "id": "toolu_1", "name": "Bash", "input": {}}


async def test_tool_use_input_strings_scanned_by_opf(proxy_client, upstream) -> None:
    from redact_proxy import server

    server.redactor._pipe = flag_pipe("hunter2")
    block = TOOL_USE | {
        "input": {
            "command": "echo hunter2 > creds.txt",
            "args": ["hunter2"],
            "nested": {"k": "hunter2"},
        }
    }
    body = {"model": "m", "messages": [{"role": "assistant", "content": [block]}]}
    await proxy_client.post("/v1/messages", json=body)
    sent = json.loads(upstream.requests[0].content)["messages"][0]["content"][0]
    assert "hunter2" not in json.dumps(sent["input"])
    assert set(sent["input"]) == {"command", "args", "nested"}  # keys untouched
    assert sent["id"] == "toolu_1" and sent["name"] == "Bash"


async def test_structure_change_is_refused(proxy_client, upstream, monkeypatch) -> None:
    from redact_proxy import server

    def eats_a_block(text: str) -> str:  # a hypothetical boundary-spanning rule
        return text.replace(json.dumps(TOOL_USE, separators=(",", ":")) + ",", "")

    monkeypatch.setattr(server.redactor, "regex_redact", eats_a_block)
    body = {
        "model": "m",
        "messages": [
            {"role": "assistant", "content": [TOOL_USE, {"type": "text", "text": "x"}]}
        ],
    }
    resp = await proxy_client.post("/v1/messages", **compact(body))
    assert resp.status_code == 500
    assert "structure" in resp.json()["error"]["message"]
    assert upstream.requests == []  # never forwarded


async def test_broken_json_after_redaction_is_refused(
    proxy_client, upstream, monkeypatch
) -> None:
    from redact_proxy import server

    monkeypatch.setattr(server.redactor, "regex_redact", lambda text: text + "}")
    resp = await proxy_client.post("/v1/messages", json=message_body("hi"))
    assert resp.status_code == 500
    assert upstream.requests == []


async def test_non_messages_body_skips_shape_check(proxy_client, upstream) -> None:
    resp = await proxy_client.post("/v1/complete", json={"prompt": "hi"})
    assert resp.status_code == 200
    assert len(upstream.requests) == 1


async def test_upstream_unreachable_is_clean_502(
    proxy_client, upstream, monkeypatch
) -> None:
    from redact_proxy import server

    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    monkeypatch.setattr(
        server, "client", httpx.AsyncClient(transport=httpx.MockTransport(refuse))
    )
    resp = await proxy_client.post("/v1/messages", json=message_body("hi"))
    assert resp.status_code == 502
    err = resp.json()["error"]
    assert err["type"] == "api_error" and "unreachable" in err["message"]


async def test_requests_refused_while_model_loading(proxy_client, upstream) -> None:
    from redact_proxy import server

    server.redactor.loading = True
    resp = await proxy_client.post("/v1/messages", json=message_body("hi"))
    assert resp.status_code == 503
    assert "loading" in resp.json()["error"]["message"]
    assert upstream.requests == []
    health = (await proxy_client.get("/health")).json()
    assert health["state"] == "loading" and health["status"] == "loading"
    server.redactor.loading = False
    assert (
        await proxy_client.post("/v1/messages", json=message_body("hi"))
    ).status_code == 200
    assert (await proxy_client.get("/health")).json()["state"] == "ready"


async def test_model_load_failure_reported(proxy_client, upstream) -> None:
    from redact_proxy import server

    server.redactor.load_error = "RuntimeError: no metal device"
    resp = await proxy_client.post("/v1/messages", json=message_body("hi"))
    assert (
        resp.status_code == 503 and "no metal device" in resp.json()["error"]["message"]
    )
    health = (await proxy_client.get("/health")).json()
    assert health["state"] == "error" and health["load_error"].startswith(
        "RuntimeError"
    )
    assert isinstance(health["pid"], int)
