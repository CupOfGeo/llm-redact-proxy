"""PII-redacting proxy for the Anthropic API.

Point Claude Code (or any Anthropic SDK client) at this proxy and every
outbound request body is scrubbed of vital PII before it leaves the
machine:

    uv run --extra proxy python -m redact_proxy.server
    ANTHROPIC_BASE_URL=http://127.0.0.1:8787 claude

Redaction is two-layer (see redactor.py): a regex floor over the raw body
that cannot fail, then an OPF pass over the message/system content of
parsed JSON bodies. Responses stream back verbatim. Secrets are never
logged — only categories and counts.
"""

from __future__ import annotations

import json
import os
import sys
import time
from typing import Any

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import Response, StreamingResponse

from redact_proxy.redactor import Redactor

UPSTREAM = os.environ.get("OPF_PROXY_UPSTREAM", "https://api.anthropic.com")
PORT = int(os.environ.get("OPF_PROXY_PORT", "8787"))
# Comma-separated OPF categories to redact, e.g. "secret" or
# "secret,account_number,person". See redactor.DEFAULT_CATEGORIES.
_CATEGORIES_ENV = os.environ.get("OPF_PROXY_CATEGORIES")
# Un-redaction: restore real values in responses so files/commands the
# model writes contain working credentials. ON by default; set
# OPF_PROXY_UNREDACT=0 for "awareness mode" (you see exactly what the
# model saw). Trade-off: a prompt-injected model can echo a placeholder
# into a locally executed tool call and get the real secret restored —
# see README "Threat model".
UNREDACT = os.environ.get("OPF_PROXY_UNREDACT", "1") != "0"

# Hop-by-hop / recalculated headers that must not be forwarded verbatim.
_SKIP_REQ_HEADERS = {"host", "content-length", "connection", "accept-encoding"}
_SKIP_RESP_HEADERS = {
    "content-length",
    "transfer-encoding",
    "content-encoding",
    "connection",
}

# Content keys that carry user/tool text worth scanning. "input" covers
# tool_use blocks (model-authored commands can echo secrets it was shown).
_CONTENT_KEYS = ("text", "content", "thinking", "input")

app = FastAPI()
client = httpx.AsyncClient(timeout=600)
redactor = (
    Redactor(
        categories=frozenset(c.strip() for c in _CATEGORIES_ENV.split(",") if c.strip())
    )
    if _CATEGORIES_ENV
    else Redactor()
)


def _redact_node(node: Any) -> Any:
    if isinstance(node, str):
        return redactor.redact(node)
    if isinstance(node, list):
        return [_redact_node(item) for item in node]
    if isinstance(node, dict):
        out = dict(node)
        for key in _CONTENT_KEYS:
            if key in out:
                out[key] = _redact_node(out[key])
        return out
    return node


def _redact_body(body: bytes) -> bytes:
    """Regex floor on the raw body, then OPF over parsed message content."""
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return body
    text = redactor.regex_redact(text)
    try:
        payload = json.loads(text)
        if isinstance(payload, dict):
            for field in ("system", "messages"):
                if field in payload:
                    payload[field] = _redact_node(payload[field])
        # Compact separators: match SDK wire format so size/flag stay honest.
        text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    except Exception as exc:  # noqa: BLE001 - regex floor already applied
        print(f"  ! OPF pass skipped: {exc}", file=sys.stderr, flush=True)
    return text.encode("utf-8")


def _restore_node(node: Any) -> Any:
    if isinstance(node, str):
        return redactor.restore(node)
    if isinstance(node, list):
        return [_restore_node(item) for item in node]
    if isinstance(node, dict):
        return {k: _restore_node(v) for k, v in node.items()}
    return node


def _restore_body(body: bytes) -> bytes:
    """Un-redact a non-streaming JSON response body.

    Walks every string — the placeholder grammar is unambiguous, so no
    response schema is hardcoded. JSON-aware on purpose: raw byte
    substitution would corrupt multi-line secrets (PEM) inside JSON
    strings. Any failure returns the body unchanged: fail toward
    awareness mode, never toward corrupt output.
    """
    try:
        payload = json.loads(body.decode("utf-8"))
        restored = _restore_node(payload)
        return json.dumps(restored, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )
    except Exception:  # noqa: BLE001 - see docstring
        return body


# Registered before the catch-all so it never proxies upstream.
@app.get("/health")
async def health() -> dict:
    return {
        "status": "ok",
        "model": redactor.model_id,
        "model_loaded": redactor._pipe is not None,
        "categories": sorted(redactor.categories),
        "unredact": UNREDACT,
        "upstream": UPSTREAM,
    }


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def proxy(request: Request, path: str) -> Response:
    body = await request.body()
    stats_before = dict(redactor.stats)
    t0 = time.perf_counter()
    scrubbed = _redact_body(body) if body else body
    redact_ms = (time.perf_counter() - t0) * 1000
    cached = redactor.stats["cached"] - stats_before["cached"]
    scanned = redactor.stats["scanned"] - stats_before["scanned"]
    # Counts NEW redactions only — placeholders already inside cached blocks
    # were counted when first scanned.
    redactions = redactor.stats["redactions"] - stats_before["redactions"]
    redacted_flag = f" [{redactions} REDACTED]" if redactions else ""

    headers = {
        k: v for k, v in request.headers.items() if k.lower() not in _SKIP_REQ_HEADERS
    }
    url = f"{UPSTREAM}/{path}"
    if request.url.query:
        url += f"?{request.url.query}"

    t1 = time.perf_counter()
    upstream = await client.send(
        client.build_request(request.method, url, headers=headers, content=scrubbed),
        stream=True,
    )
    ttfb_ms = (time.perf_counter() - t1) * 1000
    print(
        f"{request.method} /{path} {len(body)}b{redacted_flag} | "
        f"redact {redact_ms:.1f}ms ({scanned} scanned, {cached} cached) | "
        f"upstream ttfb {ttfb_ms:.0f}ms -> {upstream.status_code}",
        flush=True,
    )
    resp_headers = {
        k: v for k, v in upstream.headers.items() if k.lower() not in _SKIP_RESP_HEADERS
    }

    if "text/event-stream" in upstream.headers.get("content-type", ""):

        async def stream():
            async for chunk in upstream.aiter_bytes():
                yield chunk
            await upstream.aclose()
            print(
                f"  stream /{path} done in {time.perf_counter() - t1:.1f}s",
                flush=True,
            )

        return StreamingResponse(
            stream(),
            status_code=upstream.status_code,
            headers=resp_headers,
            media_type="text/event-stream",
        )

    content = await upstream.aread()
    await upstream.aclose()
    if UNREDACT:
        content = _restore_body(content)
    return Response(
        content=content, status_code=upstream.status_code, headers=resp_headers
    )


def main() -> None:
    print(f"Loading {redactor.model_id} ...", flush=True)
    redactor.load()
    print(
        f"redact-proxy on http://127.0.0.1:{PORT} -> {UPSTREAM}\n"
        f"  categories: {', '.join(sorted(redactor.categories))}\n"
        f"  use: ANTHROPIC_BASE_URL=http://127.0.0.1:{PORT} claude",
        flush=True,
    )
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="warning")


if __name__ == "__main__":
    main()
