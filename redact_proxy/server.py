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

import asyncio
import json
import os
import sys
import time
from contextlib import asynccontextmanager
from typing import Any

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from redact_proxy import config
from redact_proxy.config import Config
from redact_proxy.redactor import Redactor
from redact_proxy.unredact import SSERestorer

# Effective settings (config.toml ← OPF_PROXY_* env). Kept as module
# globals: `serve()` rebinds them from a Config, and tests monkeypatch them.
CONFIG = config.load()
UPSTREAM = CONFIG.upstream
PORT = CONFIG.port
# Un-redaction: restore real values in responses so files/commands the
# model writes contain working credentials. ON by default; off is
# "awareness mode" (you see exactly what the model saw). Trade-off: a
# prompt-injected model can echo a placeholder into a locally executed
# tool call and get the real secret restored — see README "Threat model".
UNREDACT = CONFIG.unredact

# Hop-by-hop / recalculated headers that must not be forwarded verbatim.
_SKIP_REQ_HEADERS = {"host", "content-length", "connection", "accept-encoding"}
_SKIP_RESP_HEADERS = {
    "content-length",
    "transfer-encoding",
    "content-encoding",
    "connection",
}

# Content keys that carry user/tool text worth scanning. Under "input"
# (tool_use blocks) every string is scanned — the keys are tool-defined
# ("command", "content", ...) and model-authored commands can echo secrets
# the model was shown. Elsewhere only these keys are followed, which also
# keeps ids, names and base64 image data out of the model's path.
_CONTENT_KEYS = ("text", "content", "thinking", "input")


async def _load_model() -> None:
    """Background model load; the server answers /health meanwhile."""
    print(f"Loading {redactor.model_id} ...", flush=True)
    try:
        await asyncio.to_thread(redactor.load)
        print("model ready", flush=True)
    except Exception as exc:  # noqa: BLE001 - reported via /health
        redactor.load_error = f"{type(exc).__name__}: {exc}"
        print(f"  ! model load FAILED: {redactor.load_error}", flush=True)
    finally:
        redactor.loading = False


@asynccontextmanager
async def _lifespan(_: FastAPI):
    # `serve()` sets redactor.loading before uvicorn starts; tests drive the
    # app without a lifespan, so a plain Redactor() is never "loading".
    if redactor.loading:
        asyncio.create_task(_load_model())
    yield


app = FastAPI(lifespan=_lifespan)
client = httpx.AsyncClient(timeout=600)
redactor = Redactor(categories=CONFIG.categories, model_id=CONFIG.model)


def _model_state() -> str:
    if redactor.load_error:
        return "error"
    return "loading" if redactor.loading else "ready"


def _redact_strings(node: Any) -> Any:
    """Every string beneath `node` (values only; keys are structure)."""
    if isinstance(node, str):
        return redactor.redact(node)
    if isinstance(node, list):
        return [_redact_strings(item) for item in node]
    if isinstance(node, dict):
        return {k: _redact_strings(v) for k, v in node.items()}
    return node


def _redact_node(node: Any) -> Any:
    if isinstance(node, str):
        return redactor.redact(node)
    if isinstance(node, list):
        return [_redact_node(item) for item in node]
    if isinstance(node, dict):
        out = dict(node)
        for key in _CONTENT_KEYS:
            if key in out:
                walk = _redact_strings if key == "input" else _redact_node
                out[key] = walk(out[key])
        return out
    return node


class RedactionShapeError(Exception):
    """Redaction changed the request's structure; it must not be forwarded."""


def _shape(payload: Any) -> tuple | None:
    """Structural fingerprint: message count, block count, tool ids in order.

    None when the body is not a messages request (nothing to compare).
    """
    if not isinstance(payload, dict) or not isinstance(payload.get("messages"), list):
        return None
    blocks = 0
    ids: list[tuple[str, Any]] = []
    for msg in payload["messages"]:
        content = msg.get("content") if isinstance(msg, dict) else None
        if not isinstance(content, list):
            blocks += 1
            continue
        blocks += len(content)
        for block in content:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "tool_use":
                ids.append(("use", block.get("id")))
            elif block.get("type") == "tool_result":
                ids.append(("result", block.get("tool_use_id")))
    return (len(payload["messages"]), blocks, ids)


def _redact_body(body: bytes) -> bytes:
    """Regex floor on the raw body, then OPF over parsed message content.

    Invariant: redaction never changes the *shape* of a request — message
    and block counts, tool_use/tool_result ids. A pattern that spans JSON
    string boundaries can delete whole blocks while leaving valid JSON
    (the API then rejects the orphaned tool_result). If the shape differs,
    raise rather than forward: a mangled conversation is never right, and
    the only other option is forwarding unredacted.
    """
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return body
    try:
        before = _shape(json.loads(text))
    except ValueError:
        before = None
    text = redactor.regex_redact(text)
    payload: Any = None
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
    if before is not None:
        after = _shape(payload)
        if after != before:
            raise RedactionShapeError(
                "redaction changed message structure "
                f"(messages/blocks/tool-ids before={before[:2]} after="
                f"{after[:2] if after else 'unparseable'})"
            )
    return text.encode("utf-8")


def _error_response(status: int, message: str) -> JSONResponse:
    """Anthropic-shaped error body so SDK clients surface `message` as is."""
    return JSONResponse(
        {"type": "error", "error": {"type": "api_error", "message": message}},
        status_code=status,
    )


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
    state = _model_state()
    return {
        "status": "ok" if state == "ready" else state,
        "state": state,
        "pid": os.getpid(),
        "port": PORT,
        "model": redactor.model_id,
        "model_loaded": redactor._pipe is not None,
        "load_error": redactor.load_error,
        "categories": sorted(redactor.categories),
        "unredact": UNREDACT,
        "upstream": UPSTREAM,
    }


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def proxy(request: Request, path: str) -> Response:
    # Fail closed while the model isn't available: forwarding with only the
    # regex floor would silently weaken the protection the user configured.
    state = _model_state()
    if state != "ready":
        detail = f" ({redactor.load_error})" if state == "error" else ""
        return _error_response(
            503, f"redact-proxy: model {state}{detail} — retry in a moment"
        )
    body = await request.body()
    stats_before = dict(redactor.stats)
    t0 = time.perf_counter()
    try:
        scrubbed = _redact_body(body) if body else body
    except RedactionShapeError as exc:
        print(f"{request.method} /{path} {len(body)}b | REFUSED: {exc}", flush=True)
        return _error_response(500, f"redact-proxy refused to forward: {exc}")
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
    try:
        upstream = await client.send(
            client.build_request(
                request.method, url, headers=headers, content=scrubbed
            ),
            stream=True,
        )
    except httpx.HTTPError as exc:
        print(
            f"{request.method} /{path} {len(body)}b{redacted_flag} | "
            f"upstream unreachable: {type(exc).__name__}: {exc}",
            flush=True,
        )
        return _error_response(
            502, f"redact-proxy: upstream {UPSTREAM} unreachable ({exc})"
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
        # Un-redact the stream in place: the map is shared with the request
        # path, so placeholders minted by this or earlier requests resolve.
        restorer = SSERestorer(redactor.reverse) if UNREDACT else None

        async def stream():
            try:
                async for chunk in upstream.aiter_bytes():
                    out = restorer.feed(chunk) if restorer else chunk
                    if out:
                        yield out
                if restorer and (tail := restorer.flush()):
                    yield tail
            finally:  # also runs on client disconnect — no leaked upstream
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


def serve(cfg: Config) -> None:
    """Bind the module globals to `cfg` and run until interrupted.

    The model loads in the background after the socket is up, so `/health`
    answers `loading` immediately instead of the port looking dead for a
    minute; requests get a 503 until it is ready.
    """
    global CONFIG, UPSTREAM, PORT, UNREDACT, redactor
    CONFIG, UPSTREAM, PORT, UNREDACT = cfg, cfg.upstream, cfg.port, cfg.unredact
    redactor = Redactor(categories=cfg.categories, model_id=cfg.model)
    redactor.loading = True
    print(
        f"redact-proxy on {cfg.base_url} -> {cfg.upstream}\n"
        f"  categories: {', '.join(sorted(cfg.categories))}\n"
        f"  unredact: {'on' if cfg.unredact else 'off (awareness mode)'}\n"
        f"  use: ANTHROPIC_BASE_URL={cfg.base_url} claude",
        flush=True,
    )
    uvicorn.run(app, host="127.0.0.1", port=cfg.port, log_level="warning")


def main() -> None:
    serve(config.load())


if __name__ == "__main__":
    main()
