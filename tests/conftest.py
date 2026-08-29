"""Shared fixtures.

No MLX anywhere: a Redactor without .load() has _pipe=None and runs the
regex floor only, so the whole suite runs on any platform. Layer 2 is
exercised via `fake pipe` callables assigned to redactor._pipe.

Test seam: server.py resolves `client` and `redactor` as module globals at
call time, so monkeypatching them needs a zero-line production diff.
(If tests ever need parallel app instances, app.state is the escape hatch.)
"""

from __future__ import annotations

import os
import tempfile

# Isolate the keyed placeholder hash from the developer's real install key.
# Must happen at import time, before redact_proxy.redactor is imported
# anywhere: test modules compute placeholders in their module bodies.
os.environ["OPF_PROXY_KEY_FILE"] = os.path.join(
    tempfile.mkdtemp(prefix="redact-proxy-test-"), "install.key"
)

import httpx
import pytest

from redact_proxy import server
from redact_proxy.redactor import Redactor


@pytest.fixture
def redactor() -> Redactor:
    return Redactor()


class ChunkStream(httpx.AsyncByteStream):
    """Async byte stream with exact, test-controlled chunk boundaries."""

    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks

    async def __aiter__(self):
        for chunk in self._chunks:
            yield chunk


class MockUpstream:
    """Records requests the proxy forwards; serves a canned response."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.response: httpx.Response | None = None

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.response is not None:
            return self.response
        return httpx.Response(200, json={"ok": True})

    def sse(self, chunks: list[bytes]) -> None:
        """Serve an SSE response streamed with these exact chunk boundaries."""
        self.response = httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            stream=ChunkStream(chunks),
        )


@pytest.fixture
def upstream(monkeypatch) -> MockUpstream:
    mock = MockUpstream()
    monkeypatch.setattr(
        server,
        "client",
        httpx.AsyncClient(transport=httpx.MockTransport(mock.handler)),
    )
    monkeypatch.setattr(server, "redactor", Redactor())
    return mock


@pytest.fixture
async def proxy_client(upstream):
    transport = httpx.ASGITransport(app=server.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://proxy") as c:
        yield c
