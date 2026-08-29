"""Response-side un-redaction for SSE streams.

The request path replaces secrets with ``⟨REDACTED:category:hash⟩``
placeholders and remembers the reverse mapping in memory. On the way back,
a placeholder can be split across delta events and across raw byte chunks,
so restoring it needs a small amount of state:

* :class:`TextRestorer` is a per-content-block incremental restorer. It
  substitutes complete placeholders and holds back only the longest tail
  that could still grow into one; ``flush()`` releases whatever is held.
  In ``json_fragment`` mode (tool_use ``input_json_delta``) the brackets
  may also arrive as JSON ``\\u27e8``/``\\u27e9`` escapes, and restored
  values are spliced in JSON-string-escaped so the tool input stays valid.

* :class:`SSERestorer` buffers bytes to complete events, keys off the
  parsed JSON ``type`` (never the ``event:`` line), rewrites only
  ``content_block_delta`` payloads, and emits a synthetic delta carrying a
  held tail *before* the block's ``content_block_stop``. Every other event —
  and anything it cannot parse — is forwarded byte-verbatim. The rewriter
  can only fail open to passthrough.

The placeholder grammar mirrors ``redactor.PLACEHOLDER_RE``; the extra
partial-match machinery here is why it is spelled out again.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping

# Longest tail a false start may hold back. Categories are short words; the
# cap bounds latency and memory if the grammar's unbounded `[a-z0-9_]+` is
# ever fed a runaway.
MAX_PLACEHOLDER_LEN = 64

_OPEN, _CLOSE = "⟨", "⟩"
_ESC_OPEN = r"\\u27[eE]8"
_ESC_CLOSE = r"\\u27[eE]9"
_BODY = r"REDACTED:([a-z0-9_]+):([0-9a-f]{6})"

_PLAIN_RE = re.compile(_OPEN + _BODY + _CLOSE)
_FRAG_RE = re.compile(f"(?:{_OPEN}|{_ESC_OPEN}){_BODY}(?:{_CLOSE}|{_ESC_CLOSE})")


def _prefixes(literal: str) -> str:
    """Regex matching any prefix of `literal`, the empty string included."""
    out = ""
    for ch in reversed(literal):
        out = f"(?:{re.escape(ch)}{out})?"
    return out


# Any proper prefix of the escaped bracket: `\`, `\u`, `\u2`, `\u27`, `\u27e`.
_ESC_PARTIAL = r"\\(?:u(?:2(?:7(?:[eE])?)?)?)?"

# A suffix that could still become a placeholder once more text arrives.
_PARTIAL_PLAIN_RE = re.compile(
    _OPEN
    + "(?:"
    + _prefixes("REDACTED:")
    + "|REDACTED:[a-z0-9_]+(?::[0-9a-f]{0,6})?"
    + ")$"
)
_PARTIAL_FRAG_RE = re.compile(
    "(?:"
    + f"(?:{_OPEN}|{_ESC_OPEN})"
    + "(?:"
    + _prefixes("REDACTED:")
    + "|REDACTED:[a-z0-9_]+"
    + f"(?::(?:[0-9a-f]{{0,5}}|[0-9a-f]{{6}}(?:{_ESC_PARTIAL})?))?"
    + ")"
    + f"|{_ESC_PARTIAL}"
    + ")$"
)


class TextRestorer:
    """Incremental placeholder → value restorer for one content block."""

    def __init__(self, reverse: Mapping[str, str], json_fragment: bool = False):
        self._reverse = reverse
        self._json_fragment = json_fragment
        self._full = _FRAG_RE if json_fragment else _PLAIN_RE
        self._partial = _PARTIAL_FRAG_RE if json_fragment else _PARTIAL_PLAIN_RE
        self.pending = ""

    def _substitute(self, m: re.Match) -> str:
        key = f"{_OPEN}REDACTED:{m.group(1)}:{m.group(2)}{_CLOSE}"
        value = self._reverse.get(key)
        if value is None:  # unknown (minted before a restart): leave as is
            return m.group()
        if self._json_fragment:
            return json.dumps(value, ensure_ascii=False)[1:-1]
        return value

    def feed(self, text: str) -> str:
        """Return text safe to emit now; a viable placeholder tail is held."""
        buf = self._full.sub(self._substitute, self.pending + text)
        m = self._partial.search(buf[-MAX_PLACEHOLDER_LEN:])
        if m is None:
            self.pending = ""
            return buf
        self.pending = m.group()
        return buf[: len(buf) - len(self.pending)]

    def flush(self) -> str:
        out, self.pending = self.pending, ""
        return out


_EVENT_END = re.compile(rb"\r?\n\r?\n")
_DELTA_FIELDS = {
    "text_delta": "text",
    "thinking_delta": "thinking",
    "input_json_delta": "partial_json",
}
_BLOCK_DELTAS = {
    "text": "text_delta",
    "thinking": "thinking_delta",
    "tool_use": "input_json_delta",
}


def _dumps(payload: dict) -> bytes:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()


class SSERestorer:
    """Rewrite an Anthropic SSE byte stream, restoring placeholders."""

    def __init__(self, reverse: Mapping[str, str]):
        self._reverse = reverse
        self._buf = b""
        self._blocks: dict[int, tuple[TextRestorer, str]] = {}

    def feed(self, chunk: bytes) -> bytes:
        self._buf += chunk
        out: list[bytes] = []
        while (m := _EVENT_END.search(self._buf)) is not None:
            event, self._buf = self._buf[: m.end()], self._buf[m.end() :]
            out.append(self._event(event))
        return b"".join(out)

    def flush(self) -> bytes:
        """End of stream: release held tails, then any unterminated bytes."""
        out = [
            self._synthetic(index, restorer.flush(), delta_type, b"\n")
            for index, (restorer, delta_type) in self._blocks.items()
            if restorer.pending
        ]
        self._blocks.clear()
        out.append(self._buf)
        self._buf = b""
        return b"".join(out)

    @staticmethod
    def _synthetic(index: int, text: str, delta_type: str, nl: bytes) -> bytes:
        payload = {
            "type": "content_block_delta",
            "index": index,
            "delta": {"type": delta_type, _DELTA_FIELDS[delta_type]: text},
        }
        return (
            b"event: content_block_delta" + nl + b"data: " + _dumps(payload) + nl + nl
        )

    def _event(self, event: bytes) -> bytes:
        nl = b"\r\n" if b"\r\n" in event else b"\n"
        lines = event.split(nl)
        data_at = next(
            (i for i, ln in enumerate(lines) if ln.startswith(b"data:")), None
        )
        if data_at is None:
            return event
        try:
            payload = json.loads(lines[data_at][5:])
        except ValueError:
            return event
        if not isinstance(payload, dict):
            return event
        kind = payload.get("type")
        index = payload.get("index")

        if kind == "content_block_start":
            block_type = (payload.get("content_block") or {}).get("type")
            delta_type = _BLOCK_DELTAS.get(block_type)
            if isinstance(index, int) and delta_type is not None:
                self._blocks[index] = (
                    TextRestorer(self._reverse, json_fragment=block_type == "tool_use"),
                    delta_type,
                )
            return event

        if kind == "content_block_delta":
            entry = self._blocks.get(index)
            delta = payload.get("delta") or {}
            field = _DELTA_FIELDS.get(delta.get("type"))
            if entry is None or field is None or not isinstance(delta.get(field), str):
                return event
            restored = entry[0].feed(delta[field])
            if restored == delta[field]:
                return event  # byte-identical when nothing changed
            delta[field] = restored
            lines[data_at] = b"data: " + _dumps(payload)
            return nl.join(lines)

        if kind == "content_block_stop":
            entry = self._blocks.pop(index, None)
            if entry is None:
                return event
            restorer, delta_type = entry
            tail = restorer.flush()
            if not tail:
                return event
            return self._synthetic(index, tail, delta_type, nl) + event

        return event
