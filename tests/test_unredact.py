"""TextRestorer / SSERestorer: placeholders split every which way."""

from __future__ import annotations

import json

import pytest

from redact_proxy.redactor import PLACEHOLDER_RE, _placeholder
from redact_proxy.unredact import (
    _PLAIN_RE,
    MAX_PLACEHOLDER_LEN,
    SSERestorer,
    TextRestorer,
)

SECRET = "ghp_" + "A" * 36
PH = _placeholder("secret", SECRET)
ESC_PH = PH.replace("⟨", "\\u27e8").replace("⟩", "\\u27e9")
REVERSE = {PH: SECRET}


def test_grammar_matches_redactor() -> None:
    assert PLACEHOLDER_RE.fullmatch(PH) and _PLAIN_RE.fullmatch(PH)


# --- TextRestorer -----------------------------------------------------------


@pytest.mark.parametrize("cut", range(1, len(PH)))
def test_split_at_every_boundary(cut: int) -> None:
    r = TextRestorer(REVERSE)
    out = r.feed("run " + PH[:cut]) + r.feed(PH[cut:] + " now") + r.flush()
    assert out == f"run {SECRET} now"


def test_char_by_char() -> None:
    r = TextRestorer(REVERSE)
    text = f"a {PH} b {PH}"
    out = "".join(r.feed(ch) for ch in text) + r.flush()
    assert out == f"a {SECRET} b {SECRET}"


def test_false_start_held_then_flushed() -> None:
    r = TextRestorer(REVERSE)
    assert r.feed("see ⟨REDACTED:sec") == "see "
    assert r.pending == "⟨REDACTED:sec"
    assert r.flush() == "⟨REDACTED:sec"
    assert r.pending == ""


def test_ordinary_bracket_released_on_next_text() -> None:
    r = TextRestorer(REVERSE)
    assert r.feed("math ⟨") == "math "
    assert r.feed("x, y⟩ done") == "⟨x, y⟩ done"


def test_unknown_placeholder_untouched() -> None:
    unknown = _placeholder("secret", "never-recorded")
    r = TextRestorer(REVERSE)
    assert r.feed(f"[{unknown}]") + r.flush() == f"[{unknown}]"


def test_holdback_is_capped() -> None:
    r = TextRestorer(REVERSE)
    r.feed("⟨REDACTED:" + "a" * 200)
    assert len(r.pending) <= MAX_PLACEHOLDER_LEN


def test_fragment_plain_and_escaped_forms() -> None:
    for form in (PH, ESC_PH):
        r = TextRestorer(REVERSE, json_fragment=True)
        out = r.feed('{"cmd":"echo ' + form + '"}') + r.flush()
        assert json.loads(out) == {"cmd": f"echo {SECRET}"}


@pytest.mark.parametrize("cut", range(1, 6))
def test_fragment_split_inside_escape(cut: int) -> None:
    r = TextRestorer(REVERSE, json_fragment=True)
    out = r.feed('"' + ESC_PH[:cut]) + r.feed(ESC_PH[cut:] + '"') + r.flush()
    assert json.loads(out) == SECRET


def test_fragment_value_is_json_escaped() -> None:
    value = 'pa"ss\\wo\nrd'
    ph = _placeholder("secret", value)
    r = TextRestorer({ph: value}, json_fragment=True)
    out = r.feed('{"p":"' + ph + '"}') + r.flush()
    assert json.loads(out)["p"] == value
    # Plain mode splices the raw value.
    assert TextRestorer({ph: value}).feed(ph) == value


# --- SSERestorer ------------------------------------------------------------


def ev(name: str, payload: dict, nl: bytes = b"\n") -> bytes:
    data = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
    return b"event: " + name.encode() + nl + b"data: " + data + nl + nl


def start(index: int, kind: str = "text", nl: bytes = b"\n") -> bytes:
    block: dict = {"type": kind}
    if kind == "tool_use":
        block |= {"id": "toolu_1", "name": "Bash", "input": {}}
    else:
        block[kind] = ""
    return ev(
        "content_block_start",
        {"type": "content_block_start", "index": index, "content_block": block},
        nl,
    )


def delta(index: int, text: str, kind: str = "text_delta", nl: bytes = b"\n") -> bytes:
    field = {"text_delta": "text", "input_json_delta": "partial_json"}.get(
        kind, "thinking"
    )
    return ev(
        "content_block_delta",
        {
            "type": "content_block_delta",
            "index": index,
            "delta": {"type": kind, field: text},
        },
        nl,
    )


def stop(index: int, nl: bytes = b"\n") -> bytes:
    return ev("content_block_stop", {"type": "content_block_stop", "index": index}, nl)


CONTROL = (
    ev("message_start", {"type": "message_start", "message": {"content": []}})
    + ev("ping", {"type": "ping"})
    + ev("message_delta", {"type": "message_delta", "usage": {"output_tokens": 3}})
    + ev("message_stop", {"type": "message_stop"})
)


def run(chunks: list[bytes], reverse: dict | None = None) -> bytes:
    r = SSERestorer(REVERSE if reverse is None else reverse)
    return b"".join(r.feed(c) for c in chunks) + r.flush()


def texts(stream: bytes, index: int | None = None) -> str:
    """Concatenate delta payload text (any delta type) from a stream."""
    out = []
    for line in stream.split(b"\n"):
        if not line.startswith(b"data:"):
            continue
        p = json.loads(line[5:])
        if p.get("type") == "content_block_delta" and index in (None, p["index"]):
            d = p["delta"]
            out.append(
                d.get("text") or d.get("thinking") or d.get("partial_json") or ""
            )
    return "".join(out)


def everywhere(data: bytes) -> list[list[bytes]]:
    """Every 2-way byte split of `data`."""
    return [[data[:i], data[i:]] for i in range(len(data) + 1)]


def test_control_and_clean_deltas_byte_identical() -> None:
    stream = CONTROL + start(0) + delta(0, "hello ⟨x⟩ world") + stop(0)
    for chunks in everywhere(stream):
        assert run(chunks) == stream


def test_placeholder_in_one_delta() -> None:
    stream = start(0) + delta(0, f"run {PH} now") + stop(0)
    assert texts(run([stream])) == f"run {SECRET} now"


def test_split_across_deltas_and_byte_chunks() -> None:
    stream = start(0) + delta(0, "x " + PH[:12]) + delta(0, PH[12:] + " y") + stop(0)
    for chunks in everywhere(stream):
        out = run(chunks)
        assert texts(out) == f"x {SECRET} y"
        assert out.endswith(stop(0))


def test_split_mid_utf8_bracket_byte() -> None:
    stream = start(0) + delta(0, PH) + stop(0)
    i = stream.index("⟨".encode()) + 1  # inside the 3-byte sequence
    assert texts(run([stream[:i], stream[i:]])) == SECRET


def test_flush_before_stop_exact_bytes() -> None:
    held = "⟨REDACTED:se"
    stream = start(0) + delta(0, "abc " + held) + stop(0)
    expected = (
        start(0)
        + delta(0, "abc ")  # tail held back
        + delta(0, held)  # synthetic delta carrying the flushed tail
        + stop(0)
    )
    assert run([stream]) == expected


def test_interleaved_blocks_restore_independently() -> None:
    stream = (
        start(0)
        + start(1, "tool_use")
        + delta(0, "t " + PH[:8])
        + delta(1, '{"cmd":"' + ESC_PH[:9], "input_json_delta")
        + delta(0, PH[8:], "text_delta")
        + delta(1, ESC_PH[9:] + '"}', "input_json_delta")
        + stop(0)
        + stop(1)
    )
    out = run([stream])
    assert texts(out, 0) == f"t {SECRET}"
    assert json.loads(texts(out, 1)) == {"cmd": SECRET}


def test_tool_use_partial_json_reparses_with_awkward_secret() -> None:
    value = 'x"y\\z\n'
    ph = _placeholder("secret", value)
    esc = ph.replace("⟨", "\\u27e8").replace("⟩", "\\u27e9")
    pieces = ['{"command":', '"echo ', esc[:3], esc[3:20], esc[20:], '"}']
    stream = start(0, "tool_use")
    for p in pieces:
        stream += delta(0, p, "input_json_delta")
    stream += stop(0)
    out = run([stream], {ph: value})
    assert json.loads(texts(out)) == {"command": f"echo {value}"}


def test_thinking_delta_restored() -> None:
    stream = start(0, "thinking") + delta(0, f"hm {PH}", "thinking_delta") + stop(0)
    assert texts(run([stream])) == f"hm {SECRET}"


def test_unknown_placeholder_in_stream_untouched() -> None:
    unknown = _placeholder("secret", "gone-after-restart")
    stream = start(0) + delta(0, unknown) + stop(0)
    assert run([stream]) == stream


def test_crlf_stream() -> None:
    nl = b"\r\n"
    stream = start(0, nl=nl) + delta(0, PH, nl=nl) + stop(0, nl=nl)
    out = run([stream])
    assert SECRET.encode() in out and b"\n\n" not in out.replace(b"\r\n", b"")


def test_unparseable_and_foreign_events_verbatim() -> None:
    stream = (
        b"data: not json\n\n"
        b"event: content_block_delta\ndata: [1,2]\n\n"
        b": comment line\n\n"
        + delta(7, PH)  # delta for a block we never saw start
        + b"partial trailing bytes"
    )
    assert run([stream]) == stream


def test_flush_releases_tail_of_unterminated_block() -> None:
    held = "⟨REDACTED:se"
    stream = start(0) + delta(0, held)
    assert run([stream]) == start(0) + delta(0, "") + delta(0, held)


def test_restorer_sees_map_updates() -> None:
    reverse: dict[str, str] = {}
    r = SSERestorer(reverse)
    r.feed(start(0))
    reverse[PH] = SECRET  # recorded after the stream began
    assert SECRET.encode() in r.feed(delta(0, PH))
