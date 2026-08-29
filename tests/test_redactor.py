"""Redactor unit tests: two-layer interaction, caching, chunking, guards."""

from __future__ import annotations

import pytest

from redact_proxy.redactor import CHUNK_CHARS, Redactor, _placeholder

GH_TOKEN = "ghp_" + "A" * 36
GH_PLACEHOLDER = _placeholder("secret", GH_TOKEN)


def span_pipe(needle: str, label: str = "secret"):
    """Fake OPF pipe flagging every occurrence of `needle` in the chunk."""

    def pipe(chunk: str):
        spans = []
        start = 0
        while (i := chunk.find(needle, start)) != -1:
            spans.append({"entity_group": label, "start": i, "end": i + len(needle)})
            start = i + 1
        return spans

    return pipe


def test_empty_text(redactor: Redactor) -> None:
    assert redactor.redact("") == ""


def test_regex_layer_only_without_pipe(redactor: Redactor) -> None:
    out = redactor.redact(f"token: {GH_TOKEN}")
    assert GH_TOKEN not in out
    assert GH_PLACEHOLDER in out


def test_two_layers_together(redactor: Redactor) -> None:
    redactor._pipe = span_pipe("hunter2")
    out = redactor.redact(f"token {GH_TOKEN} and password hunter2 here")
    assert GH_TOKEN not in out
    assert "hunter2" not in out
    assert out.count("REDACTED") == 2


def test_category_filter_default_excludes_person(redactor: Redactor) -> None:
    redactor._pipe = span_pipe("Alice", label="PERSON")
    out = redactor.redact("reviewer is Alice today")
    assert "Alice" in out  # person not in DEFAULT_CATEGORIES


def test_category_filter_opt_in() -> None:
    r = Redactor(categories=frozenset({"secret", "person"}))
    r._pipe = span_pipe("Alice", label="PRIVATE_PERSON")  # normalized -> person
    out = r.redact("reviewer is Alice today")
    assert "Alice" not in out
    assert "REDACTED:person:" in out


def test_guard_span_covering_placeholder(redactor: Redactor) -> None:
    # OPF flags the whole placeholder (brackets included) -> must be skipped.
    redactor._pipe = span_pipe(GH_PLACEHOLDER)
    out = redactor.redact(f"token: {GH_TOKEN}")
    assert GH_PLACEHOLDER in out


@pytest.mark.xfail(
    strict=True,
    reason="known bug: guard misses OPF spans strictly inside a placeholder "
    "(brackets excluded) — fixed in phase 2",
)
def test_guard_span_inside_placeholder(redactor: Redactor) -> None:
    inner = GH_PLACEHOLDER[1:-1]  # placeholder content without the brackets
    redactor._pipe = span_pipe(inner)
    out = redactor.redact(f"token: {GH_TOKEN}")
    assert GH_PLACEHOLDER in out  # mangled today


def test_cache_hit_and_stats(redactor: Redactor) -> None:
    text = f"token: {GH_TOKEN}"
    first = redactor.redact(text)
    assert redactor.stats == {"cached": 0, "scanned": 1, "redactions": 1}
    second = redactor.redact(text)
    assert second == first
    assert redactor.stats == {"cached": 1, "scanned": 1, "redactions": 1}


def test_determinism_across_cache_clear(redactor: Redactor) -> None:
    text = f"token: {GH_TOKEN}"
    first = redactor.redact(text)
    redactor._cache.clear()
    assert redactor.redact(text) == first


def test_chunking_offsets() -> None:
    r = Redactor()
    r._pipe = span_pipe("hunter2")
    filler = ("x" * 99 + "\n") * (CHUNK_CHARS // 100 + 5)  # forces >1 chunk
    text = filler + "the password is hunter2 ok\n"
    out = r.redact(text)
    assert "hunter2" not in out
    assert "REDACTED:secret:" in out
    # Everything before the marker line is untouched (offset math correct).
    assert out.startswith(filler)
