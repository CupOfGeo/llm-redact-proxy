"""Redactor unit tests: two-layer interaction, caching, chunking, guards."""

from __future__ import annotations

from redact_proxy.redactor import CHUNK_CHARS, Redactor, _chunks, _placeholder

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


def test_guard_span_inside_placeholder(redactor: Redactor) -> None:
    inner = GH_PLACEHOLDER[1:-1]  # placeholder content without the brackets
    redactor._pipe = span_pipe(inner)
    out = redactor.redact(f"token: {GH_TOKEN}")
    assert GH_PLACEHOLDER in out


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


def test_reverse_recorded_from_both_layers(redactor: Redactor) -> None:
    redactor._pipe = span_pipe("hunter2")
    original = f"token {GH_TOKEN} pass hunter2"
    out = redactor.redact(original)
    assert redactor.reverse[GH_PLACEHOLDER] == GH_TOKEN
    assert redactor.reverse[_placeholder("secret", "hunter2")] == "hunter2"
    assert redactor.restore(out) == original


def test_restore_multiline_pem_round_trip(redactor: Redactor) -> None:
    pem = "-----BEGIN PRIVATE KEY-----\n" + "A" * 64 + "\n-----END PRIVATE KEY-----"
    original = f"key:\n{pem}\ndone"
    out = redactor.redact(original)
    assert pem not in out
    assert redactor.restore(out) == original


def test_restore_unknown_and_malformed_untouched(redactor: Redactor) -> None:
    unknown = _placeholder("secret", "never-recorded-value")
    assert redactor.restore(unknown) == unknown
    for not_a_placeholder in [
        "⟨REDACTED:secret:ABCDEFABCDEF⟩",  # uppercase hex: outside the grammar
        "⟨REDACTED:secret:abc12⟩",  # hash too short
        "⟨REDACTED:⟩",
    ]:
        assert redactor.restore(not_a_placeholder) == not_a_placeholder


def test_reverse_overflow_clears_both(redactor: Redactor, monkeypatch) -> None:
    import redact_proxy.redactor as rmod

    text = f"token: {GH_TOKEN}"
    first = redactor.redact(text)
    assert redactor._cache and redactor.reverse
    monkeypatch.setattr(rmod, "_REVERSE_MAX", 1)
    redactor.redact("other secret ghp_" + "B" * 36)
    assert GH_PLACEHOLDER not in redactor.reverse  # joint clear happened
    # The cached entry was dropped too, so a rescan repopulates the map:
    assert redactor.redact(text) == first
    assert redactor.restore(first) == text


def test_cache_only_clear_keeps_restore_working(redactor: Redactor) -> None:
    original = f"token: {GH_TOKEN}"
    out = redactor.redact(original)
    redactor._cache.clear()  # the _CACHE_MAX path clears the cache alone
    assert redactor.restore(out) == original


def test_hard_split_long_line_prefers_whitespace() -> None:
    text = ("word " * (CHUNK_CHARS // 5 * 7)).strip()  # one ~7-cap line
    chunks = _chunks(text)
    assert "".join(chunks) == text
    assert len(chunks) >= 7
    assert max(map(len, chunks)) <= CHUNK_CHARS
    assert all(c.endswith(" ") for c in chunks[:-1])  # cut after whitespace


def test_hard_split_without_whitespace_cuts_at_cap() -> None:
    text = "x" * (CHUNK_CHARS * 3 + 10)
    chunks = _chunks(text)
    assert "".join(chunks) == text
    assert [len(c) for c in chunks] == [CHUNK_CHARS] * 3 + [10]


def test_hard_split_offsets_still_correct() -> None:
    r = Redactor()
    r._pipe = span_pipe("hunter2")
    filler = "y" * (CHUNK_CHARS * 2 + 50)  # a single enormous line
    out = r.redact(filler + " the password is hunter2 ok")
    assert "hunter2" not in out
    assert out.startswith(filler)
