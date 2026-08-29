# Roadmap

Feature ideas and testing backlog. Rough priority order within each section.

## Features

### 1. ~~Un-redaction round-trip ("hash and unhash")~~ — shipped
Done: reverse map in `Redactor`, JSON-aware non-streaming restore, and
the SSE rewriter in `redact_proxy/unredact.py` (see README "Un-redaction,
and the threat model"). Original notes kept for the record:

Keep the placeholder → real-value map in proxy memory (never on disk) and
restore real values in responses on the way back, so files the model writes
contain working credentials and tools behave normally while the API only
ever sees placeholders.
- Redactor already computes `sha256(value)[:6]` per placeholder — store the
  reverse map at that point.
- Response side is the hard part: responses stream as SSE and a placeholder
  can be split across chunk boundaries. Needs a small stateful scanner that
  buffers only when a partial `⟨REDACTED:` prefix is seen at a chunk tail.
- Ship behind a flag first (`OPF_PROXY_UNREDACT=1`); "awareness mode"
  (off = you see exactly what the model saw) stays the default until tested.
- Prior art: [claude-code-redact](https://github.com/paroque28/claude-code-redact)
  does this round-trip with an in-memory map.

### 2. Homebrew install
`brew install llm-redact-proxy` (own tap first: `CupOfGeo/homebrew-tap`).
- Formula wraps the Python package; `brew services start llm-redact-proxy`
  replaces `just proxy-install` (brew services manages the launchd plist).
- Blockers to sort out: MLX/openmed dependency weight in a formula
  (likely `virtualenv_install_with_resources`), and where the HF model
  snapshot lands on first run (document `HF_HOME`).
- Wrapper + `claude-raw` need a brew-friendly install story too
  (`brew --prefix`-based source line).

### 3. Beyond Claude / Anthropic
Not needed yet, but the repo name leaves room:
- `OPF_PROXY_UPSTREAM` already exists — document/test OpenAI-compatible
  upstreams (`OPENAI_BASE_URL`) and other CLI agents (Codex CLI, opencode).
- Body schema differs per provider (`messages` vs `input`); generalize the
  JSON walk or add per-upstream profiles.
- Rename env vars from `OPF_PROXY_*` to something provider-neutral when
  this lands (keep old names as aliases).

### 4. Debug logging
The launchd log (`~/Library/Logs/redact-proxy.log`) is one line per request:
size, count, timings, status. The Aug 2026 PEM-regex bug (a lazy match
swallowing 20 `tool_use` blocks, API then rejected the orphaned
`tool_result`) showed as a normal-looking `[14 REDACTED] … -> 400`.
Log what would have caught it, without ever logging a value:
- **Per-redaction metadata**: pattern/category, match *length*, which
  message/block it landed in. A 50 KB `pem` hit is a red flag on its own.
- **Structure check**: message count, block count, and the `tool_use` /
  `tool_use_id` sets before vs after redaction. Log loudly on any
  difference — and make it a runtime invariant in `_redact_body`, not just
  a log line (redaction must never change body shape).
- **Upstream error bodies** on 4xx/5xx (the API's own message, not ours).
- **OPF throughput** (measured 2026-08-29, M-series, cold cache): ~0.7 s per
  6 KB chunk ≈ 5 KB/s, so a 200 KB resumed conversation is ~40 s before
  the first request leaves. The hard chunk cap removed the quadratic
  cliff (32 KB in one call was 22 s); the baseline needs batching chunks
  through one pipeline call and/or a disk-persistent scan cache
  (hash → redacted text, no secrets) so restarts don't rescan history.
- **Per-chunk OPF timing** — a 574 KB body took 22 s; need to see whether
  that's a few huge chunks or a cache-miss storm.
- `OPF_PROXY_LOG_LEVEL` (info default / debug), JSONL records so they're
  greppable, rotation (current file grows forever and captures tqdm bars).
- **Body dumps stay a separate, explicit footgun**: `OPF_PROXY_DEBUG_DUMP=<dir>`
  writes the *redacted* request (what went upstream) and the response.
  Never the pre-redaction body. Off by default; README must say "this is
  your whole conversation history on disk".

### 5. Smaller ideas
- `gitleaks` pre-commit hook in this repo (eat own dog food).
- ~~Config file instead of env vars only~~ — shipped (`~/.config/llm-redact-proxy/config.toml`).
- Optional response-side scanning (model echoing a secret it inferred).
- Stats endpoint (`/stats`): cumulative redaction counts by category.
- Non-Apple-Silicon fallback: regex floor only, model layer off, so Linux
  users get *something* (also unblocks CI).

## Testing needed

- [ ] **Port the TOKEN_PATTERNS test suite.** A validation suite for all ~36
  regexes (positive + zero-false-positive cases) was written during
  development in opf-benchmarks but never landed in-tree. Recreate as
  `tests/test_patterns.py`.
- [ ] **Redactor unit tests**: two-layer interaction, category filtering,
  the no-double-redaction guard (placeholders never re-redacted/mangled),
  cache hit/miss behavior, chunking at CHUNK_CHARS boundaries.
- [ ] **Proxy e2e against a mock upstream**: assert body redacted, headers
  forwarded/skipped correctly, SSE streams pass through unmodified,
  `/health` never proxied.
- [ ] **Placeholder-across-chunk SSE test** (prerequisite for feature #1).
- [ ] **Fail-closed wrapper test**: proxy down → `claude` refuses with the
  error message; `claude-raw` still works.
- [ ] **False-positive corpus**: run the regex floor over a pile of ordinary
  source code / lockfiles and assert zero hits.
- [ ] **Latency benchmark**: redaction ms per request size, cache-warm vs
  cold, to keep the "~5–30 ms" README claim honest.
- [ ] CI: regex-floor tests on Linux (no MLX needed); full suite on a
  macOS runner.
