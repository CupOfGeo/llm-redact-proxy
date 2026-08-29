# Roadmap

Feature ideas and testing backlog. Rough priority order within each section.

## Features

### 1. Un-redaction round-trip ("hash and unhash")
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

### 4. Smaller ideas
- `gitleaks` pre-commit hook in this repo (eat own dog food).
- Config file (`~/.config/llm-redact-proxy.toml`) instead of env vars only.
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
