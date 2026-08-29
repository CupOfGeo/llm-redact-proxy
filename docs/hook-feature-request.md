# Feature request (for Anthropic): result-rewriting hooks for DLP/redaction

## Summary

Add a hook that can **rewrite tool-result content (and injected context)
before it enters the model's context** — the inbound analogue of
`PreToolUse`'s `updatedInput`. Today `PostToolUse` can only *append*
context (`additionalContext`), not replace the result.

## Why

We maintain [llm-redact-proxy], a local PII/secret redactor for Claude
Code. It scrubs secrets to placeholders before requests reach the API. It
has to run as a **network proxy** (an intercepting daemon on
`ANTHROPIC_BASE_URL`) for one reason only: no hook can transform content on
the way *into* the model's context. Everything else already lives in a
plugin.

We proved the outbound-adjacent half works as a plugin: a `PreToolUse` hook
uses `updatedInput` to restore redacted values into tool calls at execution
time, under a policy (llm-redact-proxy v0.4.0). The missing half is the
inbound direction — redacting a tool result (a file read, command output)
*before the model sees it*.

## What we'd build with it

Drop the network proxy entirely. A single plugin would:
- On tool results / file reads: scan for secrets, replace with
  deterministic placeholders before they enter context.
- On tool execution (`PreToolUse`, already possible): restore real values
  into the tool input.

Result: per-session redaction, no daemon, no `ANTHROPIC_BASE_URL`
redirection, no TLS interception, no model download at service start.
Simpler for users and far less invasive than a MITM proxy.

## Concrete ask

A hook output field (e.g. `PostToolUse` / a new `ToolResult` event) that
**replaces** the result content the model receives — mirroring the existing
`updatedInput` contract on `PreToolUse`. Ideally the same for large
injected context (file reads surfaced to the model).

## Why it's safe / bounded

- Opt-in per user via settings, same trust model as existing command hooks.
- The transform is the user's own code, already trusted to run as a hook.
- No new data leaves the machine; this *keeps* data local that otherwise
  transits a redirected endpoint.

## Proof of concept

llm-redact-proxy v0.4.0 — `PreToolUse` + `updatedInput` restoration and the
`/restore` mechanism are shipped and tested. The proxy is the only piece
that exists solely because the inbound transform is missing.

[llm-redact-proxy]: https://github.com/CupOfGeo/llm-redact-proxy
