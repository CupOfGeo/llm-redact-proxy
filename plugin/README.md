# redact-proxy plugin

PreToolUse hook for [llm-redact-proxy](https://github.com/CupOfGeo/llm-redact-proxy)
hook mode (`unredact = "hook"`): redacted placeholders are restored to real
values only at tool execution — and withheld entirely (ask/deny) when the
same tool input also targets an external host. Requires the brew package;
see the main README's "Un-redaction, and the threat model".
