# Fail-closed Claude Code wrapper for redact_proxy.
# Source this from your zshrc (e.g. in dotfiles):
#   source ~/Code/llm-redact-proxy/claude-wrapper.zsh
#
# Plain `claude` then always routes through the PII-redacting proxy, and
# refuses to run (with a clear reason) when the proxy is down.
# Deliberate bypass: `command claude` or `claude-raw`.

claude() {
  if ! curl -sf --max-time 1 http://127.0.0.1:8787/health >/dev/null 2>&1; then
    echo "⛔ redact-proxy is not running — requests would go to Anthropic UNREDACTED." >&2
    echo "   start it:   launchctl kickstart gui/$(id -u)/com.llm.redact-proxy" >&2
    echo "   status:     just -f ~/Code/llm-redact-proxy/justfile proxy-status" >&2
    echo "   bypass:     claude-raw   (deliberate, unprotected)" >&2
    return 1
  fi
  ANTHROPIC_BASE_URL=http://127.0.0.1:8787 command claude "$@"
}

claude-raw() {
  command claude "$@"
}
