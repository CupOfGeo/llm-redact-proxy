#!/bin/bash
# Dispatch to the stdlib-only hook module through the fastest available
# interpreter. Order matters: the brew keg's venv python (~40 ms) beats
# the click CLI on PATH (~220 ms). Falls through to a silent no-op so a
# missing install never breaks tool use (the SessionStart warning and
# `redact-proxy doctor` surface that state instead).
for py in /opt/homebrew/opt/llm-redact-proxy/libexec/bin/python \
          /usr/local/opt/llm-redact-proxy/libexec/bin/python; do
  [ -x "$py" ] && exec "$py" -m redact_proxy.hook "$1"
done
if command -v redact-proxy >/dev/null 2>&1; then
  exec redact-proxy hook "$1"
fi
cat > /dev/null
exit 0
