# PII-redacting LLM API proxy. Then: ANTHROPIC_BASE_URL=http://127.0.0.1:8787 claude
proxy:
    uv run python -m redact_proxy.server

# Install the proxy as a login service (launchd: starts at login, auto-restarts).
proxy-install:
    #!/usr/bin/env bash
    set -euo pipefail
    uv sync --quiet
    plist="$HOME/Library/LaunchAgents/com.llm.redact-proxy.plist"
    cat > "$plist" <<PLIST
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
      <key>Label</key><string>com.llm.redact-proxy</string>
      <key>ProgramArguments</key>
      <array>
        <string>{{justfile_directory()}}/.venv/bin/python</string>
        <string>-m</string>
        <string>redact_proxy.server</string>
      </array>
      <key>WorkingDirectory</key><string>{{justfile_directory()}}</string>
      <key>RunAtLoad</key><true/>
      <key>KeepAlive</key><true/>
      <key>StandardOutPath</key><string>$HOME/Library/Logs/redact-proxy.log</string>
      <key>StandardErrorPath</key><string>$HOME/Library/Logs/redact-proxy.log</string>
    </dict>
    </plist>
    PLIST
    launchctl bootout "gui/$(id -u)/com.llm.redact-proxy" 2>/dev/null || true
    launchctl bootstrap "gui/$(id -u)" "$plist"
    echo "Installed. Waiting for model load..."
    for _ in $(seq 1 60); do
        curl -sf --max-time 1 http://127.0.0.1:8787/health >/dev/null && break
        sleep 1
    done
    just proxy-status

proxy-status:
    @curl -sf --max-time 2 http://127.0.0.1:8787/health && echo || echo "⛔ redact-proxy is NOT running (log: ~/Library/Logs/redact-proxy.log)"

proxy-uninstall:
    launchctl bootout "gui/$(id -u)/com.llm.redact-proxy" 2>/dev/null || true
    rm -f "$HOME/Library/LaunchAgents/com.llm.redact-proxy.plist"
    @echo "Uninstalled."

test:
    uv run pytest -q
