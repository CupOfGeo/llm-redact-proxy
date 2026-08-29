# PII-redacting LLM API proxy. Everyday driver is the CLI: `redact-proxy --help`
# (inside this checkout: `uv run redact-proxy ...`).

proxy:
    uv run redact-proxy run

status:
    uv run redact-proxy status

doctor:
    uv run redact-proxy doctor

test:
    uv run pytest -q

# Login service via launchd (auto-restarts); interim until `brew services` takes over.
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
        <string>{{justfile_directory()}}/.venv/bin/redact-proxy</string>
        <string>run</string>
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
    echo "Installed. Waiting for the model to load..."
    for _ in $(seq 1 90); do
        uv run redact-proxy status >/dev/null 2>&1 && break
        sleep 1
    done
    uv run redact-proxy status

proxy-uninstall:
    launchctl bootout "gui/$(id -u)/com.llm.redact-proxy" 2>/dev/null || true
    rm -f "$HOME/Library/LaunchAgents/com.llm.redact-proxy.plist"
    @echo "Uninstalled."
