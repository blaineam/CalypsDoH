#!/bin/bash
# Install CalypsDoH as a system daemon (macOS LaunchAgent or Linux systemd user service).
#
# Usage:
#   ./install-daemon.sh              # build (if needed), install + start
#   ./install-daemon.sh uninstall    # stop + remove
#   ./install-daemon.sh status       # check status

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BINARY="$SCRIPT_DIR/calypsdoh"

# ── macOS ────────────────────────────────────────────────────────────────────
LABEL="com.calypsdoh.daemon"
MAC_PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
MAC_LOG_DIR="$HOME/Library/Logs/calypsdoh"

# ── Linux ────────────────────────────────────────────────────────────────────
LINUX_SERVICE="calypsdoh"
LINUX_UNIT="$HOME/.config/systemd/user/$LINUX_SERVICE.service"

build_if_needed() {
    if [ ! -f "$BINARY" ]; then
        echo "Building calypsdoh..."
        cd "$SCRIPT_DIR" && go build -o calypsdoh .
        echo "Built: $BINARY"
    fi
}

install_macos() {
    build_if_needed
    mkdir -p "$MAC_LOG_DIR"
    mkdir -p "$(dirname "$MAC_PLIST")"

    cat > "$MAC_PLIST" << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$LABEL</string>
    <key>ProgramArguments</key>
    <array>
        <string>$BINARY</string>
    </array>
    <key>WorkingDirectory</key>
    <string>$SCRIPT_DIR</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$MAC_LOG_DIR/calypsdoh.log</string>
    <key>StandardErrorPath</key>
    <string>$MAC_LOG_DIR/calypsdoh-error.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin</string>
    </dict>
</dict>
</plist>
PLIST

    launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
    launchctl bootstrap "gui/$(id -u)" "$MAC_PLIST"

    echo ""
    echo "CalypsDoH daemon installed and running!"
    echo ""
    echo "  Status:  ./install-daemon.sh status"
    echo "  Logs:    tail -f $MAC_LOG_DIR/calypsdoh.log"
    echo "  Stop:    ./install-daemon.sh uninstall"
}

uninstall_macos() {
    echo "Stopping CalypsDoH daemon..."
    launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
    rm -f "$MAC_PLIST"
    echo "Uninstalled."
}

status_macos() {
    launchctl print "gui/$(id -u)/$LABEL" 2>/dev/null || echo "Not running"
}

install_linux() {
    build_if_needed
    mkdir -p "$(dirname "$LINUX_UNIT")"

    cat > "$LINUX_UNIT" << UNIT
[Unit]
Description=CalypsDoH DNS-over-HTTPS Proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BINARY
WorkingDirectory=$SCRIPT_DIR
Restart=on-failure
RestartSec=10

[Install]
WantedBy=default.target
UNIT

    systemctl --user daemon-reload
    systemctl --user enable "$LINUX_SERVICE"
    systemctl --user start "$LINUX_SERVICE"

    echo ""
    echo "CalypsDoH daemon installed and running!"
    echo ""
    echo "  Status:  systemctl --user status $LINUX_SERVICE"
    echo "  Logs:    journalctl --user -u $LINUX_SERVICE -f"
    echo "  Stop:    ./install-daemon.sh uninstall"
}

uninstall_linux() {
    echo "Stopping CalypsDoH daemon..."
    systemctl --user stop "$LINUX_SERVICE" 2>/dev/null || true
    systemctl --user disable "$LINUX_SERVICE" 2>/dev/null || true
    rm -f "$LINUX_UNIT"
    systemctl --user daemon-reload
    echo "Uninstalled."
}

status_linux() {
    systemctl --user status "$LINUX_SERVICE" 2>/dev/null || echo "Not running"
}

case "$(uname -s)" in
    Darwin)
        case "${1:-install}" in
            uninstall) uninstall_macos ;;
            status)    status_macos ;;
            *)         install_macos ;;
        esac
        ;;
    Linux)
        case "${1:-install}" in
            uninstall) uninstall_linux ;;
            status)    status_linux ;;
            *)         install_linux ;;
        esac
        ;;
    *)
        echo "Unsupported OS: $(uname -s)"
        exit 1
        ;;
esac
