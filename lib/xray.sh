#!/usr/bin/env bash

capture_xray_service_state() {
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet xray; then
        XRAY_SERVICE_WAS_ACTIVE=1
    fi
}

install_or_update_xray() {
    # Historical explicit mode only; NEVER run a remote install script or replace
    # /usr/local/bin/xray. Use the same user-local verified prerelease as modern modes.
    local resolved
    resolved="$(python3 "$PROJECT_ROOT/lib/core_manager.py" --ensure)" || return 1
    XRAY_PATH="$resolved"
    echo "Historical mode uses verified pre-release: $XRAY_PATH"
}

stop_xray_process() {
    if [[ -n "${XRAY_PID:-}" ]] && kill -0 "$XRAY_PID" 2>/dev/null; then
        kill "$XRAY_PID" 2>/dev/null
        wait "$XRAY_PID" 2>/dev/null || true
    fi

    XRAY_PID=""
}

stop_xray_service_if_running() {
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet xray; then
        echo "Stopping active xray service temporarily..."
        systemctl stop xray
    fi
}

restore_xray_service() {
    if [[ "$XRAY_SERVICE_WAS_ACTIVE" -eq 1 ]]; then
        echo "Restoring xray service..."
        systemctl start xray 2>/dev/null || true
    fi
}

start_xray_for_test() {
    stop_xray_process

    "$XRAY_PATH" run -c "$CONFIG_PATH" > "$XRAY_LOG_FILE" 2> "$XRAY_ERROR_LOG_FILE" &
    XRAY_PID=$!

    sleep 3

    if ! kill -0 "$XRAY_PID" 2>/dev/null; then
        echo
        echo "Error: Xray failed to start."
        echo "Check error log:"
        echo "$XRAY_ERROR_LOG_FILE"
        exit 1
    fi
}
