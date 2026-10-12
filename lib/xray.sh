#!/usr/bin/env bash

capture_xray_service_state() {
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet xray; then
        XRAY_SERVICE_WAS_ACTIVE=1
    fi
}

install_or_update_xray() {
    local latest_version=""
    local installed_version=""

    echo "Checking Xray version..."

    latest_version="$(
        curl -fsSL https://api.github.com/repos/XTLS/Xray-core/releases/latest \
        | jq -r '.tag_name' \
        | sed 's/^v//'
    )"

    if [[ -z "$latest_version" || "$latest_version" == "null" ]]; then
        echo "Error: Could not detect latest Xray version."
        exit 1
    fi

    if [[ -x "$XRAY_PATH" ]]; then
        installed_version="$("$XRAY_PATH" version 2>/dev/null | awk 'NR==1 {print $2}' | sed 's/^v//')"

        if [[ -z "$installed_version" ]]; then
            installed_version="$("$XRAY_PATH" -version 2>/dev/null | awk 'NR==1 {print $2}' | sed 's/^v//')"
        fi
    fi

    if [[ -z "$installed_version" ]]; then
        echo "Xray is not installed. Installing latest version: $latest_version"
        bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    elif [[ "$installed_version" != "$latest_version" ]]; then
        echo "Xray update required."
        echo "Installed: $installed_version"
        echo "Latest:    $latest_version"
        bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    else
        echo "Xray is already up to date: $installed_version"
    fi

    if [[ ! -x "$XRAY_PATH" ]]; then
        echo "Error: Xray binary not found at $XRAY_PATH"
        exit 1
    fi
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
