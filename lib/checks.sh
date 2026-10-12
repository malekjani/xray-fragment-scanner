#!/usr/bin/env bash

require_root() {
    if [[ "$EUID" -ne 0 ]]; then
        echo "Error: Please run this script with sudo:"
        echo "sudo $0"
        exit 1
    fi
}

check_dependencies() {
    local missing=0
    local cmd=""

    for cmd in curl jq awk sort head cut sed grep python3; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo "Error: '$cmd' is not installed."
            missing=1
        fi
    done

    if [[ "$missing" -eq 1 ]]; then
        echo
        echo "Install dependencies with:"
        echo "sudo apt update && sudo apt install -y curl jq python3"
        exit 1
    fi
}

prepare_logs() {
    mkdir -p "$LOG_DIR"
    : > "$LOG_FILE"
    : > "$XRAY_LOG_FILE"
    : > "$XRAY_ERROR_LOG_FILE"
}
