#!/usr/bin/env bash

# Shared runtime variables for Xray Finalmask Scanner.
# This file is sourced by bin/xray-finalmask-scanner.

XRAY_PATH="${XRAY_PATH:-/usr/local/bin/xray}"
CONFIG_PATH="${CONFIG_PATH:-$PROJECT_ROOT/config.json}"
CONFIG_BACKUP="${CONFIG_BACKUP:-$PROJECT_ROOT/config.json.backup-before-fragment-scanner}"

LOG_DIR="${LOG_DIR:-$PROJECT_ROOT/logs}"
LOG_FILE="${LOG_FILE:-$LOG_DIR/pings.txt}"
XRAY_LOG_FILE="${XRAY_LOG_FILE:-$LOG_DIR/xraylogs.txt}"
XRAY_ERROR_LOG_FILE="${XRAY_ERROR_LOG_FILE:-$LOG_DIR/xraylogs.error.txt}"

HTTP_PROXY_SERVER="${HTTP_PROXY_SERVER:-127.0.0.1}"
HTTP_PROXY_PORT="${HTTP_PROXY_PORT:-10809}"

XRAY_PID=""
XRAY_SERVICE_WAS_ACTIVE=0
SCAN_MODE=""

is_finalmask_mode() {
    [[ "$SCAN_MODE" == "finalmask_fragment" || "$SCAN_MODE" == "finalmask_header_fragment" || "$SCAN_MODE" == "finalmask" ]]
}

is_finalmask_header_fragment_mode() {
    [[ "$SCAN_MODE" == "finalmask_header_fragment" ]]
}
