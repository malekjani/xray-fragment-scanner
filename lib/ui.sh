#!/usr/bin/env bash

choose_scan_mode() {
    local choice=""

    echo
    echo "Choose fragment mode:"
    echo "1) finalmask-fragment"
    echo "2) finalmask-header-custom + fragment"
    echo "3) legacy-fragment"
    read -r -p "Mode default 1: " choice

    case "${choice:-1}" in
        1|finalmask|finalmask-fragment|finalmask_fragment)
            SCAN_MODE="finalmask_fragment"
            ;;
        2|finalmask-header|finalmask-header-fragment|finalmask-header-custom-fragment|finalmask_header_fragment)
            SCAN_MODE="finalmask_header_fragment"
            ;;
        3|legacy|legacy-fragment)
            SCAN_MODE="legacy"
            ;;
        *)
            echo "Error: invalid mode."
            exit 1
            ;;
    esac
}

read_scan_options() {
    read -r -p "Enter the number of instances default 10: " InstancesInput
    read -r -p "Enter timeout for each request in seconds default 10: " TimeoutSecInput
    read -r -p "Enter HTTP listening port default 10809: " HTTPProxyPortInput
    read -r -p "Enter number of requests per instance default 3: " RequestCountInput

    Instances="${InstancesInput:-10}"
    TimeoutSec="${TimeoutSecInput:-10}"
    HTTP_PROXY_PORT="${HTTPProxyPortInput:-10809}"

    if [[ -n "${RequestCountInput}" ]]; then
        RequestCount=$((RequestCountInput + 1))
    else
        RequestCount=4
    fi
}

print_scan_mode() {
    case "$SCAN_MODE" in
        finalmask_fragment|finalmask)
            echo "Scanner mode: finalmask-fragment"
            ;;
        finalmask_header_fragment)
            echo "Scanner mode: finalmask-header-custom + fragment"
            ;;
        legacy)
            echo "Scanner mode: legacy-fragment"
            ;;
    esac
}
