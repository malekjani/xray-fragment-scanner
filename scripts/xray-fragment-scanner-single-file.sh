#!/usr/bin/env bash

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

XRAY_PATH="/usr/local/bin/xray"
CONFIG_PATH="$SCRIPT_DIR/config.json"

LOG_FILE="$SCRIPT_DIR/pings.txt"
XRAY_LOG_FILE="$SCRIPT_DIR/xraylogs.txt"
XRAY_ERROR_LOG_FILE="$SCRIPT_DIR/xraylogs.error.txt"
CONFIG_BACKUP="$SCRIPT_DIR/config.json.backup-before-fragment-scanner"

HTTP_PROXY_SERVER="127.0.0.1"
XRAY_PID=""
XRAY_SERVICE_WAS_ACTIVE=0
SCAN_MODE=""

if [[ "$EUID" -ne 0 ]]; then
    echo "Error: Please run this script with sudo:"
    echo "sudo $0"
    exit 1
fi

for cmd in curl jq awk sort head cut sed grep python3; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Error: '$cmd' is not installed."
        echo "Install dependencies with:"
        echo "sudo apt update && sudo apt install -y curl jq python3"
        exit 1
    fi
done

is_finalmask_mode() {
    [[ "$SCAN_MODE" == "finalmask_fragment" || "$SCAN_MODE" == "finalmask_header_fragment" || "$SCAN_MODE" == "finalmask" ]]
}

is_finalmask_header_fragment_mode() {
    [[ "$SCAN_MODE" == "finalmask_header_fragment" ]]
}

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

generate_config_from_vless_link() {
    local vless_link=""

    echo "config.json not found in script directory."
    read -r -p "Enter VLESS link: " vless_link

    if [[ -z "$vless_link" ]]; then
        echo "Error: VLESS link is empty."
        exit 1
    fi

    choose_scan_mode

    python3 - "$vless_link" "$CONFIG_PATH" "$SCAN_MODE" <<'PY'
import json
import sys
from urllib.parse import urlsplit, parse_qs, unquote

link = sys.argv[1].strip()
output_path = sys.argv[2]
scan_mode = sys.argv[3]

parsed = urlsplit(link)

if parsed.scheme.lower() != "vless":
    raise SystemExit("Error: Only vless:// links are supported.")

query = parse_qs(parsed.query, keep_blank_values=True)

def q(name, default=""):
    value = query.get(name, [default])[0]
    return unquote(value) if isinstance(value, str) else value

def q_bool(*names):
    for name in names:
        value = q(name, "").strip().lower()
        if value in ("1", "true", "yes"):
            return True
    return False

uuid = unquote(parsed.username or "")
address = parsed.hostname
port = parsed.port or 443

if not uuid:
    raise SystemExit("Error: UUID not found in VLESS link.")

if not address:
    raise SystemExit("Error: Server address not found in VLESS link.")

remark = unquote(parsed.fragment or "VLESS-Xray")
network = q("type", "tcp") or "tcp"
security = q("security", "none") or "none"
encryption = q("encryption", "none") or "none"

sni = q("sni", "")
host = q("host", "")
path = q("path", "/") or "/"
mode_value = q("mode", "auto") or "auto"
fingerprint = q("fp", "")
flow = q("flow", "")

alpn_raw = q("alpn", "")
alpn = [item.strip() for item in alpn_raw.split(",") if item.strip()]

proxy_settings = {
    "address": address,
    "port": port,
    "id": uuid,
    "encryption": encryption
}

if flow:
    proxy_settings["flow"] = flow

stream_settings = {
    "network": network,
    "security": security,
    "sockopt": {
        "tcpKeepAliveIdle": 100,
        "tcpNoDelay": True
    }
}

if security == "tls":
    tls_settings = {
        "allowInsecure": q_bool("insecure", "allowInsecure"),
        "serverName": sni or host or address
    }

    if fingerprint:
        tls_settings["fingerprint"] = fingerprint

    if alpn:
        tls_settings["alpn"] = alpn

    stream_settings["tlsSettings"] = tls_settings

elif security == "reality":
    reality_settings = {
        "serverName": sni or host or address
    }

    public_key = q("pbk", "")
    short_id = q("sid", "")
    spider_x = q("spx", "")

    if fingerprint:
        reality_settings["fingerprint"] = fingerprint

    if public_key:
        reality_settings["publicKey"] = public_key

    if short_id:
        reality_settings["shortId"] = short_id

    if spider_x:
        reality_settings["spiderX"] = spider_x

    stream_settings["realitySettings"] = reality_settings

if network in ("xhttp", "splithttp"):
    stream_settings["network"] = "xhttp"

    xhttp_settings = {
        "path": path,
        "mode": mode_value
    }

    if host:
        xhttp_settings["host"] = host

    stream_settings["xhttpSettings"] = xhttp_settings

elif network in ("ws", "websocket"):
    stream_settings["network"] = "ws"

    ws_settings = {
        "path": path
    }

    if host:
        ws_settings["headers"] = {
            "Host": host
        }

    stream_settings["wsSettings"] = ws_settings

elif network == "grpc":
    service_name = q("serviceName", "")
    grpc_settings = {}

    if service_name:
        grpc_settings["serviceName"] = service_name

    stream_settings["grpcSettings"] = grpc_settings

elif network == "httpupgrade":
    httpupgrade_settings = {
        "path": path
    }

    if host:
        httpupgrade_settings["host"] = host

    stream_settings["httpupgradeSettings"] = httpupgrade_settings

outbounds = [
    {
        "tag": "proxy",
        "protocol": "vless",
        "settings": proxy_settings,
        "streamSettings": stream_settings
    },
    {
        "tag": "direct",
        "protocol": "freedom",
        "settings": {}
    },
    {
        "tag": "block",
        "protocol": "blackhole",
        "settings": {
            "response": {
                "type": "http"
            }
        }
    }
]

if scan_mode in ("finalmask", "finalmask_fragment", "finalmask_header_fragment"):
    finalmask_tcp = []

    if scan_mode == "finalmask_header_fragment":
        finalmask_tcp.append({
            "type": "header-custom",
            "settings": {
                "clients": [
                    [
                        {
                            "delay": 0,
                            "type": "str",
                            "packet": "GET / HTTP/1.1\r\nHost: www.cloudflare.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n"
                        }
                    ]
                ],
                "servers": [],
                "errors": []
            }
        })

    finalmask_tcp.append({
        "type": "fragment",
        "settings": {
            "packets": "1-2",
            "length": "5-10",
            "delay": "5-10",
            "maxSplit": "1-3"
        }
    })

    stream_settings["finalmask"] = {
        "tcp": finalmask_tcp
    }
else:
    stream_settings["sockopt"]["dialerProxy"] = "fragment"

    outbounds.insert(1, {
        "tag": "fragment",
        "protocol": "freedom",
        "settings": {
            "domainStrategy": "AsIs",
            "fragment": {
                "packets": "1-2",
                "length": "5-10",
                "interval": "5-10"
            }
        },
        "streamSettings": {
            "sockopt": {
                "tcpNoDelay": True,
                "tcpKeepAliveIdle": 100
            }
        }
    })

config = {
    "remarks": remark,
    "log": {
        "access": "",
        "error": "",
        "loglevel": "warning"
    },
    "inbounds": [
        {
            "tag": "socks",
            "port": 10808,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "sniffing": {
                "enabled": True,
                "destOverride": [
                    "http",
                    "tls"
                ],
                "routeOnly": False
            },
            "settings": {
                "auth": "noauth",
                "udp": True
            }
        },
        {
            "tag": "http",
            "port": 10809,
            "listen": "127.0.0.1",
            "protocol": "http",
            "sniffing": {
                "enabled": True,
                "destOverride": [
                    "http",
                    "tls"
                ],
                "routeOnly": False
            },
            "settings": {
                "allowTransparent": False
            }
        }
    ],
    "outbounds": outbounds,
    "routing": {
        "domainStrategy": "AsIs",
        "rules": [
            {
                "type": "field",
                "port": "0-65535",
                "outboundTag": "proxy"
            }
        ]
    }
}

with open(output_path, "w", encoding="utf-8") as f:
    json.dump(config, f, indent=2, ensure_ascii=False)

print(f"Generated config: {output_path}")
PY
}

inject_fragment_mode() {
    local tmp_file=""

    tmp_file="$(mktemp)"

    if [[ "$SCAN_MODE" == "finalmask_header_fragment" ]]; then
        jq '
        (.outbounds[] | select(.tag == "proxy") | .streamSettings.finalmask.tcp) = [
          {
            "type": "header-custom",
            "settings": {
              "clients": [
                [
                  {
                    "delay": 0,
                    "type": "str",
                    "packet": "GET / HTTP/1.1\r\nHost: www.cloudflare.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n"
                  }
                ]
              ],
              "servers": [],
              "errors": []
            }
          },
          {
            "type": "fragment",
            "settings": {
              "packets": "1-2",
              "length": "5-10",
              "delay": "5-10",
              "maxSplit": "1-3"
            }
          }
        ]
        ' "$CONFIG_PATH" > "$tmp_file"
    elif is_finalmask_mode; then
        jq '
        (.outbounds[] | select(.tag == "proxy") | .streamSettings.finalmask.tcp) = [
          {
            "type": "fragment",
            "settings": {
              "packets": "1-2",
              "length": "5-10",
              "delay": "5-10",
              "maxSplit": "1-3"
            }
          }
        ]
        ' "$CONFIG_PATH" > "$tmp_file"
    else
        jq '
        (.outbounds[] | select(.tag == "proxy") | .streamSettings.sockopt.dialerProxy) = "fragment" |
        .outbounds += [
          {
            "tag": "fragment",
            "protocol": "freedom",
            "settings": {
              "domainStrategy": "AsIs",
              "fragment": {
                "packets": "1-2",
                "length": "5-10",
                "interval": "5-10"
              }
            },
            "streamSettings": {
              "sockopt": {
                "tcpNoDelay": true,
                "tcpKeepAliveIdle": 100
              }
            }
          }
        ]
        ' "$CONFIG_PATH" > "$tmp_file"
    fi

    mv "$tmp_file" "$CONFIG_PATH"
}

detect_scan_mode() {
    local has_finalmask=0
    local has_finalmask_header=0
    local has_legacy=0

    if jq -e '.outbounds[]? | .streamSettings.finalmask.tcp[]? | select(.type == "fragment")' "$CONFIG_PATH" >/dev/null; then
        has_finalmask=1
    fi

    if jq -e '.outbounds[]? | .streamSettings.finalmask.tcp[]? | select(.type == "header-custom")' "$CONFIG_PATH" >/dev/null; then
        has_finalmask_header=1
    fi

    if jq -e '.outbounds[]? | select(.tag == "fragment") | .settings.fragment' "$CONFIG_PATH" >/dev/null; then
        has_legacy=1
    fi

    if [[ "$has_finalmask" -eq 1 && "$has_legacy" -eq 1 ]]; then
        echo "Both finalmask and legacy fragment were found."
        choose_scan_mode

        if [[ "$SCAN_MODE" == "finalmask_header_fragment" && "$has_finalmask_header" -eq 0 ]]; then
            inject_fragment_mode
        fi
    elif [[ "$has_finalmask" -eq 1 && "$has_finalmask_header" -eq 1 ]]; then
        SCAN_MODE="finalmask_header_fragment"
    elif [[ "$has_finalmask" -eq 1 ]]; then
        local add_header=""
        read -r -p "Finalmask fragment found. Use header-custom + fragment? y/N: " add_header

        if [[ "${add_header:-N}" =~ ^[Yy]$ ]]; then
            SCAN_MODE="finalmask_header_fragment"
            inject_fragment_mode
        else
            SCAN_MODE="finalmask_fragment"
        fi
    elif [[ "$has_legacy" -eq 1 ]]; then
        SCAN_MODE="legacy"
    else
        echo "No fragment mode found in config.json."
        choose_scan_mode
        inject_fragment_mode
    fi

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

check_config() {
    if [[ ! -f "$CONFIG_PATH" ]]; then
        generate_config_from_vless_link
    fi

    if ! jq empty "$CONFIG_PATH" >/dev/null 2>&1; then
        echo "Error: config.json is not valid JSON."
        exit 1
    fi

    detect_scan_mode

    if [[ ! -f "$CONFIG_BACKUP" ]]; then
        cp "$CONFIG_PATH" "$CONFIG_BACKUP"
        echo "Config backup created:"
        echo "$CONFIG_BACKUP"
    fi
}

prepare_logs() {
    : > "$LOG_FILE"
    : > "$XRAY_LOG_FILE"
    : > "$XRAY_ERROR_LOG_FILE"
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

modify_config_legacy() {
    local packets="$1"
    local length="$2"
    local interval="$3"
    local tmp_file=""

    tmp_file="$(mktemp)"

    jq \
        --arg packets "$packets" \
        --arg length "$length" \
        --arg interval "$interval" \
        '
        (.outbounds[] | select(.tag == "fragment") | .settings.fragment.packets) = $packets |
        (.outbounds[] | select(.tag == "fragment") | .settings.fragment.length) = $length |
        (.outbounds[] | select(.tag == "fragment") | .settings.fragment.interval) = $interval
        ' "$CONFIG_PATH" > "$tmp_file"

    mv "$tmp_file" "$CONFIG_PATH"
}

modify_config_finalmask() {
    local packets="$1"
    local length="$2"
    local delay="$3"
    local max_split="$4"
    local tmp_file=""

    tmp_file="$(mktemp)"

    jq \
        --arg packets "$packets" \
        --arg length "$length" \
        --arg delay "$delay" \
        --arg maxSplit "$max_split" \
        '
        (.outbounds[] | .streamSettings.finalmask.tcp[]? | select(.type == "fragment") | .settings.packets) = $packets |
        (.outbounds[] | .streamSettings.finalmask.tcp[]? | select(.type == "fragment") | .settings.length) = $length |
        (.outbounds[] | .streamSettings.finalmask.tcp[]? | select(.type == "fragment") | .settings.delay) = $delay |
        (.outbounds[] | .streamSettings.finalmask.tcp[]? | select(.type == "fragment") | .settings.maxSplit) = $maxSplit
        ' "$CONFIG_PATH" > "$tmp_file"

    mv "$tmp_file" "$CONFIG_PATH"
}

get_random_value() {
    local -n arr="$1"
    echo "${arr[$(( RANDOM % ${#arr[@]} ))]}"
}

get_unique_combination_legacy() {
    local packets=""
    local length=""
    local interval=""
    local combination=""

    while true; do
        packets="$(get_random_value packetsOptions)"
        length="$(get_random_value lengthOptions)"
        interval="$(get_random_value legacyIntervalOptions)"

        combination="${packets},${length},${interval}"

        if [[ -z "${USED_COMBINATIONS[$combination]+x}" ]]; then
            USED_COMBINATIONS["$combination"]=1
            echo "$packets|$length|$interval"
            return
        fi
    done
}

get_unique_combination_finalmask() {
    local packets=""
    local length=""
    local delay=""
    local max_split=""
    local combination=""

    while true; do
        packets="$(get_random_value packetsOptions)"
        length="$(get_random_value lengthOptions)"
        delay="$(get_random_value finalmaskDelayOptions)"
        max_split="$(get_random_value maxSplitOptions)"

        combination="${packets},${length},${delay},${max_split}"

        if [[ -z "${USED_COMBINATIONS[$combination]+x}" ]]; then
            USED_COMBINATIONS["$combination"]=1
            echo "$packets|$length|$delay|$max_split"
            return
        fi
    done
}

send_http_request() {
    local request_count="$1"
    local timeout_sec="$2"
    local timeout_ms=$(( timeout_sec * 1000 ))
    local url="http://cp.cloudflare.com"
    local times=()
    local elapsed=""
    local rc=0
    local ms=""
    local total="0"
    local valid=0
    local failed=0
    local avg="0"

    for ((i = 1; i <= request_count; i++)); do
        elapsed="$(
            curl \
                --silent \
                --output /dev/null \
                --write-out "%{time_total}" \
                --max-time "$timeout_sec" \
                --proxy "http://${HTTP_PROXY_SERVER}:${HTTP_PROXY_PORT}" \
                "$url" 2>/dev/null
        )"

        rc=$?

        if [[ $rc -eq 0 && "$elapsed" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
            ms="$(awk -v t="$elapsed" 'BEGIN { printf "%.2f", t * 1000 }')"
            times+=("$ms")
        else
            times+=("-1")
        fi

        sleep 1
    done

    times=("${times[@]:1}")

    echo "Individual Request Times:" >> "$LOG_FILE"
    IFS=','; echo "${times[*]}" >> "$LOG_FILE"; unset IFS

    for t in "${times[@]}"; do
        if [[ "$t" == "-1" ]]; then
            ((failed++))
        else
            total="$(awk -v a="$total" -v b="$t" 'BEGIN { print a + b }')"
            ((valid++))
        fi
    done

    if (( valid > 0 )); then
        avg="$(awk -v total="$total" -v failed="$failed" -v timeout="$timeout_ms" -v n="${#times[@]}" \
            'BEGIN { printf "%.2f", (total + failed * timeout) / n }')"
    else
        avg="0"
    fi

    echo "$avg"
}

trap 'stop_xray_process; restore_xray_service' EXIT

capture_xray_service_state
install_or_update_xray
stop_xray_service_if_running
check_config
prepare_logs

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

packetsOptions=("tlshello" "1-1" "1-2" "1-3" "1-5")

lengthOptions=(
    "1-1" "1-2" "1-3" "2-5" "1-5" "1-10"
    "3-5" "5-10" "10-15" "10-20" "20-50" "50-100"
)

legacyIntervalOptions=(
    "1-1" "1-2" "3-5" "1-5" "5-10" "10-15"
    "10-20" "20-30" "20-50" "50-100" "100-150" "150-200"
)

finalmaskDelayOptions=(
    "1-1" "1-2" "3-5" "1-5" "5-10" "10-15"
    "10-20" "20-30" "20-50" "50-100" "100-150" "150-200"
)

maxSplitOptions=("1-1" "1-2" "1-3" "2-4" "3-5" "3-7")

if is_finalmask_mode; then
    maxPossibleInstances=$(( ${#packetsOptions[@]} * ${#lengthOptions[@]} * ${#finalmaskDelayOptions[@]} * ${#maxSplitOptions[@]} ))
else
    maxPossibleInstances=$(( ${#packetsOptions[@]} * ${#lengthOptions[@]} * ${#legacyIntervalOptions[@]} ))
fi

while (( Instances > maxPossibleInstances )); do
    echo "Error: Number of instances cannot be greater than $maxPossibleInstances"
    read -r -p "Enter the number of instances default 10: " InstancesInput
    Instances="${InstancesInput:-10}"
done

declare -A USED_COMBINATIONS
declare -a RESULTS

if is_finalmask_mode; then
    printf '+--------------+-----------------+---------------+-----------------+---------------+---------------+\n'
    printf '|   Instance   |     Packets     |    Length     |      Delay      |   Max Split   | Average Ping  |\n'
    printf '+--------------+-----------------+---------------+-----------------+---------------+---------------+\n'
else
    printf '+--------------+-----------------+---------------+-----------------+---------------+\n'
    printf '|   Instance   |     Packets     |    Length     |    Interval     | Average Ping  |\n'
    printf '+--------------+-----------------+---------------+-----------------+---------------+\n'
fi

for ((i = 0; i < Instances; i++)); do
    if is_finalmask_mode; then
        combination="$(get_unique_combination_finalmask)"

        packets="$(echo "$combination" | cut -d'|' -f1)"
        length="$(echo "$combination" | cut -d'|' -f2)"
        delay="$(echo "$combination" | cut -d'|' -f3)"
        max_split="$(echo "$combination" | cut -d'|' -f4)"

        modify_config_finalmask "$packets" "$length" "$delay" "$max_split"
    else
        combination="$(get_unique_combination_legacy)"

        packets="$(echo "$combination" | cut -d'|' -f1)"
        length="$(echo "$combination" | cut -d'|' -f2)"
        delay="$(echo "$combination" | cut -d'|' -f3)"
        max_split="-"

        modify_config_legacy "$packets" "$length" "$delay"
    fi

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

    if is_finalmask_mode; then
        echo "Testing packets=$packets, length=$length, delay=$delay, maxSplit=$max_split..." >> "$LOG_FILE"
    else
        echo "Testing packets=$packets, length=$length, interval=$delay..." >> "$LOG_FILE"
    fi

    averagePing="$(send_http_request "$RequestCount" "$TimeoutSec")"

    echo "Average Response Time: $averagePing ms" >> "$LOG_FILE"
    echo >> "$LOG_FILE"

    RESULTS+=("${averagePing}|$((i + 1))|${packets}|${length}|${delay}|${max_split}")

    if [[ "$averagePing" == "0" ]]; then
        displayPing="FAILED"
    else
        displayPing="$averagePing"
    fi

    if is_finalmask_mode; then
        printf '|    %-9s | %-15s | %-13s | %-15s | %-13s | %-13s |\n' \
            "$((i + 1))" "$packets" "$length" "$delay" "$max_split" "$displayPing"
    else
        printf '|    %-9s | %-15s | %-13s | %-15s | %-13s |\n' \
            "$((i + 1))" "$packets" "$length" "$delay" "$displayPing"
    fi

    sleep 1
done

if is_finalmask_mode; then
    printf '+--------------+-----------------+---------------+-----------------+---------------+---------------+\n'
else
    printf '+--------------+-----------------+---------------+-----------------+---------------+\n'
fi

echo
echo "Top three lowest average response times:"
echo

if is_finalmask_mode; then
    printf '%-10s %-12s %-12s %-12s %-12s %-24s\n' \
        "Instance" "Packets" "Length" "Delay" "MaxSplit" "AverageResponseTime(ms)"
else
    printf '%-10s %-12s %-12s %-12s %-24s\n' \
        "Instance" "Packets" "Length" "Interval" "AverageResponseTime(ms)"
fi

printf '%s\n' "${RESULTS[@]}" \
    | awk -F'|' '$1 > 0 { print }' \
    | sort -t'|' -k1,1n \
    | head -n 3 \
    | while IFS='|' read -r avg instance packets length delay max_split; do
        if is_finalmask_mode; then
            printf '%-10s %-12s %-12s %-12s %-12s %-24s\n' \
                "$instance" "$packets" "$length" "$delay" "$max_split" "$avg"
        else
            printf '%-10s %-12s %-12s %-12s %-24s\n' \
                "$instance" "$packets" "$length" "$delay" "$avg"
        fi
      done

stop_xray_process

echo
echo "Files:"
echo "Config:        $CONFIG_PATH"
echo "Config backup: $CONFIG_BACKUP"
echo "Ping log:      $LOG_FILE"
echo "Xray log:      $XRAY_LOG_FILE"
echo "Xray errors:   $XRAY_ERROR_LOG_FILE"

read -r -p "Press Enter to exit..."