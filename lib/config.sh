#!/usr/bin/env bash

# Config generation and mutation functions.
# The Python block converts a VLESS URI into an Xray config.json.

generate_config_from_vless_link() {
    local vless_link=""

    echo "config.json not found in project root."
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
    # parse_qs has already percent-decoded once; decoding twice corrupts
    # literal %XX sequences embedded in encrypted/authenticated parameters.
    return query.get(name, [default])[0]

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
    "encryption": encryption,
}

if flow:
    proxy_settings["flow"] = flow

stream_settings = {
    "network": network,
    "security": security,
    "sockopt": {
        "tcpKeepAliveIdle": 100,
        "tcpNoDelay": True,
    },
}

if security == "tls":
    tls_settings = {
        "allowInsecure": q_bool("insecure", "allowInsecure"),
        "serverName": sni or host or address,
    }

    if fingerprint:
        tls_settings["fingerprint"] = fingerprint

    if alpn:
        tls_settings["alpn"] = alpn
    if q("ech"):
        tls_settings["echConfigList"] = q("ech")
    if q("cs") or q("cipherSuites"):
        tls_settings["cipherSuites"] = q("cs") or q("cipherSuites")
    if q("pcs"):
        tls_settings["pinnedPeerCertSha256"] = q("pcs")
    if q("vcn"):
        tls_settings["verifyPeerCertByName"] = q("vcn")

    stream_settings["tlsSettings"] = tls_settings

elif security == "reality":
    reality_settings = {
        "serverName": sni or host or address,
    }

    public_key = q("pbk", "") or q("publicKey", "") or q("password", "")
    short_id = q("sid", "")
    spider_x = q("spx", "")

    if fingerprint:
        reality_settings["fingerprint"] = fingerprint

    if public_key:
        # Newer Xray configs use password. Older configs used publicKey.
        reality_settings["password"] = public_key

    if short_id:
        reality_settings["shortId"] = short_id

    if spider_x:
        reality_settings["spiderX"] = spider_x

    stream_settings["realitySettings"] = reality_settings

if network in ("xhttp", "splithttp"):
    stream_settings["network"] = "xhttp"

    xhttp_settings = {
        "path": path,
        "mode": mode_value,
    }

    if host:
        xhttp_settings["host"] = host

    stream_settings["xhttpSettings"] = xhttp_settings

elif network in ("ws", "websocket"):
    stream_settings["network"] = "ws"

    ws_settings = {
        "path": path,
    }

    if host:
        ws_settings["headers"] = {"Host": host}

    stream_settings["wsSettings"] = ws_settings

elif network == "grpc":
    service_name = q("serviceName", "")
    grpc_settings = {}

    if service_name:
        grpc_settings["serviceName"] = service_name

    stream_settings["grpcSettings"] = grpc_settings

elif network == "httpupgrade":
    httpupgrade_settings = {
        "path": path,
    }

    if host:
        httpupgrade_settings["host"] = host

    stream_settings["httpupgradeSettings"] = httpupgrade_settings

# An existing FinalMask must remain in place in legacy freedom.fragment
# mode; fragmentation via dialerProxy must not silently remove it.
if q("fm"):
    raw_mask = q("fm").strip().rstrip(",").strip()
    if raw_mask.startswith('"finalmask"'):
        raw_mask = "{" + raw_mask + "}"
    parsed_mask = json.loads(raw_mask)
    if not isinstance(parsed_mask, dict):
        raise SystemExit("Error: Invalid fm query value")
    value = parsed_mask.get("finalmask", parsed_mask)
    if not isinstance(value, dict):
        raise SystemExit("Error: Invalid FinalMask JSON")
    stream_settings["finalmask"] = value

outbounds = [
    {
        "tag": "proxy",
        "protocol": "vless",
        "settings": proxy_settings,
        "streamSettings": stream_settings,
    },
    {
        "tag": "direct",
        "protocol": "freedom",
        "settings": {},
    },
    {
        "tag": "block",
        "protocol": "blackhole",
        "settings": {"response": {"type": "http"}},
    },
]

if scan_mode in ("finalmask", "finalmask_fragment", "finalmask_header_fragment"):
    finalmask_tcp = []

    if scan_mode == "finalmask_header_fragment":
        finalmask_tcp.append({
            "type": "header-custom",
            "settings": {
                "clients": [[
                    {
                        "delay": 0,
                        "type": "str",
                        "packet": "GET / HTTP/1.1\r\nHost: www.cloudflare.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n",
                    }
                ]],
                "servers": [],
                "errors": [],
            },
        })

    finalmask_tcp.append({
        "type": "fragment",
        "settings": {
            "packets": "1-2",
            "length": "5-10",
            "delay": "5-10",
            "maxSplit": "1-3",
        },
    })

    # Replace only TCP fragments; retain pre-existing header/sudoku, UDP
    # masks and QUIC parameters from the link. Header mode adds one extra
    # header-custom layer only when the link does not already have one.
    original_mask = stream_settings.get("finalmask", {})
    original_tcp = original_mask.get("tcp", [])
    preserved_tcp = [layer for layer in original_tcp if layer.get("type") != "fragment"]
    if scan_mode == "finalmask_header_fragment" and any(
            layer.get("type") == "header-custom" for layer in preserved_tcp):
        finalmask_tcp = [layer for layer in finalmask_tcp if layer.get("type") != "header-custom"]
    original_index = next((i for i, layer in enumerate(original_tcp)
                           if layer.get("type") == "fragment"), len(preserved_tcp))
    insertion = min(original_index, len(preserved_tcp))
    preserved_tcp[insertion:insertion] = finalmask_tcp
    stream_settings["finalmask"] = {**original_mask, "tcp": preserved_tcp}
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
                "interval": "5-10",
            },
        },
        "streamSettings": {
            "sockopt": {
                "tcpNoDelay": True,
                "tcpKeepAliveIdle": 100,
            },
        },
    })

config = {
    "remarks": remark,
    "log": {
        "access": "",
        "error": "",
        "loglevel": "warning",
    },
    "inbounds": [
        {
            "tag": "socks",
            "port": 10808,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "sniffing": {
                "enabled": True,
                "destOverride": ["http", "tls"],
                "routeOnly": False,
            },
            "settings": {
                "auth": "noauth",
                "udp": True,
            },
        },
        {
            "tag": "http",
            "port": 10809,
            "listen": "127.0.0.1",
            "protocol": "http",
            "sniffing": {
                "enabled": True,
                "destOverride": ["http", "tls"],
                "routeOnly": False,
            },
            "settings": {
                "allowTransparent": False,
            },
        },
    ],
    "outbounds": outbounds,
    "routing": {
        "domainStrategy": "AsIs",
        "rules": [
            {
                "type": "field",
                "port": "0-65535",
                "outboundTag": "proxy",
            }
        ],
    },
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

    print_scan_mode
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
