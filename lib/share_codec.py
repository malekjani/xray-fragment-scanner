#!/usr/bin/env python3
"""Loss-averse VLESS, VMess AEAD/legacy QR, and Trojan share URI decoding.

Legacy VMess QR URLs are deliberately exported as VMess AEAD URLs when
modified: base64(JSON) has no interoperable FinalMask field. Input baseline
remains original, and unsupported fields fail closed before any scans.
"""
from __future__ import annotations

import base64
import json
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit, urlunsplit

from network_scan import vless_to_config

URL_KEYS = {"encryption", "security", "sni", "fp", "alpn", "ech", "fm",
            "type", "host", "path", "flow", "mode", "serviceName",
            "allowInsecure", "insecure", "cs", "cipherSuites", "pcs",
            "vcn", "pbk", "password", "sid", "spx"}
VMESS_QR_KEYS = {"v", "ps", "add", "port", "id", "aid", "scy", "net",
                 "type", "host", "path", "tls", "sni", "alpn", "fp",
                 "insecure", "ech", "fm", "pcs", "vcn", "cs"}


def is_legacy_vmess(link: str) -> bool:
    link = link.strip()
    return link.lower().startswith("vmess://") and "@" not in link.split("#", 1)[0]


def _query_validate(link: str) -> None:
    pairs = parse_qsl(urlsplit(link).query, keep_blank_values=True)
    keys = [k for k, _ in pairs]
    unknown = sorted(set(keys) - URL_KEYS)
    repeated = sorted(k for k in set(keys) if keys.count(k) > 1)
    if unknown or repeated:
        raise ValueError(f"unmapped fields/repeated link parameters: {','.join(unknown + repeated)}")


def legacy_to_aead(link: str) -> str:
    raw = link.strip()[len("vmess://"):].split("#", 1)[0]
    try:
        decoded = base64.b64decode(raw.replace("-", "+").replace("_", "/") + "=" * (-len(raw) % 4), validate=True)
        data = json.loads(decoded.decode("utf-8-sig"))
    except (ValueError, UnicodeError) as exc:
        raise ValueError("Invalid VMess Base64 JSON share link") from None
    if not isinstance(data, dict):
        raise ValueError("VMess QR payload must be an object")
    unknown = sorted(set(data) - VMESS_QR_KEYS)
    if unknown:
        raise ValueError("Unsupported VMess QR keys: " + ",".join(unknown))
    if str(data.get("aid", "0")) not in ("0", "", "None"):
        raise ValueError("Legacy VMess alterId != 0 cannot be exported as AEAD safely")
    addr, user, port = str(data.get("add", "")), str(data.get("id", "")), str(data.get("port", ""))
    if not addr or not user or not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError("VMess QR requires add, port and id")
    net = str(data.get("net", "tcp") or "tcp")
    header_type = str(data.get("type", "none") or "none")
    if header_type not in ("none", ""):
        raise ValueError("VMess legacy transport header type cannot be represented safely")
    sec = str(data.get("tls", "") or "none")
    if sec not in ("none", "tls", "reality"):
        raise ValueError("Unsupported legacy VMess TLS value")
    params = [("encryption", str(data.get("scy") or "auto")),
              ("security", sec), ("type", net)]
    for old, new in (("host", "host"), ("path", "path"), ("sni", "sni"),
                     ("alpn", "alpn"), ("fp", "fp"), ("ech", "ech"),
                     ("fm", "fm"), ("pcs", "pcs"), ("vcn", "vcn"),
                     ("insecure", "insecure"), ("cs", "cs")):
        if old in data and str(data[old]) != "":
            params.append((new, str(data[old])))
    netloc = f"{quote(user, safe='')}@{'[' + addr + ']' if ':' in addr else addr}:{port}"
    return urlunsplit(("vmess", netloc, "", urlencode(params),
                       quote(str(data.get("ps", "VMess")), safe="")))


def normalize_link(link: str) -> str:
    link = link.strip()
    if is_legacy_vmess(link):
        link = legacy_to_aead(link)
    parsed = urlsplit(link)
    if parsed.scheme.lower() not in ("vless", "vmess", "trojan"):
        raise ValueError("Supported protocols: vless://, vmess://, trojan://")
    if not parsed.username or not parsed.hostname or not parsed.port:
        raise ValueError("Share URL needs user/password, address and port")
    _query_validate(link)
    return link


def link_to_config(link: str) -> dict:
    canonical = normalize_link(link)
    parsed = urlsplit(canonical)
    scheme = parsed.scheme.lower()
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    fields = dict(pairs)
    if scheme == "vless":
        return vless_to_config(canonical)
    if scheme == "trojan":
        transport_security = fields.get("security", "tls")
        if transport_security != "tls":
            raise ValueError("Trojan scanner requires TLS (no unsafe plaintext downgrade)")
        if "encryption" in fields or "flow" in fields:
            raise ValueError("Trojan link has protocol-incompatible encryption/flow field")
    if scheme == "vmess":
        if "flow" in fields:
            raise ValueError("VMess doesn't support VLESS flow")
        if fields.get("encryption", "auto") not in ("auto", "none", "aes-128-gcm", "chacha20-poly1305"):
            raise ValueError("Unsupported VMess security value")
    # Reuse exactly the same shared TLS, ECH, WS, REALITY and FinalMask parser,
    # then replace protocol-only fields using Xray's current flat outbound syntax.
    transport_pairs = [(k, v) for k, v in pairs if k not in ("encryption", "flow")]
    if scheme == "trojan" and "security" not in fields:
        transport_pairs.append(("security", "tls"))
    if scheme == "vmess" and "security" not in fields:
        transport_pairs.append(("security", "none"))
    synth = urlunsplit(("vless", parsed.netloc, parsed.path,
                       urlencode(transport_pairs + [("encryption", "none")]), parsed.fragment))
    config = vless_to_config(synth)
    outbound = config["outbounds"][0]
    outbound["protocol"] = scheme
    if scheme == "vmess":
        outbound["settings"].pop("encryption", None)
        outbound["settings"]["security"] = fields.get("encryption", "auto")
    if scheme == "trojan":
        outbound["settings"].pop("encryption", None)
        outbound["settings"].pop("id", None)
        outbound["settings"]["password"] = unquote(parsed.username)
    return config


def scheme_and_encoding(link: str) -> tuple[str, str]:
    scheme = urlsplit(link.strip()).scheme.lower()
    return scheme, "legacy-qr" if is_legacy_vmess(link) else "uri"
