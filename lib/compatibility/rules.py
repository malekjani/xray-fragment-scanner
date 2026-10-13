"""Version-scoped, conservative compatibility rules for Expert Combination Builder.

Rules describe documented restrictions; they cannot prove on-the-wire effects.
The exact selected prerelease is validated with `xray run -test` before LIVE probes.
"""
from __future__ import annotations

import copy
import ipaddress
from dataclasses import dataclass

from network_scan import proxy
from .versioning import core_capabilities

DOCS = {
    "finalmask": "https://github.com/XTLS/Xray-docs-next/blob/main/docs/en/config/transports/finalmask.md",
    "tls": "https://github.com/XTLS/Xray-docs-next/blob/main/docs/en/config/transports/tls.md",
    "browser": "https://github.com/XTLS/Xray-docs-next/blob/main/docs/en/config/features/browser_dialer.md",
}

@dataclass
class Finding:
    severity: str  # BLOCK, WARN, INFO
    code: str
    explanation: str
    reference: str = ""


def validate(cfg: dict, *, browser_dialer: bool = False, core_version: str | None = None) -> list[Finding]:
    out = proxy(cfg)
    stream = out["streamSettings"]
    network = stream.get("network", "tcp")
    security = stream.get("security", "none")
    mask = stream.get("finalmask") or {}
    core = core_capabilities(core_version)
    tls = stream.get("tlsSettings") or {}
    tcp = mask.get("tcp", [])
    findings: list[Finding] = []
    def flag(severity, code, explanation, ref=""):
        findings.append(Finding(severity, code, explanation, DOCS.get(ref, "")))
    if network not in {"tcp", "raw", "ws", "xhttp", "httpupgrade", "grpc", "kcp", "hysteria"}:
        flag("WARN", "unreviewed-transport", "This transport is not covered by V8 compatibility rules.")
    if security == "reality" and network not in {"tcp", "raw", "xhttp", "grpc"}:
        flag("BLOCK", "reality-transport", "REALITY is unsupported with this transport.")
    if security == "reality" and tls.get("echConfigList"):
        flag("BLOCK", "ech-reality", "ECH is a TLS configuration and cannot be applied to REALITY simultaneously.", "tls")
    if tls.get("echConfigList") and security != "tls":
        flag("BLOCK", "ech-requires-tls", "ECH requires TLS security.", "tls")
    if tcp and network in {"kcp", "hysteria"}:
        flag("BLOCK", "tcp-mask-udp-transport", "TCP masks cannot be applied to UDP-only transports.", "finalmask")
    if not isinstance(tcp, list):
        flag("BLOCK", "tcp-mask-type", "finalmask.tcp must be an ordered array.", "finalmask")
        tcp = []
    if any(isinstance(layer, dict) and layer.get("type") == "fragment" for layer in tcp):
        if core["fragment_arrays"] == "unsupported-known-old-core":
            flag("BLOCK", "fragment-arrays-old-core", "Current Xray core predates FinalMask fragment lengths[]/delays[] support.", "finalmask")
        elif core["fragment_arrays"] == "unverified":
            flag("WARN", "core-version-pending", "Fragment combinations are experimental until an exact Xray core is validated.", "finalmask")
    for i, layer in enumerate(tcp):
        if not isinstance(layer, dict):
            flag("BLOCK", "invalid-layer", "Each TCP mask layer must be an object.")
            continue
        typ = layer.get("type")
        if typ == "fragment":
            settings = layer.get("settings", {})
            sizes = settings.get("lengths")
            delays = settings.get("delays")
            if not isinstance(sizes, list) or not sizes or not isinstance(delays, list) or not delays:
                flag("BLOCK", "fragment-array-shape", "Fragment requires nonempty lengths[] and delays[].", "finalmask")
            elif str(sizes[-1]).split("-")[0] == "0":
                flag("BLOCK", "fragment-final-zero", "Last lengths entry must be positive.", "finalmask")
            if settings.get("packets") == "tlshello" and sizes and str(sizes[0]) == "0":
                flag("WARN", "tls-empty-record", "A zero first length may emit an empty TLS record and break some peers.", "finalmask")
        elif typ == "header-custom":
            config = layer.get("settings", {})
            if not isinstance(config, dict) or not config.get("clients"):
                flag("BLOCK", "header-clients-required", "Header-Custom requires clients packet template(s).", "finalmask")
        else:
            flag("WARN", "unreviewed-tcp-mask", f"TCP mask type {str(typ)[:30]!r} was not statically reviewed; requires Xray validation.", "finalmask")
    if len(tcp) > 1:
        flag("INFO", "mask-order", "TCP FinalMask order is significant: the first element is the innermost layer.", "finalmask")
    if browser_dialer:
        if network not in {"ws", "xhttp"}:
            flag("BLOCK", "browser-transport", "Browser Dialer supports only WebSocket/XHTTP.", "browser")
        address = out["settings"].get("address", "")
        try:
            ipaddress.ip_address(address)
            flag("BLOCK", "browser-address", "Browser Dialer requires a domain name, not a bare IP.", "browser")
        except ValueError:
            pass
        sni = tls.get("serverName")
        host = (stream.get("wsSettings") or {}).get("host") or (stream.get("wsSettings") or {}).get("headers", {}).get("Host")
        if (sni and sni != address) or (host and host != address):
            flag("BLOCK", "browser-host-sni", "Browser Dialer requires SNI == Host == address.", "browser")
        flag("BLOCK", "browser-runtime", "Automated Browser Dialer runs are disabled: a connected real browser, direct routing and CORS checks are required. Use external/manual validation.", "browser")
    if security == "tls" and tls.get("fingerprint") not in (None, "", "unsafe") and tls.get("cipherSuites"):
        flag("WARN", "utls-cipher-effect", "uTLS fingerprinting can override configured TLS cipher suites; test effective behavior.", "tls")
    return findings


def safe_summary(cfg: dict, *, browser_dialer=False, core_version=None) -> dict:
    findings = validate(cfg, browser_dialer=browser_dialer, core_version=core_version)
    allowed=not any(f.severity == "BLOCK" for f in findings)
    status="BLOCKED" if not allowed else "EXPERIMENTAL" if findings or core_version is None else "DOCUMENTED_UNVERIFIED"
    return {"allowed":allowed,"status":status,"core_version":core_capabilities(core_version),
            "effective_evidence":"NOT_OBSERVED", "findings":[f.__dict__ for f in findings]}
