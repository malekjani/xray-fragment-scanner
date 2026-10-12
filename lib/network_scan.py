#!/usr/bin/env python3
"""Independent, non-root Cloudflare IP/ECH and IP/FinalMask experiments.

Does not install Xray, change system services or alter project config.json.
Inputs are private credentials: never print a VLESS URI or UUID to stdout/logs.
"""
from __future__ import annotations

import argparse
import copy
import csv
import getpass
import ipaddress
import itertools
import json
import os
from pathlib import Path
import random
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlsplit, unquote

CF_IPS = [f"188.114.97.{n}" for n in (1, 2, 3, 4, 5, 7, 8)]
ECH_DNS = [
    "1.1.1.1", "9.9.9.9", "208.67.222.222", "8.8.8.8", "1.0.0.1",
    "8.8.4.4", "149.112.112.112", "208.67.220.220", "76.76.19.19",
    "76.76.2.0", "94.140.14.14", "94.140.15.15", "64.6.64.6",
    "64.6.65.6", "45.90.28.0", "45.90.30.0", "185.228.168.9",
    "185.228.169.9",
]

# Go TLS 1.2 cipher suite identifiers, NOT guaranteed identical to PattNG's
# "real_firefox_cipherSuites" preset. See docs/NETWORK_SCAN.md.
FIREFOX_LIKE_CIPHERS = ":".join([
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
])

# This experimental profile follows a public Fragment+Fingerprint example;
# it has NOT been verified to be byte-identical to PattNG's named preset.
# Xray issue #6724 reports that non-final 0 in tlshello lengths may break TLS.
EXPERIMENTAL_ZERO_MASK = {"tcp": [
    {"type": "fragment", "settings": {
        "packets": "tlshello", "lengths": ["0", "104", "1"],
        "delays": ["0"], "maxSplit": "0"}},
    {"type": "fragment", "settings": {
        "packets": "1-1", "lengths": ["114", "1"],
        "delays": ["1"], "maxSplit": "11"}},
]}
ZERO_FREE_MASK = {"tcp": [
    {"type": "fragment", "settings": {
        "packets": "tlshello", "lengths": ["104", "1"],
        "delays": ["1"], "maxSplit": "0"}},
    {"type": "fragment", "settings": {
        "packets": "1-1", "lengths": ["114", "1"],
        "delays": ["1"], "maxSplit": "11"}},
]}


def extract_finalmask(raw: str):
    """Tolerate fm= encoded as a JSON object or a JSON property fragment."""
    raw = raw.strip().rstrip(",").strip()
    if not raw:
        return None
    if raw.startswith('"finalmask"'):
        raw = "{" + raw + "}"
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise ValueError("fm must be a JSON object")
    result = obj.get("finalmask", obj)
    if not isinstance(result, dict):
        raise ValueError("fm.finalmask must be a JSON object")
    return result


def vless_to_config(link: str, listen_port: int = 0) -> dict:
    parsed = urlsplit(link.strip())
    if parsed.scheme.lower() != "vless" or not parsed.hostname or not parsed.username:
        raise ValueError("Expected a complete vless:// URL with UUID and host")
    query = parse_qs(parsed.query, keep_blank_values=True)

    def q(k, default=""):
        # parse_qs already percent-decodes both key and value
        return query.get(k, [default])[0]

    def present_true(*keys):
        return any(q(k).lower() in {"1", "true", "yes"} for k in keys)

    network = q("type", "tcp").lower()
    if network in ("websocket",):
        network = "ws"
    if network in ("splithttp",):
        network = "xhttp"
    security = q("security", "none").lower()
    dest = parsed.hostname
    user = {"id": unquote(parsed.username), "encryption": q("encryption", "none")}
    if q("flow"):
        user["flow"] = q("flow")

    # Matches the original ZIP's 2026 flat VLESS client syntax.
    stream = {"network": network, "security": security, "sockopt": {
        "tcpNoDelay": True, "tcpKeepAliveIdle": 100}}
    host = q("host")
    path = q("path", "/") or "/"
    if network == "ws":
        stream["wsSettings"] = {"path": path}
        if host:
            stream["wsSettings"]["headers"] = {"Host": host}
    elif network == "xhttp":
        stream["xhttpSettings"] = {"path": path, "mode": q("mode", "auto")}
        if host:
            stream["xhttpSettings"]["host"] = host
    elif network == "httpupgrade":
        stream["httpupgradeSettings"] = {"path": path}
        if host:
            stream["httpupgradeSettings"]["host"] = host
    elif network == "grpc":
        stream["grpcSettings"] = {"serviceName": q("serviceName")}
    elif network not in ("tcp", "raw"):
        raise ValueError(f"Unsupported network type for this scanner: {network}")

    if security == "tls":
        tls = {"serverName": q("sni") or host or dest,
               "allowInsecure": present_true("allowInsecure", "insecure")}
        if q("fp"):
            tls["fingerprint"] = q("fp")
        if q("alpn"):
            tls["alpn"] = [x.strip() for x in q("alpn").split(",") if x.strip()]
        if q("ech"):
            tls["echConfigList"] = q("ech")
        if q("cs") or q("cipherSuites"):
            tls["cipherSuites"] = q("cs") or q("cipherSuites")
        stream["tlsSettings"] = tls
    elif security == "reality":
        reality = {"serverName": q("sni") or host or dest}
        for key, val in (("fingerprint", q("fp")),
                         ("password", q("pbk") or q("password")),
                         ("shortId", q("sid")), ("spiderX", q("spx"))):
            if val:
                reality[key] = val
        stream["realitySettings"] = reality
    elif security != "none":
        raise ValueError(f"Unsupported security type: {security}")

    if q("fm"):
        stream["finalmask"] = extract_finalmask(q("fm"))

    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{"tag": "scanner-http", "listen": "127.0.0.1",
                      "port": listen_port, "protocol": "http", "settings": {}}],
        "outbounds": [{"tag": "proxy", "protocol": "vless",
                       "settings": {"address": dest,
                                    "port": parsed.port or 443, **user},
                       "streamSettings": stream}],
        "routing": {"domainStrategy": "AsIs", "rules": [
            {"type": "field", "port": "0-65535", "outboundTag": "proxy"}]},
    }


def proxy(cfg):
    return cfg["outbounds"][0]


def build_candidates(cfg: dict, method: str, ips=None, dns=None,
                     custom_mask=None, experimental_zero=False,
                     custom_ciphers=None):
    original = copy.deepcopy(cfg)
    yield ("original", "original", "original", original)
    ips = ips if ips is not None else CF_IPS
    if method == "ech":
        if proxy(cfg)["streamSettings"]["security"] != "tls":
            raise ValueError("ECH mode requires security=tls")
        for ip, server in itertools.product(ips, dns if dns is not None else ECH_DNS):
            ipaddress.ip_address(ip)
            x = copy.deepcopy(cfg)
            proxy(x)["settings"]["address"] = ip
            st = proxy(x)["streamSettings"]
            st["tlsSettings"]["fingerprint"] = "chrome"
            st["tlsSettings"]["echConfigList"] = f"cloudflare-ech.com+udp://{server}"
            st.pop("finalmask", None)  # compare ECH alone rather than mixed masks
            yield (ip, server, "ECH+chrome", x)
    elif method == "irancell":
        if proxy(cfg)["streamSettings"]["security"] != "tls":
            raise ValueError("FinalMask+TLS fingerprint mode requires security=tls")
        masks = [("zero-free", ZERO_FREE_MASK), ("none", None)]
        if experimental_zero:
            masks.append(("experimental-zero", EXPERIMENTAL_ZERO_MASK))
        if custom_mask is not None:
            masks.insert(0, ("custom-pattng", custom_mask))
        cipher_variants = [("native-default", None),
                           ("firefox-like-approx", FIREFOX_LIKE_CIPHERS)]
        if custom_ciphers is not None:
            cipher_variants.insert(0, ("custom-pattng", custom_ciphers))
        for ip, (mask_name, mask), (cipher_name, cipher) in itertools.product(
                ips, masks, cipher_variants):
            ipaddress.ip_address(ip)
            x = copy.deepcopy(cfg)
            proxy(x)["settings"]["address"] = ip
            st = proxy(x)["streamSettings"]
            tls = st["tlsSettings"]
            tls.pop("echConfigList", None)
            tls["fingerprint"] = "unsafe"
            tls.pop("cipherSuites", None)
            if cipher is not None:
                tls["cipherSuites"] = cipher
            st.pop("finalmask", None)
            if mask is not None:
                st["finalmask"] = copy.deepcopy(mask)
            yield (ip, mask_name, cipher_name, x)
    else:
        raise ValueError(f"Unknown method: {method}")


def balanced_sample(candidates, limit, seed):
    """Baseline then round-robin per candidate IP (not just first list entries)."""
    if limit is None or limit >= len(candidates):
        return candidates
    if limit < 1:
        raise ValueError("limit must be >= 1")
    rand = random.Random(seed)
    baseline = candidates[0]
    by_ip = {}
    for candidate in candidates[1:]:
        by_ip.setdefault(candidate[0], []).append(candidate)
    for group in by_ip.values():
        rand.shuffle(group)
    order = list(by_ip)
    rand.shuffle(order)
    out = [baseline]
    while len(out) < limit and any(by_ip.values()):
        for ip in order:
            if by_ip[ip] and len(out) < limit:
                out.append(by_ip[ip].pop())
    return out


def write_private_json(path, obj):
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            json.dump(obj, file, indent=2, ensure_ascii=False)
    except BaseException:
        raise


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def probe(port, url, timeout):
    args = ["curl", "--silent", "--show-error", "--location", "--max-redirs", "2",
            "--output", os.devnull, "--write-out", "%{http_code} %{time_total}",
            "--max-time", str(timeout), "--connect-timeout", str(min(timeout, 5)),
            "--noproxy", "", "--proxy", f"http://127.0.0.1:{port}", url]
    try:
        run = subprocess.run(args, capture_output=True, text=True, timeout=timeout + 2)
        bits = run.stdout.split()
        if run.returncode or len(bits) != 2:
            return False, None
        status, seconds = int(bits[0]), float(bits[1])
        return 200 <= status < 400, round(seconds * 1000, 2)
    except (ValueError, subprocess.TimeoutExpired):
        return False, None


def run_candidate(xray, cfg, cfg_file, url, count, timeout):
    test_cmd = [xray, "run", "-test", "-c", str(cfg_file)]
    try:
        valid = subprocess.run(test_cmd, capture_output=True, text=True, timeout=12)
    except subprocess.TimeoutExpired:
        return "INVALID_CONFIG", 0, None, "config-test-timeout"
    if valid.returncode:
        # Truncate messages to avoid inadvertent credential disclosure in logs.
        return "INVALID_CONFIG", 0, None, "xray-config-rejected"
    port = cfg["inbounds"][0]["port"]
    with open(os.devnull, "wb") as devnull:
        process = subprocess.Popen([xray, "run", "-c", str(cfg_file)],
                                   stdout=devnull, stderr=devnull,
                                   start_new_session=True)
        try:
            started = False
            for _ in range(30):
                if process.poll() is not None:
                    return "START_FAILED", 0, None, "xray-exited"
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        started = True
                        break
                except OSError:
                    time.sleep(0.1)
            if not started:
                return "START_FAILED", 0, None, "proxy-listen-timeout"
            ok = []
            for _ in range(count):
                success, ms = probe(port, url, timeout)
                ok.append(ms if success else None)
            succeeded = [x for x in ok if x is not None]
            # Success ratio has precedence over latency in ranking.
            return ("OK" if succeeded else "FAILED", len(succeeded),
                    round(sum(succeeded) / len(succeeded), 2) if succeeded else None,
                    "")
        finally:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                    process.wait(timeout=2)
                except (OSError, subprocess.TimeoutExpired):
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()


def get_link(args):
    if args.link_file:
        return Path(args.link_file).expanduser().read_text(encoding="utf-8").strip()
    if not sys.stdin.isatty():
        return sys.stdin.readline().strip()
    return getpass.getpass("Paste your VLESS link (input hidden): ").strip()


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Non-root IP/ECH and FinalMask scanner")
    p.add_argument("--method", choices=["ech", "irancell"], required=True)
    p.add_argument("--link-file", help="Read VLESS URL from a file (prefer chmod 600)")
    p.add_argument("--all", action="store_true", help="Scan every candidate; may take a long time")
    p.add_argument("--limit", type=int, help="Limit candidates (includes original baseline)")
    p.add_argument("--requests", type=int, default=3)
    p.add_argument("--timeout", type=float, default=8)
    p.add_argument("--seed", type=int, default=2026)
    p.add_argument("--url", default="https://www.gstatic.com/generate_204")
    p.add_argument("--xray", help="Xray executable path (default: PATH or /usr/local/bin/xray)")
    p.add_argument("--output", type=Path, help="Output folder (default ~/.local/share/...)")
    p.add_argument("--dry-run", action="store_true", help="Generate and inspect configs; no network or xray")
    p.add_argument("--experimental-zero", action="store_true", help="Include potentially broken zero-length preset")
    p.add_argument("--finalmask-json", type=Path, help="Exact PattNG finalmask JSON export (if you have it)")
    p.add_argument("--cipher-file", type=Path, help="Exact colon-separated PattNG cipherSuites string")
    a = p.parse_args(argv)
    if a.requests < 1 or a.timeout <= 0 or (a.limit is not None and a.limit < 1):
        p.error("requests, timeout and limit must be positive")
    return a


def main(argv=None):
    args = parse_args(argv)
    if not args.dry_run:
        xray = args.xray or shutil.which("xray") or "/usr/local/bin/xray"
        if not (shutil.which("curl") and (shutil.which(xray) or os.path.isfile(xray))):
            raise SystemExit("Error: Install Xray-core and curl; this mode never installs software")
    else:
        xray = ""
    custom_mask = None
    if args.finalmask_json:
        custom_mask = extract_finalmask(args.finalmask_json.read_text(encoding="utf-8"))
    custom_ciphers = None
    if args.cipher_file:
        custom_ciphers = args.cipher_file.read_text(encoding="utf-8").strip()
        if not custom_ciphers:
            raise SystemExit("Error: --cipher-file is empty")
    cfg = vless_to_config(get_link(args))
    candidates = list(build_candidates(cfg, args.method,
                      custom_mask=custom_mask, experimental_zero=args.experimental_zero,
                      custom_ciphers=custom_ciphers))
    limit = None if args.all else (args.limit if args.limit is not None else
                                  (22 if args.method == "ech" else 15))
    candidates = balanced_sample(candidates, limit, args.seed)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    output = (args.output or (Path.home() / ".local/share/xray-finalmask-scanner" /
              f"{args.method}-{stamp}")).expanduser()
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(output, 0o700)
    results = []
    csv_path = output / "results.csv"
    fields = ["index", "address", "variant", "tls", "status", "successes", "requests", "success_rate", "avg_ms", "reason"]
    try:
        with csv_path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            for i, (ip, variant, tls_variant, candidate) in enumerate(candidates, 1):
                candidate["inbounds"][0]["port"] = free_port()
                tmp = output / ".candidate.json"
                write_private_json(tmp, candidate)
                if args.dry_run:
                    status, count_ok, mean, reason = "DRY_RUN", 0, None, "not-executed"
                else:
                    status, count_ok, mean, reason = run_candidate(
                        xray, candidate, tmp, args.url, args.requests, args.timeout)
                row = {"index": i, "address": ip, "variant": variant,
                       "tls": tls_variant, "status": status,
                       "successes": count_ok, "requests": args.requests,
                       "success_rate": round(count_ok / args.requests, 4),
                       "avg_ms": mean if mean is not None else "", "reason": reason}
                writer.writerow(row)
                f.flush()
                results.append((row, copy.deepcopy(candidate)))
                latency = f"{mean}ms" if mean is not None else "-"
                print(f"[{i:>3}/{len(candidates)}] {ip:16} {variant:23} {tls_variant:22} "
                      f"{status:14} {count_ok}/{args.requests} {latency}", flush=True)
                if args.dry_run and i == 1:
                    # Only first config is saved as an example, with private permissions.
                    write_private_json(output / "example-config.json", candidate)
                tmp.unlink(missing_ok=True)
    finally:
        (output / ".candidate.json").unlink(missing_ok=True)
    os.chmod(csv_path, 0o600)
    qualifying = [(r, c) for r, c in results if r["successes"] == args.requests]
    # Only fully successful profiles can win, unlike old mean=0 ranking.
    if qualifying:
        best, best_cfg = min(qualifying, key=lambda pair: pair[0]["avg_ms"])
        best_cfg["inbounds"][0]["port"] = free_port()
        write_private_json(output / "best-config.json", best_cfg)
        summary = {"winner": {k: v for k, v in best.items() if k != "reason"},
                   "note": "Full success required. Validate stability at another time."}
        write_private_json(output / "summary.json", summary)
        print(f"\nBest full-success result: {best['address']} / {best['variant']} / {best['tls']}")
    else:
        print("\nNo fully successful candidate; no best-config.json was generated.")
    print(f"Results folder: {output}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        # Never print a credential-containing URL in errors.
        print(f"Error: {type(exc).__name__}: {str(exc)[:200]}", file=sys.stderr)
        sys.exit(2)
