#!/usr/bin/env python3
"""Reproducible VLESS/VMess/Trojan FinalMask optimization.

Every candidate links an unchanged-input share URI (except fm=, optional address)
to the exact Xray JSON that is validated and tested. Legacy freedom.fragment
is intentionally not exported as a shareable URI: all fragment candidates
use current Xray FinalMask fragment layers.
"""
from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import itertools
import json
import math
import os
from pathlib import Path
import re
import shutil
import sys
from datetime import datetime, timezone
from urllib.parse import parse_qsl, quote, unquote, urlsplit, urlunsplit

from network_scan import (
    MAX_CANDIDATES, PATTNG_TLSHELLO, PATTNG_TLSHELLO_ZERO,
    ZERO_FREE_MASK, extract_finalmask, free_port, get_link,
    proxy, run_candidate, write_private_json,
    expand_addresses,
)

from share_codec import link_to_config, normalize_link, scheme_and_encoding

RANGE_RE = re.compile(r"^(0|[1-9][0-9]*)(?:-(0|[1-9][0-9]*))?$")
FIELDS = ["id", "rank", "protocol", "source_encoding", "mode", "profile", "address", "port", "transport",
          "security", "fingerprint", "sni", "ech", "packets", "lengths",
          "delays", "maxSplit", "fragment_layers", "finalmask_json", "status",
          "successes", "requests", "success_rate", "avg_ms", "p95_ms",
          "min_ms", "max_ms", "reason", "link_sha256"]
DEFAULT_LENGTHS = ["1-3", "5-10", "10-20", "0,104,1", "6,98,1"]
DEFAULT_DELAYS = ["0", "1-5", "5-10"]
DEFAULT_MAX_SPLITS = ["0", "2-4"]
DEFAULT_PACKETS = ["tlshello", "1-2"]


def parse_range(s: str, *, zero=True) -> str:
    s = str(s).strip()
    m = RANGE_RE.fullmatch(s)
    if not m:
        raise ValueError("Invalid numeric range; expected N or N-M: " + s[:80])
    a, b = int(m[1]), int(m[2] or m[1])
    if b < a or b > 2147483647 or (not zero and a == 0):
        raise ValueError("Out-of-range/inverted fragment range: " + s[:80])
    return s


def parse_array(s: str, *, final_nonzero=False) -> list[str]:
    values = [parse_range(x) for x in s.split(",")]
    if not values or len(values) > 32:
        raise ValueError("Expected 1-32 fragment array elements")
    if final_nonzero and values[-1].split("-")[0] == "0":
        raise ValueError("Final lengths entry must be nonzero to avoid infinite splitting")
    return values


def validate_packets(value: str) -> str:
    value = value.strip()
    if value != "tlshello":
        parse_range(value, zero=False)
    return value


def fragment(packets, lengths, delays, max_split):
    return {"type": "fragment", "settings": {
        "packets": validate_packets(packets),
        "lengths": parse_array(lengths, final_nonzero=True),
        "delays": parse_array(delays),
        "maxSplit": parse_range(max_split),
    }}


def merge_fragments(original_mask, new_layers):
    """Replace only TCP fragment layers, keeping other TCP layers in order and UDP/quic untouched."""
    mask = copy.deepcopy(original_mask) if original_mask else {}
    tcp = mask.get("tcp", [])
    if not isinstance(tcp, list):
        raise ValueError("finalmask.tcp must be an array")
    assert new_layers
    insert_at = next((i for i, layer in enumerate(tcp)
                      if layer.get("type") == "fragment"), len(tcp))
    non_fragments = [layer for layer in tcp if layer.get("type") != "fragment"]
    insertion = min(insert_at, len(non_fragments))
    non_fragments[insertion:insertion] = copy.deepcopy(new_layers)
    mask["tcp"] = non_fragments
    return mask


def share_link(base: str, cfg: dict, marker: str, *, baseline=False) -> str:
    """Preserve all original query *values* and order, only edit address/fm and label.

    Xray's share standard encodes the JSON property for fm (without outer braces).
    """
    if baseline:
        return base.strip()
    canonical = normalize_link(base)
    parsed = urlsplit(canonical)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    if sum(k == "fm" for k, _ in params) > 1:
        raise ValueError("Ambiguous repeated fm query parameter")
    outbound = proxy(cfg)
    address = outbound["settings"]["address"]
    if address != parsed.hostname:
        netloc = f"{parsed.username}@[{address}]" if ":" in address else f"{parsed.username}@{address}"
        if parsed.port:
            netloc += f":{parsed.port}"
    else:
        netloc = parsed.netloc
    mask = outbound["streamSettings"].get("finalmask")
    fm_value = '"finalmask":' + json.dumps(mask, ensure_ascii=False, separators=(",", ":")) if mask else None
    updated = []
    fm_seen = False
    for k, v in params:
        if k == "fm":
            fm_seen = True
            if fm_value is not None:
                updated.append((k, fm_value))
        else:
            updated.append((k, v))
    if not fm_seen and fm_value is not None:
        updated.append(("fm", fm_value))
    # quote(...safe=...) matches encodeURIComponent for JSON-bearing parameters.
    query = "&".join(f"{quote(k, safe='-_.!~*\'()')}={quote(v, safe='-_.!~*\'()')}" for k, v in updated)
    label = quote((unquote(parsed.fragment) or parsed.scheme.upper()) + " | " + marker,
                  safe="-_.!~*'()")
    return urlunsplit((parsed.scheme, netloc, parsed.path, query, label))


def make_candidates(config, scan, addr, packets, lengths, delays, splits,
                    layer2=None, mask_file=None):
    """Yield (category, preset, candidate config) in stable generation order."""
    yield ("baseline", "original", copy.deepcopy(config))
    original_mask = proxy(config)["streamSettings"].get("finalmask")
    seen = set()

    def emit(category, name, layers):
        mask = merge_fragments(original_mask, layers)
        sig = json.dumps(mask, sort_keys=True, ensure_ascii=False)
        if sig in seen:
            return None
        seen.add(sig)
        x = copy.deepcopy(config)
        proxy(x)["settings"]["address"] = addr
        proxy(x)["streamSettings"]["finalmask"] = mask
        return category, name, x

    if scan in ("fragment", "both"):
        for p, l, d, s in itertools.product(packets, lengths, delays, splits):
            item = emit("fragment", f"fragment-{p}-{l}-{d}-{s}", [fragment(p, l, d, s)])
            if item:
                yield item
    if scan in ("finalmask", "both"):
        for name, mask in (("pattng-tlshello-0-len", PATTNG_TLSHELLO_ZERO),
                           ("pattng-tlshello", PATTNG_TLSHELLO),
                           ("zero-free", ZERO_FREE_MASK)):
            item = emit("finalmask", name, mask["tcp"])
            if item:
                yield item
        if mask_file is not None:
            mask = extract_finalmask(Path(mask_file).read_text(encoding="utf-8"))
            layers = [entry for entry in mask.get("tcp", []) if entry.get("type") == "fragment"]
            if not layers:
                raise ValueError("Custom mask JSON must contain TCP fragment layers")
            item = emit("finalmask", "custom-mask-file", layers)
            if item:
                yield item
        if layer2:
            second = fragment(*layer2)
            for p, l, d, s in itertools.product(packets, lengths, delays, splits):
                item = emit("finalmask", f"two-layer-{p}-{l}-{d}-{s}",
                            [fragment(p, l, d, s), second])
                if item:
                    yield item


def percentile95(values):
    if not values:
        return None
    ordered = sorted(values)
    return round(ordered[max(0, math.ceil(len(ordered) * 0.95) - 1)], 2)


def summarize_parameters(cfg):
    outbound = proxy(cfg)
    stream = outbound["streamSettings"]
    mask = stream.get("finalmask", {})
    layers = [e.get("settings", {}) for e in mask.get("tcp", []) if e.get("type") == "fragment"]
    return {
        "address": outbound["settings"]["address"], "port": outbound["settings"]["port"],
        "transport": stream.get("network", ""), "security": stream.get("security", ""),
        "fingerprint": stream.get("tlsSettings", {}).get("fingerprint", ""),
        "sni": stream.get("tlsSettings", {}).get("serverName", ""),
        "ech": stream.get("tlsSettings", {}).get("echConfigList", ""),
        "packets": json.dumps([e.get("packets") for e in layers]),
        "lengths": json.dumps([e.get("lengths", [e.get("length")]) for e in layers]),
        "delays": json.dumps([e.get("delays", [e.get("delay")]) for e in layers]),
        "maxSplit": json.dumps([e.get("maxSplit") for e in layers]),
        "fragment_layers": json.dumps(layers, separators=(",", ":")),
        "finalmask_json": json.dumps(mask, separators=(",", ":")) if mask else "",
    }


def ranking(row):
    return (-row["success_rate"], float(row["p95_ms"]) if row["p95_ms"] != "" else float("inf"),
            float(row["avg_ms"]) if row["avg_ms"] != "" else float("inf"))


def safe_text_file(path, lines):
    with os.fdopen(os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600), "w", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")
    os.chmod(path, 0o600)


def safe_csv(path, columns, rows):
    with os.fdopen(os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600),
                   "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)
    os.chmod(path, 0o600)


def parser():
    p = argparse.ArgumentParser(description="Repeatable VLESS/VMess/Trojan FinalMask/Fragment optimization with link export")
    p.add_argument("--link-file", type=Path, help="Private file containing the original vless:// link")
    p.add_argument("--scan", choices=["fragment", "finalmask", "both"], default="both")
    p.add_argument("--ip", action="append", default=[], help="Candidate address; default is original address")
    p.add_argument("--packets", action="append", help="Repeatable 'tlshello' or packet-write range")
    p.add_argument("--lengths", action="append", help="Repeatable comma-separated length arrays: '0,104,1'")
    p.add_argument("--delays", action="append", help="Repeatable comma-separated delay arrays: '0,1-5'")
    p.add_argument("--max-split", action="append", help="Repeatable maxSplit ranges")
    p.add_argument("--layer2-packets", help="Optional second layer packet range")
    p.add_argument("--layer2-lengths", help="Optional second layer lengths array")
    p.add_argument("--layer2-delays", help="Optional second layer delays array")
    p.add_argument("--layer2-max-split", help="Optional second layer maxSplit")
    p.add_argument("--mask-file", type=Path, help="Additional multilayer mask JSON preset")
    p.add_argument("--limit", type=int, default=25, help="Candidate limit per scan incl. baseline")
    p.add_argument("--all", action="store_true", help="Evaluate every generated candidate")
    p.add_argument("--requests", type=int, default=5)
    p.add_argument("--timeout", type=float, default=8)
    p.add_argument("--url", default="https://www.gstatic.com/generate_204")
    p.add_argument("--xray")
    p.add_argument("--output", type=Path)
    p.add_argument("--dry-run", action="store_true", help="Export all sampled candidates without network testing")
    return p


def main(argv=None, *, link_override=None):
    p = parser()
    args = p.parse_args(argv)
    if args.limit < 1 or args.requests < 1 or args.timeout <= 0:
        p.error("--limit, --requests and --timeout must be positive")
    xray = args.xray or shutil.which("xray") or "/usr/local/bin/xray"
    if not args.dry_run and (not shutil.which("curl") or not (shutil.which(xray) or os.path.isfile(xray))):
        p.error("Xray and curl required for real tests; try --dry-run for offline config export")
    orig_link = link_override if link_override is not None else get_link(args)
    scheme, source_encoding = scheme_and_encoding(orig_link)
    canonical_link = normalize_link(orig_link)
    if source_encoding == "legacy-qr":
        print("Note: modified VMess QR links export in VMess AEAD URI format; client compatibility must be checked.")
    config = link_to_config(orig_link)
    original_addr = proxy(config)["settings"]["address"]
    address_set = expand_addresses(args.ip) if args.ip else [original_addr]
    if proxy(config)["streamSettings"]["security"] not in ("tls", "reality", "none"):
        p.error("Unsupported transport security")
    packets = [validate_packets(x) for x in (args.packets or DEFAULT_PACKETS)]
    lengths = [",".join(parse_array(x, final_nonzero=True)) for x in (args.lengths or DEFAULT_LENGTHS)]
    delays = [",".join(parse_array(x)) for x in (args.delays or DEFAULT_DELAYS)]
    splits = [parse_range(x) for x in (args.max_split or DEFAULT_MAX_SPLITS)]
    opts = (args.layer2_packets, args.layer2_lengths, args.layer2_delays, args.layer2_max_split)
    layer2 = None
    if any(x is not None for x in opts):
        layer2 = (args.layer2_packets or "1-1", args.layer2_lengths or "114,1",
                  args.layer2_delays or "1", args.layer2_max_split or "11")
        fragment(*layer2)  # Fail fast before scanning.
    configs = []
    for addr in address_set:
        for mode, name, candidate in make_candidates(config, args.scan, addr, packets, lengths,
                                                      delays, splits, layer2, args.mask_file):
            if mode == "baseline" and addr != address_set[0]:
                continue
            configs.append((mode, name, candidate))
    # Baseline once, sampled deterministic round-robin by mode/profile (avoid prefix bias).
    if len(configs) > MAX_CANDIDATES:
        p.error(f"Exceeds safety limit {MAX_CANDIDATES} candidates; narrow custom grid")
    if not args.all and len(configs) > args.limit:
        from network_scan import balanced_sample
        baseline = configs[0]
        # balanced_sample indexes first tuple item; group by category then cycle.
        configs = balanced_sample([("baseline",) + baseline] + [(c[0],) + c for c in configs[1:]],
                                  args.limit, 2026)
        configs = [c[1:] for c in configs]
    output = (args.output or Path.home() / ".local/share/xray-finalmask-scanner" /
              ("optimize-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S"))).expanduser()
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(output, 0o700)
    results, links_rows, manifest, actual_links = [], [], [], []
    for i, (mode, profile, candidate) in enumerate(configs, 1):
        id_ = f"OPT-{i:04d}"
        candidate["inbounds"][0]["port"] = free_port()
        link = share_link(orig_link, candidate, id_, baseline=(mode == "baseline"))
        # Verify that every exported fm fragment round-trips identically to tested JSON.
        parsed_back = link_to_config(link)
        a, b = proxy(candidate), proxy(parsed_back)
        if (a["settings"] != b["settings"] or a["streamSettings"] != b["streamSettings"]):
            raise ValueError("Share link round-trip mismatch for " + id_)
        elapsed = []
        tmp = output / ".candidate.json"
        write_private_json(tmp, candidate)
        try:
            if args.dry_run:
                status, count, avg, reason = "DRY_RUN", 0, None, "not-executed"
            else:
                status, count, avg, reason = run_candidate(xray, candidate, tmp, args.url,
                                                           args.requests, args.timeout, times_out=elapsed)
                if 0 < count < args.requests:
                    status, reason = "PARTIAL", "partial-success"
        finally:
            tmp.unlink(missing_ok=True)
        info = summarize_parameters(candidate)
        row = {"id": id_, "rank": "", "protocol": scheme, "source_encoding": source_encoding,
               "mode": mode, "profile": profile,
               **info, "status": status, "successes": count, "requests": args.requests,
               "success_rate": round(count / args.requests, 5), "avg_ms": avg if avg is not None else "",
               "p95_ms": percentile95(elapsed) if elapsed else "",
               "min_ms": round(min(elapsed), 2) if elapsed else "",
               "max_ms": round(max(elapsed), 2) if elapsed else "",
               "reason": reason, "link_sha256": hashlib.sha256(link.encode()).hexdigest()}
        results.append(row)
        links_rows.append({"id": id_, "link": link})
        actual_links.append(link)
        manifest.append({"id": id_, "protocol": scheme, "source_encoding": source_encoding,
                         "profile": profile, "mode": mode,
                         "fragment_layers": json.loads(info["fragment_layers"]),
                         "finalmask": json.loads(info["finalmask_json"]) if info["finalmask_json"] else None,
                         "link_sha256": row["link_sha256"],
                         "https_timings_ms": elapsed, "status": status})
        print(f"[{i}/{len(configs)}] {id_} {mode:<9} {profile[:38]:<38} {status:<15} "
              f"{count}/{args.requests} avg={avg if avg is not None else '-'}ms p95={row['p95_ms'] or '-'}", flush=True)
    ranked = sorted(results, key=ranking)
    for rank, r in enumerate(ranked, 1):
        r["rank"] = rank if not args.dry_run else ""
    safe_csv(output / "results.csv", FIELDS, results)
    safe_csv(output / "ranked.csv", FIELDS, ranked)
    safe_csv(output / "links.csv", ["id", "link"], links_rows)
    safe_text_file(output / "links.txt", actual_links)
    safe_text_file(output / "manifest.jsonl", [json.dumps(m, ensure_ascii=False) for m in manifest])
    summary = {"dry_run": args.dry_run, "generated": len(results),
               "ranking_method": "success_rate desc, p95_ms asc, avg_ms asc; dry_run is unranked",
               "source_link_unchanged": True, "protocol": scheme, "source_encoding": source_encoding,
               "note": "Every ID joins results.csv, links.csv, manifest.jsonl; no actual success in dry-run"}
    winners = [r for r in ranked if not args.dry_run and r["successes"] == args.requests]
    if winners:
        best = winners[0]
        idx = results.index(best)
        safe_text_file(output / "best-link.txt", [actual_links[idx]])
        if scheme == "vless":
            safe_text_file(output / "best-vless.txt", [actual_links[idx]])
        best_cfg = configs[idx][-1]
        write_private_json(output / "best-config.json", best_cfg)
        summary["best_id"] = best["id"]
        print("Best fully successful link:", best["id"])
    else:
        print("No verified winning link (offline dry run or all candidates had failures).")
    write_private_json(output / "summary.json", summary)
    print("Results folder:", output)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        # Do not include raw credentials or URI in exception messages.
        print(f"Error ({type(exc).__name__}): {str(exc)[:160]}", file=sys.stderr)
        sys.exit(2)
