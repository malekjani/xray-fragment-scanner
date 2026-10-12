#!/usr/bin/env python3
"""Private, step-by-step interactive scanner configuration (no root)."""
from __future__ import annotations

import getpass
import sys

from network_scan import proxy
from optimize import main as optimize_main
from share_codec import link_to_config, scheme_and_encoding


def ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    response = input(f"{prompt}{suffix}: ").strip()
    return response or default


def yes(prompt: str, default=False) -> bool:
    answer = ask(prompt + (" [Y/n]" if default else " [y/N]")).strip().lower()
    if not answer:
        return default
    if answer in ("y", "yes"):
        return True
    if answer in ("n", "no"):
        return False
    raise ValueError("Expected y or n")


def choose(prompt: str, options: dict[str, str], default="1") -> str:
    print(prompt)
    for key, label in options.items():
        print(f"  {key}) {label}")
    while True:
        choice = ask("Select", default)
        if choice in options:
            return choice
        print("Invalid choice; try again.")


def ask_int(prompt: str, default: int, lo: int, hi: int) -> int:
    while True:
        response = ask(prompt, str(default))
        if response.isdigit() and lo <= int(response) <= hi:
            return int(response)
        print(f"Enter a whole number between {lo} and {hi}.")


def ask_float(prompt: str, default: float, lo: float, hi: float) -> float:
    while True:
        response = ask(prompt, str(default))
        try:
            value = float(response)
            if lo <= value <= hi:
                return value
        except ValueError:
            pass
        print(f"Enter a number between {lo} and {hi}.")


def ask_link() -> tuple[str, dict]:
    for attempt in range(3):
        print("\n[1/6] Import VLESS, VMess (AEAD or Base64 JSON) or Trojan")
        if sys.stdin.isatty():
            link = getpass.getpass("Paste share link (input hidden): ").strip()
        else:
            link = input("Paste share link: ").strip()
        try:
            cfg = link_to_config(link)
            return link, cfg
        except (ValueError, UnicodeError) as exc:
            # Errors raised by codec contain field names, never raw credentials.
            print(f"Invalid or unsupported link: {exc}")
    raise ValueError("Invalid link after 3 tries")


def csv_values(value: str) -> list[str]:
    return [v.strip() for v in value.split(";") if v.strip()]


def run_wizard() -> int:
    print("\nXray Fragment + FinalMask scanner | guided mode")
    print("Private links are kept off command-line arguments. Results may contain secrets.")
    link, cfg = ask_link()
    protocol, encoding = scheme_and_encoding(link)
    out = proxy(cfg)
    stream = out["streamSettings"]
    tls = stream.get("tlsSettings", stream.get("realitySettings", {}))
    print(f"Detected: {protocol.upper()} ({encoding}), {out['settings']['address']}:{out['settings']['port']}")
    print(f"Transport: {stream['network']}, security: {stream['security']}, "
          f"fingerprint: {tls.get('fingerprint','default')}")
    print(f"ECH: {'present' if tls.get('echConfigList') else 'absent'}, "
          f"FinalMask: {'present' if stream.get('finalmask') else 'absent'}")
    if encoding == "legacy-qr":
        print("Note: changed VMess legacy QR links export as VMess AEAD URI; verify client support.")

    print("\n[2/6] Choose scan family")
    family = choose("Change only Fragment/FinalMask; keep TLS, ECH, SNI and transport", {
        "1": "Fragment only (one-layer masks)",
        "2": "FinalMask presets and optional multilayer masks",
        "3": "Both; compare against untouched original (recommended)",
    }, "3")
    scan = {"1": "fragment", "2": "finalmask", "3": "both"}[family]
    args = ["--scan", scan]

    print("\n[3/6] Connection address")
    if yes("Try additional IPs/hosts?", False):
        values = csv_values(ask("Address candidates separated by semicolons"))
        if values and yes("Include the original hostname in candidates?", True):
            values.insert(0, out["settings"]["address"])
        for value in values:
            args += ["--ip", value]
    print("(ECH, SNI, fingerprint, WS Host and path are preserved.)")

    print("\n[4/6] Fragment parameters")
    mode = choose("Select parameter source", {
        "1": "Recommended defaults and PattNG presets",
        "2": "Enter my own packets, lengths, delays and maxSplit ranges",
    }, "1")
    if mode == "2":
        values = (
            ("--packets", "packets values (semicolon separated; e.g. tlshello;1-2)", "tlshello;1-2"),
            ("--lengths", "lengths arrays (semicolon separated; e.g. 0,104,1;6,98,1)", "0,104,1;6,98,1"),
            ("--delays", "delays arrays (semicolon separated; e.g. 0;1-5)", "0;1-5"),
            ("--max-split", "maxSplit values (semicolon separated; e.g. 0;2-4)", "0;2-4"),
        )
        for flag, question, default in values:
            for value in csv_values(ask(question, default)):
                args += [flag, value]
    if scan in ("finalmask", "both") and yes("Add a custom second fragment layer?", False):
        for flag, question, default in (
            ("--layer2-packets", "Second-layer packets", "1-1"),
            ("--layer2-lengths", "Second-layer lengths", "114,1"),
            ("--layer2-delays", "Second-layer delays", "1"),
            ("--layer2-max-split", "Second-layer maxSplit", "11"),
        ):
            args += [flag, ask(question, default)]
    if scan in ("finalmask", "both") and yes("Import a custom FinalMask JSON profile from file?", False):
        args += ["--mask-file", ask("JSON file path")]

    print("\n[5/6] Test settings")
    count = ask_int("Requests per candidate", 5, 1, 100)
    timeout = ask_float("Timeout per request (seconds)", 8.0, 0.1, 120)
    limit = ask_int("Max candidates (includes original)", 25, 1, 100000)
    args += ["--requests", str(count), "--timeout", str(timeout), "--limit", str(limit)]
    offline = yes("Generate links/tables only, without actual network tests?", False)
    if offline:
        args.append("--dry-run")

    print("\n[6/6] Ready")
    print(f"Protocol: {protocol.upper()} | scan: {scan} | requests: {count} | "
          f"max candidates: {limit} | mode: {'DRY RUN' if offline else 'LIVE'}")
    print("Exports: results.csv, ranked.csv, links.csv, links.txt, manifest.jsonl")
    if not yes("Start scan and export now?", True):
        print("Cancelled; no scan files were created.")
        return 0
    return optimize_main(args, link_override=link)


if __name__ == "__main__":
    try:
        sys.exit(run_wizard())
    except (KeyboardInterrupt, EOFError):
        print("\nCancelled.")
        sys.exit(130)
    except (ValueError, OSError) as exc:
        print(f"Error: {type(exc).__name__}: {str(exc)[:180]}", file=sys.stderr)
        sys.exit(2)
