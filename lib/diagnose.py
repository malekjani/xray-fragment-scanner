#!/usr/bin/env python3
"""Compare Xray config validation for existing baseline and masked share links.

No live requests and no need to re-enter credentials; reads a prior private
links.csv, rebuilds configs, and runs xray run -test -c. Core diagnostics are
stored in a user-only file. Never prints URLs, UUIDs, passwords or raw errors.
"""
from __future__ import annotations

import argparse
import csv
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from network_scan import free_port, write_private_json
from share_codec import link_to_config
from xray_errors import classify


def choose_rows(rows):
    selected = []
    if rows:
        selected.append(rows[0])
    for row in rows[1:]:
        if not selected or row.get("id") != selected[0].get("id"):
            selected.append(row)
            break
    return selected


def run_validation(xray: str, link: str):
    cfg = link_to_config(link)
    cfg["inbounds"][0]["port"] = free_port()
    with tempfile.TemporaryDirectory(prefix="xray-scan-check-") as tmp:
        config_path = Path(tmp) / "candidate.json"
        write_private_json(config_path, cfg)
        try:
            p = subprocess.run([xray, "run", "-test", "-c", str(config_path)],
                               text=True, capture_output=True, timeout=15)
            return p.returncode == 0, (p.stderr or "") + "\n" + (p.stdout or "")
        except subprocess.TimeoutExpired:
            return False, "Core config test timed out after 15 seconds"


def main(argv=None):
    p = argparse.ArgumentParser(description="Validate saved candidate links locally without network probes")
    p.add_argument("results", type=Path, help="Previous optimize-* folder with links.csv")
    p.add_argument("--xray", help="Path to an Xray binary (default: search PATH)")
    args = p.parse_args(argv)
    xray = args.xray or shutil.which("xray") or "/usr/local/bin/xray"
    if not (shutil.which(xray) or os.path.isfile(xray)):
        p.error("Xray binary was not found; pass --xray /path/to/xray")
    folder = args.results.expanduser().resolve()
    path = folder / "links.csv"
    if not path.is_file():
        p.error("No links.csv found in this results folder")
    with path.open(encoding="utf-8", newline="") as fh:
        rows = choose_rows(list(csv.DictReader(fh)))
    if not rows:
        p.error("links.csv has no rows")
    version = subprocess.run([xray, "version"], capture_output=True, text=True, timeout=10)
    print("Xray binary:", xray)
    print("Xray version:", (version.stdout.splitlines() or ["unknown"])[0][:180])
    logs = [f"Core: {xray}", f"Version: {version.stdout[:800]}"]
    for idx, row in enumerate(rows, 1):
        ok, diagnostic = run_validation(xray, row["link"])
        category = "valid" if ok else classify(diagnostic)
        print(f"{row.get('id', 'candidate')}: {'VALID' if ok else 'INVALID'} / {category}")
        logs.append(f"\n{'='*20} {row.get('id', idx)} {'='*20}\n{diagnostic[:16000]}")
    report = folder / "xray-diagnose.log"
    fd = os.open(report, os.O_WRONLY | os.O_TRUNC | os.O_CREAT, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write("\n".join(logs))
    os.chmod(report, 0o600)
    print("Private original Xray errors:", report)
    print("Do not share the raw report without removing connection credentials.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError) as e:
        # Don't echo link parse errors that might contain credentials.
        print("Diagnosis could not finish:", type(e).__name__, file=sys.stderr)
        sys.exit(2)
