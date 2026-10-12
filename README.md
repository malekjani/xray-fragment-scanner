# Xray Finalmask Scanner

A Bash-based scanner for testing Xray fragment combinations. It supports three modes:

1. `finalmask-fragment`
2. `finalmask-header-custom + fragment`
3. `legacy-fragment`

The current `finalmask-header-custom + fragment` mode uses a fixed `header-custom` layer and scans the fragment parameters only:

- `packets`
- `length`
- `delay`
- `maxSplit`

UDP noise, browserDialer, and header-profile scanning are intentionally left for future development.

## Project structure

```text
xray-finalmask-scanner/
├── bin/
│   └── xray-finalmask-scanner
├── lib/
│   ├── checks.sh
│   ├── config.sh
│   ├── env.sh
│   ├── options.sh
│   ├── scanner.sh
│   ├── ui.sh
│   └── xray.sh
├── profiles/
│   └── header-custom-default.json
├── examples/
│   └── finalmask-header-custom-fragment.example.json
├── docs/
│   ├── ARCHITECTURE.md
│   ├── DEVELOPMENT.md
│   ├── ROADMAP.md
│   └── USAGE.md
├── scripts/
│   └── xray-fragment-scanner-single-file.sh
├── logs/
├── .gitignore
└── README.md
```

## Requirements

- Linux
- root access for stopping/restoring the Xray service
- `curl`
- `jq`
- `python3`
- `awk`, `sort`, `head`, `cut`, `sed`, `grep`

Install common dependencies on Debian/Ubuntu:

```bash
sudo apt update
sudo apt install -y curl jq python3
```

## Run

```bash
chmod +x bin/xray-finalmask-scanner
sudo ./bin/xray-finalmask-scanner
```

If `config.json` does not exist in the project root, the scanner asks for a VLESS link and generates it.

## Modes

### 1. finalmask-fragment

Adds only `finalmask.tcp.fragment` and scans fragment combinations.

### 2. finalmask-header-custom + fragment

Adds this TCP chain:

```text
finalmask.tcp[0] = header-custom
finalmask.tcp[1] = fragment
```

The `header-custom` layer is fixed in this version. Fragment parameters are scanned.

### 3. legacy-fragment

Uses the older `dialerProxy = fragment` style and scans legacy fragment combinations.

## Runtime files

Generated files are ignored by Git:

```text
config.json
config.json.backup-before-fragment-scanner
logs/pings.txt
logs/xraylogs.txt
logs/xraylogs.error.txt
```

## Development status

Current version:

- Works as a modular version of the previous single-file script
- Adds a separate mode for `finalmask-header-custom + fragment`
- Keeps the single-file version under `scripts/` for backup/reference

Planned later:

- Header profile scanner
- UDP noise config generation and UDP benchmark
- browserDialer mode
- CLI flags for non-interactive use

## New: network-aware IP/ECH and IP/FinalMask scans (2026-10)

The original three fragment modes remain in the ZIP. Two **additional**
non-root modes were added; use `./bin/xray-finalmask-scanner` and choose
option 2 or 3. They do not auto-install Xray, stop systemd, or overwrite
`config.json`. The new scanner takes VLESS URLs (including long `encryption=`,
`ech=`, and `fm=` fields) and preserves SNI, WebSocket Host, and path while
varying the actual address.

1. **Rightel/MCI IP + ECH**: 7 Cloudflare IPs × 18 ECH DNS choices; `chrome`
   fingerprint. It removes the previous FinalMask in this mode for isolation.
2. **Irancell IP + TLS/FinalMask**: 7 IPs × mask profiles × cipher profiles;
   `unsafe` fingerprint. Supports exact PattNG exports via `--finalmask-json`
   and `--cipher-file`. The included approximate preset is **not** guaranteed
   identical to PattNG's `tlshello-0-len` / `real_firefox_cipherSuites`.

Both modes record actual proxied HTTPS success rates, require 100% success
before naming a best candidate, and write private `results.csv` and
`best-config.json`. See [docs/NETWORK_SCAN.md](docs/NETWORK_SCAN.md).

## New (October 2026): flexible IP/ECH + exact PattNG presets

The non-root network experiments are available from menu choices **2** and
**3**, or using `./bin/xray-finalmask-scanner --method ech` and
`--method irancell`. Candidate addresses can be a custom IP/hostname/CIDR
list; ECH can come directly from `ech=` in a VLESS link, a custom full ECH
expression, lookup domain × resolver URI combinations, or an opt-in sample
list. The previously shared seven IPs and eighteen resolvers are **examples**,
not a hardcoded scanner limit or a compatibility guarantee. The exact PattNG
`tlshello-0-len`, `tlshello`, and `real-firefox-cipherSuites` presets are
included. They have been checked against supplied PattNG code and current
upstream Xray documentation.

See [docs/NETWORK_SCAN.md](docs/NETWORK_SCAN.md) for CLI options, examples,
Xray 2026 compatibility notes and testing caveats. Network experiments do not
need `sudo` and do not restart the system's Xray service; the original
fragment scanner (menu choice 1) still needs root for its old workflow.

## Optimize a VLESS link: reproducible fragment / FinalMask scans

New menu **4** or `--method optimize` scans **one-layer Fragment**, **multiple-layer FinalMask**,
(or both) using the modern Xray `streamSettings.finalmask.tcp` schema. It **does not silently
rewrite ECH, TLS fingerprint, SNI, encryption, transport, WebSocket Host/path, certificate
pins, or other share-link values**. Only the chosen Fragment layers are replaced; existing
non-fragment FinalMask TCP layers and its UDP/QUIC layers are retained. Unsupported share-link
fields and duplicate query keys fail closed rather than yielding misleading benchmarks.

The share-link standard has an `fm` field, **not a portable legacy freedom.fragment link
parameter**. Consequently `--scan fragment` creates one FinalMask fragment layer with the
corresponding importable `fm` share-link. The old `freedom.fragment` scanner remains option 1.

```bash
# Put your own VLESS URI in a private input file, not in shell history.
chmod 600 ~/private-vless.txt
./bin/xray-finalmask-scanner --method optimize \
  --link-file ~/private-vless.txt --scan both --requests 5 --limit 25

# Explicit Xray lengths/delays arrays; optional second layer:
./bin/xray-finalmask-scanner --method optimize \
  --link-file ~/private-vless.txt --scan both \
  --packets tlshello --lengths '0,104,1' --lengths '6,98,1' \
  --delays '0' --delays '1,1-5' --max-split 0 \
  --layer2-packets '1-1' --layer2-lengths '114,1' \
  --layer2-delays '1' --layer2-max-split '11' --all

# Offline candidate/link generation, no connectivity claims:
./bin/xray-finalmask-scanner --method optimize \
  --link-file ~/private-vless.txt --dry-run --limit 20
```

The private output directory (`~/.local/share/xray-finalmask-scanner/optimize-*`, permissions
`0700`) contains `results.csv`, `ranked.csv`, `links.csv`, `links.txt`, `manifest.jsonl`,
and `summary.json` (`0600`). Each `OPT-XXXX` ID joins **the actual tested JSON values,
per-request successful HTTPS timings, the complete modified VLESS URI, and SHA-256 of the URI**.
`fragment_layers` contains exact arrays (`packets`, `lengths`, `delays`, `maxSplit`) for
all layers. HTTPS success rate, mean, P95 and min/max are reported; this is **not ICMP ping**.
The best fully successful candidate produces `best-vless.txt` and `best-config.json`.
`--dry-run` generates all sampled links without claiming successful tests or naming a winner.

Read [docs/OPTIMIZE.md](docs/OPTIMIZE.md) before distributing links or interpreting results.
