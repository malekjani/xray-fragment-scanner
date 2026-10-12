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


## October 2026: flexible ECH/IP scanning and exact PattNG presets

Network scanner modes 2 (ECH) and 3 (FinalMask/unsafe/Firefox ciphers) now
accept arbitrary IPs, hostnames, CIDR files, full ECH values or combinations
of ECH domains and resolvers. The old 7 IPs and 18 DNS addresses are optional
examples, not hardcoded limits. Exact PattNG `tlshello-0-len`, `tlshello`,
and `real-firefox-cipherSuites` presets are included.
Use `--no-prompt` for automation and see
[docs/NETWORK_SCAN.md](docs/NETWORK_SCAN.md) for examples, privacy and
upstream compatibility. Mode 1 is still the legacy root-required workflow;
modes 2 and 3 do not touch system services.
