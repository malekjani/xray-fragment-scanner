# Full English guide — Xray Fragment Scanner V8

> **V8 experimental release.** CLI and Web share the same FinalMask instance table. [Home](../README.md) · [فارسی](README.fa.md) · [Ranking](RANKING.md) · [Live benchmarking](LIVE-BENCHMARK.md)

## Quickstart (Debian)

```bash
sudo apt update && sudo apt install -y python3 curl ca-certificates unzip
cd ~/xray-fragment-scanner
chmod +x bin/xray-finalmask-scanner
./bin/xray-finalmask-scanner --web
```

Open `http://127.0.0.1:8765` on the same device. Running without CLI arguments opens the existing interactive wizard; to use the V8 experimental engine use the web UI or `--method v8`. The system Xray service is not replaced.

## Modes and configuration

**Auto** samples the untouched baseline first, then selects one **fixed** initial matrix; it does not refine candidates progressively. **Expert** builds a finite matrix from four independent axes: `addresses`, `ech_values`, `fingerprints` and ordered `mask_profiles`. The original URI fields remain unchanged unless explicitly selected.

| Expert setting | Example | Meaning |
|---|---|---|
| `addresses` | `["original", "203.0.113.10"]` | Alternate dial address; preserve unrelated SNI and Host |
| `ech_values` | `["original", "none"]` | Preserve ECH, explicitly remove, or supply a full ECHConfig value |
| `fingerprints` | `["original", "firefox", "chrome"]` | Test TLS uTLS fingerprints; some TLS settings may be overridden |
| `mask_profiles` | `"original"` or object with `layers` | Ordered inner-to-outer TCP FinalMask layers |
| `fragment.settings.packets` | `"tlshello"`, `"1-2"` | ClientHello or TCP-write range |
| `fragment.settings.lengths` | `["6", "98", "1"]` | Bytes in sequential fragments; last element repeats |
| `fragment.settings.delays` | `["0", "1-5"]` | Millisecond delays per fragment |
| `fragment.settings.maxSplit` | `"0"`, `"3-6"` | Fragment count cap; zero is unlimited |
| `header-custom` | `clients`, `servers`, `errors` | TCP FinalMask packet manipulation, **not** WebSocket Host header |
| `stage1_requests` | `5` | HTTPS requests per discovery candidate |
| `stage2_requests` | `25` | Requests per shortlisted verification candidate |
| `verify_top` | `5` | Candidate count in second stage |
| `baseline_every` | `5` | Rerun untouched control every N candidates |
| `min_success` | `0.90` | Verification threshold (not a connectivity guarantee) |
| `seed` | `2026` | Reproducible shuffled order |
| `targets` | `https://...` | One to five HTTPS probe URLs |
| `throughput_url` | `null` or HTTPS URL | Optional download target capped at 5 MiB |
| `timeout` | `8` | Per-request timeout in seconds |
| `max_candidates` | `60` | Explicit matrix budget; oversize matrices error, not silently truncated |

**Compatibility:** `lengths[]` and `delays[]` require a recent FinalMask implementation, selected from the latest verified official pre-release. TCP FinalMask is not a QUIC/UDP masking mechanism. Browser Dialer is deliberately disabled in automated V8 scans: custom Host/SNI/TLS parameters become ineffective or conflicting under a real-browser connection. A valid JSON file does not prove effective on-wire behavior.

## Results and privacy

- `results.csv`, `ranked.csv`: exact Fragment/FinalMask settings and per-candidate score.
- `links.csv`, `links.txt`: the corresponding complete share URI for each candidate ID.
- `probes.csv`, `history.sqlite3`: individual HTTP outcomes, latency phases and locally stored history.
- `manifest.jsonl`: exact mask, SHA-256 and compatibility metadata.
- `verified-links.txt`, `provisional-links.txt`: distinct status-labeled exports; `VERIFIED` is a measurement threshold, not permanent availability.
- `summary.json`, `excluded.json`: scan summary and excluded incompatible combinations.

See [ranking methodology](RANKING.md) and [warm/live benchmark guide](LIVE-BENCHMARK.md) for precise current semantics. Keep all credentials and results private (`0700` directories, `0600` files).

---

# V8 architecture, examples and constraints

# Xray Fragment Scanner V8 — Experimental release

> V8 source is available on GitHub. Progressive Scanning is intentionally postponed to V9.

## Quick start on Debian

```bash
sudo apt update && sudo apt install -y python3 curl ca-certificates unzip
./bin/xray-finalmask-scanner --web
```

The dashboard runs exclusively on `http://127.0.0.1:8765`. Connect remotely using SSH local forwarding, never a public bind. CLI offline preview:

```bash
umask 077
printf '%s\n' 'vless://YOUR_PRIVATE_LINK' > ~/scanner-link.txt
chmod 600 ~/scanner-link.txt
./bin/xray-finalmask-scanner --method v8 \
  --link-file ~/scanner-link.txt --spec examples/v8-expert-matrix.json \
  --dry-run --output ~/v8-offline
```

## Features

- **Auto** chooses a *fixed* small FinalMask candidate set once after measuring the unmodified source baseline. **Expert** exhaustively constructs a user-bounded matrix of selected address, ECH, fingerprint and ordered TCP FinalMask layers.
- Unselected URI properties are preserved. Every candidate gets a unique ID, private share link, link SHA256, exact candidate JSON in local SQLite, full layer arrays and round-trip validation.
- Static compatibility findings (BLOCK/WARN/INFO), plus live `xray run -test` validation against a pinned verified official pre-release.
- Two-stage Discovery/Verification, seeded shuffle, baseline at start/periodically/end, Wilson 95% lower success bound, median/P95/latency dispersion and opt-in capped HTTPS download test.
- Results in SQLite, CSV, manifest JSONL, exact share links, and separated Verified/Provisional lists. `VERIFIED` is a measured threshold label, never an availability guarantee.
- Local-only dashboard, per-session token protection and no external browser assets. The link never appears in public event logs. Files use restrictive modes.

## Expert spec

See [`examples/v8-expert-matrix.json`](../examples/v8-expert-matrix.json) for the supported fields and a fully editable Header-Custom + Fragment pipeline. `original` preserves that field, `ech_values: ["none"]` deliberately removes ECH, and `mask_profiles.layers` sets the ordered inner-to-outer FinalMask TCP sequence. A Header-Custom FinalMask TCP layer is **not** a WebSocket Host header.

## Compatibility limits

- Browser Dialer automatic benchmarking is disabled: a real browser, direct routing, CORS and Browser TLS behavior are required; Xray TLS ECH/fingerprint fields may not be effective there.
- TCP FinalMask is not suitable for UDP-only transports such as QUIC/Hysteria; REALITY restrictions and TLS/ECH requirements are checked.
- uTLS fingerprint behavior may override some TLS fields. A zero early `tlshello` length may emit an empty TLS record and break connections.
- JSON validation does not prove on-wire effectiveness. No DPI root cause claim is made from timeouts alone.
- Throughput targets are opt-in and limited to 5 MiB response download by curl.
- An official pre-release is discovered and SHA256-verified at **scan start**, then pinned for that scan. No system Xray service is modified.

## V8 limitations

**Not yet field-verified** on your Debian network, no automatic Browser Dialer workflow, no progressive/exhaustive search beyond user-defined matrix budget, and no guarantee of superior throughput. Checkpoints persist to SQLite, but automatic restart/resume is not yet implemented. This is a functional local engineering draft for validation, not a production release.

Upstream sources: [FinalMask](https://github.com/XTLS/Xray-docs-next/blob/main/docs/en/config/transports/finalmask.md), [TLS](https://github.com/XTLS/Xray-docs-next/blob/main/docs/en/config/transports/tls.md), [Browser Dialer](https://github.com/XTLS/Xray-docs-next/blob/main/docs/en/config/features/browser_dialer.md).
