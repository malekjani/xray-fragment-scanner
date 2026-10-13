# Xray Fragment & FinalMask Scanner

**V8 — FinalMask Results Table / جدول کامل فاینال‌مسک**

Local Xray-core experimentation for **VLESS / VMess / Trojan**: build combinations, validate, benchmark and export **the exact share link for each tested configuration**.  
ابزار آزمایش محلی Xray: ساخت ترکیب‌های ECH، Fingerprint، Fragment و Header-Custom، کنترل سازگاری، تست واقعی و ذخیرهٔ لینک دقیق هر آزمایش.

**[راهنمای فارسی](docs/README.fa.md)** · **[English guide](docs/README.en.md)** · [Expert matrix](docs/README.en.md) · [Ranking / رتبه‌بندی](docs/RANKING.md) · [Live testing / تست گرم](docs/LIVE-BENCHMARK.md)

## Quickstart · شروع سریع (Debian)

Clone or update this repository on Debian / نصب یا به‌روزرسانی از مخزن در Debian:

```bash
sudo apt update && sudo apt install -y python3 curl ca-certificates unzip
git clone https://github.com/malekjani/xray-fragment-scanner.git
cd xray-fragment-scanner
chmod +x bin/xray-finalmask-scanner
./bin/xray-finalmask-scanner --web
# Open http://127.0.0.1:8765 on the same Debian computer
```

**CLI / خط فرمان:** `./bin/xray-finalmask-scanner` now opens the V8 table-based interactive wizard. To run the previous V7 wizard use `--v7-wizard`. A FinalMask-only CLI scan with a private URI file:

```bash
./bin/xray-finalmask-scanner --method v8 \
  --link-file ~/private-link.txt --spec examples/v8-finalmask-only.json \
  --dry-run --output ~/v8-preview
```

The link file must contain **your real link** on one line and have `chmod 600` permissions; do **not** put credentials in your shell history. `--dry-run` generates configurations and exports without running network tests. / برای تست آفلاین نیازی به Xray یا اتصال به سرور نیست.

## What it does · امکانات

| Feature / قابلیت | V8 behavior / رفتار |
|---|---|
| Web dashboard / پنل وب | Loopback-only `127.0.0.1:8765`, session token, live progress and parameter glossary |
| Auto | Selects a **fixed** initial matrix informed by baseline; **not progressive** |
| Expert | FinalMask-only (preserve ECH/FP/IP) or ECH × Fingerprint × Address × ordered TCP FinalMask masks |
| FinalMask | TCP `fragment` and `header-custom` layers, including multi-layer sequences |
| Compatibility | `lib/compatibility/`: Xray-version gating, BLOCK/WARN/INFO, Experimental labels, real core smoke checks, requested/generated/effective preview |
| Benchmark | Discovery and verification, periodic baseline, seeded shuffle, multi-target HTTPS, optional capped download; selectable Best Performance / Reliability / Balanced / Latency |
| Analytics | Success rate, Wilson lower bound, median, P95, jitter, link/config SHA-256 |
| Export | Screenshot-style instance table in console + web + `finalmask-instances.csv`, `top-three-lowest-average.csv`, `finalmask-table.txt`; SQLite, JSONL and exact links |
| Xray core | Official SHA-256-verified newest **pre-release** pinned at scan start; no system service change |

## FinalMask-only benchmark table · جدول کامل تست فاینال‌مسک

The terminal and web panel display the **same eight columns**: Instance, Packets, Length, Delay, Max Split, Average Response (ms), Success and Status. The complete table preserves Instance order; a separate table lists the **three lowest measured average response times**. Multi-layer settings are written in ordered ` / ` notation. **Average Response measures proxied HTTPS, not ICMP ping.** Candidates which passed screening but not verification remain marked SCREENED and are **not** verified winners.

The bundled `examples/v8-finalmask-only.json` shows fifteen configurable Fragment patterns inspired by the legacy console layout. They are merely test inputs, **not validated recommendations**. In FinalMask-only mode ECH, TLS, Fingerprint, WebSocket and connection address remain unchanged. Use Combined Matrix explicitly to vary those properties.

Files: `finalmask-instances.csv` · `top-three-lowest-average.csv` · `finalmask-table.txt` · `ranked.csv` · `links.csv` (sensitive!) · `summary.json`.

## Example output · نمونهٔ خروجی

Illustrative only — **not measured network results**. / مثال نمایشی؛ حاصل تست واقعی نیست.

| ID | Change | Discovery | Verification | Status |
|---|---|---:|---:|---|
| `V8-0001` | Original / Baseline | 5/5 | 25/25 | VERIFIED (threshold passed) |
| `V8-0002` | ECH + Firefox + Fragment | 4/5 | 23/25 | VERIFIED (if threshold is 90%) |
| `V8-0003` | Header-Custom + Fragment | 1/5 | — | FAILED / SCREENED |

For every candidate, `links.csv` maps **ID → complete share URI**; `results.csv`, `probes.csv`, `manifest.jsonl` and the local SQLite database preserve parameters and evidence. `VERIFIED` means a test threshold was passed, **not** guaranteed future connectivity.

## Guides · مستندات

- **[راهنمای کامل فارسی](docs/README.fa.md)** — نصب Debian، پنل، Expert، ECH، Fingerprint، FinalMask و پارامترها.
- **[Full English guide](docs/README.en.md)** — CLI, Web Dashboard, compatibility, parameter reference, troubleshooting.
- [Ranking methodology / الگوریتم رتبه‌بندی](docs/RANKING.md) — two stages, confidence and baseline drift.
- [Live benchmark / راهنمای تست گرم](docs/LIVE-BENCHMARK.md) — Debian prerequisites, output interpretation, secure diagnostics.
- [Pre-release core policy](docs/PRERELEASE-CORE.md) · [Wizard](docs/WIZARD.md) · [Legacy modes](docs/NETWORK_SCAN.md).
- [Changelog](CHANGELOG.md) · [V8 release notes](releases/v0.8.0.md).

## Status and boundaries · وضعیت و محدودیت‌ها

**V8 implements the fixed-matrix scanner and local dashboard.** Progressive Scanning is reserved for **V9**. Real network performance and Browser Dialer operation have **not** been field-validated on every ISP or Xray build. Browser Dialer is excluded from automated tests; resume after a terminated process is not complete.

**Privacy:** exported links may contain UUIDs, passwords, SNI and ECH information. Results live in private `0700` directories with `0600` files. Never commit exported links, JSON configs, logs or SQLite databases. The dashboard binds to localhost; for remote access use SSH forwarding instead of a public listener.

**License:** A final open-source license has not yet been approved by the repository owner. The draft MIT text is not published as an approved license. Xray-core and third-party components retain their upstream licenses.

> Expert compatibility, versioned core smoke tests and Effective Configuration Diff: see [FA V8 guide](docs/README.fa.md) and [EN V8 guide](docs/README.en.md). Full matrix remains fixed; Progressive Scanning is V9.
