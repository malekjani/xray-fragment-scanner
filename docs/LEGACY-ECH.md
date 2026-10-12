# Legacy ECH preservation and Irancell safe default / حفظ ECH در حالت‌های قدیمی

## فارسی

- تبدیل‌کنندهٔ Bash قدیمی برای VLESS در `lib/config.sh` اکنون پارامترهای `ech`، `fp`، `alpn`، `cs`، `pcs`، `vcn` و `fm` را می‌خواند و در `tlsSettings` / `finalmask` قرار می‌دهد.
- در حالت `legacy-fragment`، مقدار `sockopt.dialerProxy=fragment` اضافه می‌شود ولی ECH و تنظیمات TLS لینک اصلی حذف نمی‌شوند. این **به معنای تضمین اتصال** یا تضمین سازگاری همهٔ Coreها نیست.
- حالت `irancell` در `network_scan.py` به‌صورت پیش‌فرض **فقط Address و Fragmentهای TCP FinalMask** را تغییر می‌دهد. Fingerprint و ECH اصلی حفظ شده و لایه‌های TCP غیر Fragment، UDP و `quicParams` نیز حفظ می‌شوند.
- `--tls-profile pattng-unsafe` حالت آزمایشی **اختیاری** است؛ Fingerprint را به `unsafe` تبدیل کرده و مجموعه رمزهای `native-default` / `pattng-real-firefox` را تست می‌کند، اما ECH را پاک نمی‌کند. افزودن `--cipher-file` مستلزم همین انتخاب صریح است.
- در اسکن ECH نیز Fingerprint اصلی به‌صورت پیش‌فرض حفظ می‌شود؛ `--ech-chrome` آن را به Chrome تغییر می‌دهد. FinalMask دیگر به‌صورت مخفی حذف نمی‌شود.
- در حالت اسکن شبکه، فایل‌های `results.csv`, `ranked.csv`, `links.csv`, `links.txt`, `manifest.jsonl` ذخیره می‌شوند. هر کانفیگ قبل از اجرا به لینک تبدیل و دوباره Parse می‌شود. `best-link.txt` فقط با موفقیت واقعی همهٔ درخواست‌های تست ایجاد می‌شود.
- روش Bash تاریخی همچنان نیازمند `sudo` و ممکن است سرویس Xray سیستم را متوقف و نسخهٔ Xray را نصب/به‌روزرسانی کند. برای تست امن‌تر و لینک خروجی کامل، `optimize` یا `--method irancell` توصیه می‌شود.

```bash
# بررسی سریع و آفلاین — بدون Xray یا دسترسی root
./bin/xray-finalmask-scanner --method irancell --link-file ~/private-link.txt \
  --ip example.net --dry-run --all --no-prompt --output ~/test-irancell

# تست واقعی روی شبکهٔ خودتان
./bin/xray-finalmask-scanner --method irancell --link-file ~/private-link.txt \
  --ip example.net --requests 5 --timeout 10 --limit 12 --no-prompt

# تست عمداً با Fingerprint=unsafe و Cipher Suites مربوط به PattNG
./bin/xray-finalmask-scanner --method irancell --link-file ~/private-link.txt \
  --ip example.net --tls-profile pattng-unsafe --requests 5 --no-prompt
```

## English

The legacy Bash VLESS decoder now retains `ech`, `fp`, `alpn`, `cs`, `pcs`, `vcn` and an existing `fm`. The `freedom.fragment` dialer is added without silently dropping the input ECH or TLS settings. This historical path still requires root and can affect the system-wide Xray service; use the non-root Python modes for safe comparative testing and share-link export.

By default, the historical `--method irancell` scan **preserves the input ECH, fingerprint, TLS settings, WebSocket settings, non-Fragment TCP layers, UDP layers and QUIC parameters**. It varies the tested address and TCP fragment mask only. The native TLS/cipher experiment is explicitly enabled with `--tls-profile pattng-unsafe`; this **does not remove ECH**. A custom `--cipher-file` requires that explicit profile selection. The IP/ECH mode similarly preserves the source fingerprint and FinalMask unless `--ech-chrome` is requested.

All new network scan results have traceable `NET-0001`-style IDs, exact FinalMask and fragment parameters, verified VLESS share URIs, SHA-256 digests and CSV/JSONL analytics. A dry run does not prove connectivity or pick a winner.

## Regression checks

- `tests/test_legacy_ech.py` validates Bash VLESS generation in Legacy/FinalMask modes and single-decoding of percent escapes.
- `tests/test_network_scan.py` validates the new preserve-by-default behavior, opt-in unsafe, and non-Fragment layer preservation.
- `tests/test_live_exports.py` validates the generated VLESS share-link round-trip, CSV/manifest join and private file permissions.

Upstream references: [FinalMask](https://github.com/XTLS/Xray-docs-next/blob/main/docs/en/config/transports/finalmask.md) and [TLS/ECH](https://github.com/XTLS/Xray-docs-next/blob/main/docs/en/config/transports/tls.md).
