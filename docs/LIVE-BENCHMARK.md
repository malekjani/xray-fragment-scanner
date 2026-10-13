# Live benchmarking on Debian / راهنمای تست گرم روی Debian

[Home](../README.md) · [فارسی](README.fa.md) · [English](README.en.md) · [Ranking](RANKING.md)

## فارسی

**۱. پیش‌نیازها:** `python3`, `curl`, `ca-certificates` و دسترسی اینترنت برای دانلود **Pre-release رسمی** Xray-core؛ خود برنامه SHA-256 را بررسی و نسخهٔ انتخابی را طی همان اسکن ثابت نگه می‌دارد. Core نصب‌شدهٔ سیستم یا سرویس `systemd` تغییر نمی‌کند.

```bash
sudo apt update && sudo apt install -y python3 curl ca-certificates
cd ~/xray-fragment-scanner
./bin/xray-finalmask-scanner --latest-core
./bin/xray-finalmask-scanner --web
```

**۲. شروع امن:** لینک واقعی خود را در پنل محلی Paste کنید یا با فایل متنی خصوصی وارد کنید. برای CLI:

```bash
umask 077
# فایل ~/private-link.txt را با یک لینک خصوصی واقعی بسازید؛ هرگز لینک را در تاریخچهٔ شل وارد نکنید.
chmod 600 ~/private-link.txt
./bin/xray-finalmask-scanner --method v8 \
  --link-file ~/private-link.txt \
  --spec examples/v8-expert-matrix.json \
  --output ~/xray-v8-result
```

**۳. تأیید نتیجه:** `summary.json` و `ranked.csv` را بررسی کنید؛ با شناسهٔ `V8-XXXX` لینک متناظر را از `links.csv` پیدا کنید. `probes.csv` علت کلی شکست‌ها و زمان‌های هر درخواست را ثبت می‌کند. تنها زمانی `best-link.txt` ساخته می‌شود که آزمون Verification کامل با شرط `VERIFIED` انجام شده باشد.

**۴. خطاها:** `INVALID_CONFIG` یعنی `xray run -test` ساختار کانفیگ را نپذیرفته است؛ این وضعیت با قطع اتصال HTTPS فرق دارد. `FAILED` ممکن است از DNS، اتصال TCP، TLS/ECH، پاسخ HTTP، محدودیت ISP یا مقصد ناشی شود؛ از روی یک کد خطا علت قطعی DPI تعیین نمی‌شود. در صورت نیاز برای بررسی خروجی نسخهٔ قبلی:

```bash
./bin/xray-finalmask-scanner --diagnose \
  ~/.local/share/xray-finalmask-scanner/optimize-YYYYMMDD-HHMMSS
```

**۵. حفاظت داده:** لینک‌ها، CSV، SQLite و لاگ خام ممکن است UUID، رمز، SNI و اطلاعات خصوصی داشته باشند. همه را محلی نگه دارید و پیش از اشتراک‌گذاری ناشناس‌سازی کنید. وب‌پنل فقط `127.0.0.1` را گوش کند؛ برای دسترسی از بیرون از SSH port-forward استفاده کنید.

**محدودیت فعلی:** بدون شبکهٔ واقعی، نمی‌توان از تست واحد یا Dry Run نتیجهٔ قطعی عملکرد روی اپراتور گرفت. Browser Dialer در V8 خودکار پشتیبانی نمی‌شود. Resume کامل پس از قطع پروسه تکمیل نشده است.

## English

1. Install Debian dependencies: `sudo apt install -y python3 curl ca-certificates`. The scan manager fetches and SHA256-verifies the latest official Xray pre-release, then pins it for that scan without replacing the system binary or service.
2. Run the loopback dashboard with `./bin/xray-finalmask-scanner --web`, or use `--method v8 --link-file ~/private-link.txt --spec examples/v8-expert-matrix.json --output ~/xray-v8-result`. Use `umask 077`, `chmod 600` and keep the URI out of shell history.
3. Inspect `ranked.csv`, `summary.json`, `probes.csv` and the exact ID-to-share-link mapping in `links.csv`. Do not interpret a successful JSON parse as successful network connectivity.
4. Use `--dry-run` to inspect and export a candidate matrix **without live tests**. Distinguish `INVALID_CONFIG` (Xray rejects JSON) from DNS/TCP/TLS/HTTPS test failures. For previously generated runs the `--diagnose` command revalidates a baseline and changed candidate without repeating live probes.
5. `VERIFIED` denotes meeting this version's measured second-stage criteria, **not** uninterrupted uptime. Low-sample P95 is unstable; network drift and changing targets may distort comparisons. Retest on the actual ISP before drawing conclusions.
6. Never publish raw links, SQLite/CSV results or error logs. Use the local loopback endpoint or SSH port forwarding, not a public HTTP dashboard.

[Upstream FinalMask](https://github.com/XTLS/Xray-docs-next/blob/main/docs/en/config/transports/finalmask.md) · [Browser Dialer limitations](https://github.com/XTLS/Xray-docs-next/blob/main/docs/en/config/features/browser_dialer.md).
