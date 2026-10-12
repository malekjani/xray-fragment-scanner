# Latest official Xray-core pre-release / جدیدترین نسخهٔ آزمایشی رسمی Xray

## فارسی

**رفتار پیش‌فرض همهٔ تست‌های واقعی:** برنامه در هر نوبت اجرا فهرست انتشارهای رسمی
`XTLS/Xray-core` را از GitHub می‌خواند، جدیدترین انتشار دارای `prerelease=true`
را انتخاب و فایل مناسب معماری لینوکس را دریافت می‌کند. فایل ZIP قبل از اجرا
با اندازه و `SHA-256 digest` اعلام‌شده در متادیتای انتشار رسمی بررسی می‌شود.

- مسیر نصب: `~/.local/share/xray-finalmask-scanner/cores/<tag>/xray`
- بدون `sudo`، بدون دست‌کاری `/usr/local/bin/xray` یا سرویس‌های `systemd`
- اگر نسخهٔ منتخب قبلاً نصب و اعتبارسنجی شده باشد، از Cache استفاده می‌شود.
- اگر GitHub در دسترس نباشد **تست واقعی متوقف می‌شود** و برنامه بدون اعلام به کاربر
  به نسخهٔ پایدار قدیمی برنمی‌گردد. امکان override دستی با `--xray /path` وجود دارد.
- `--dry-run` هیچ دانلود و دسترسی به GitHub انجام نمی‌دهد و صرفاً کانفیگ، لینک و جدول می‌سازد.
- این روش فقط نسخه‌ای را که Xray-core **Pre-release** نام‌گذاری کرده انتخاب می‌کند؛
  نسخهٔ جدیدتر لزوماً بهتر یا پایدارتر نیست و کاربر باید روی شبکهٔ خودش تست کند.

در تاریخ ۱۲ اکتبر ۲۰۲۶ جدیدترین Pre-release منتشرشدهٔ GitHub برابر
`v26.10.10` است؛ این مقدار در اسکریپت hardcode نشده و از API خوانده می‌شود.
در `v26.3.27` پارامتر Fragment داخل FinalMask به شکل `length` و `delay` است،
اما `v26.10.10` ساختار آرایه‌ای `lengths` و `delays` را می‌پذیرد. این تفاوت
علت `LengthMin can't be 0` هنگام استفاده از اسکنر جدید روی نسخهٔ پایدار قدیمی بود.

### دستورات روی Debian

```bash
sudo apt update && sudo apt install -y python3 curl git ca-certificates
cd ~/xray-fragment-scanner
git pull --ff-only

# نمایش برچسب جدیدترین Pre-release از GitHub
./bin/xray-finalmask-scanner --latest-core

# دانلود/بررسی SHA-256 و نصب در فضای کاربر (فقط در صورت نیاز)
./bin/xray-finalmask-scanner --update-core

# منوی تعاملی: VLESS / VMess / Trojan؛ تمام تست‌های زنده با Core آزمایشی
./bin/xray-finalmask-scanner

# بازآزمایی کانفیگ‌های ذخیره‌شده بدون آزمون اتصال
./bin/xray-finalmask-scanner --diagnose \
  "$HOME/.local/share/xray-finalmask-scanner/optimize-20261012-164558"

# خروجی کانفیگ و لینک بدون نیاز به Core یا دانلود
./bin/xray-finalmask-scanner --method optimize \
  --link-file ~/private-link.txt --scan both --dry-run
```

### امنیت و محدودیت‌ها

فایل‌های خروجی `links.csv` و `best-link.txt` حاوی اطلاعات خصوصی هستند.
فهرست انتشار فقط از مخزن رسمی GitHub خوانده می‌شود و فایل باینری فقط وقتی
اجرا می‌شود که SHA-256 و نسخهٔ داخل باینری مطابق متادیتای انتخاب‌شده باشند.
تأیید نسخهٔ برنامه به معنای موفقیت اتصال یا اعتبار کانفیگ نیست؛ هر کانفیگ باید
با `xray run -test` و سپس با درخواست‌های HTTPS آزمایش شود.

**Legacy تاریخی:** `--legacy-menu` دیگر به‌صورت ضمنی نصب Stable یا توقف سرویس
سیستم را اجرا نمی‌کند. برای اجرای workflow قدیمی مدیریتی فقط با انتخاب آگاهانه
`sudo ./bin/xray-finalmask-scanner --legacy-system-mode` اقدام کنید؛ همچنان
ممکن است سرویس جاری را موقتاً متوقف کند، ولی Core انتخابی آن هم Pre-release است.
برای تست گرم و لینک‌های قابل اشتراک از Wizard یا `--method optimize` استفاده کنید.

## English

All **live** `optimize`, `ech`, `irancell`, and `--diagnose` executions now select
**the newest published official prerelease** of `XTLS/Xray-core`, not GitHub's
`/releases/latest` stable endpoint or the operating system's installed Xray.
The selector queries the official releases API on each live run, validates the
platform-specific archive's official `sha256:` digest and byte size, and
verifies `xray version` before caching or executing its extracted binary.

The program uses a private, versioned per-user cache, **does not overwrite the
system Xray**, and never runs a remote installer shell script. A live run fails
closed when official release metadata is unavailable. Manual `--xray` overrides
are intended for explicit development and reproducibility. Offline `--dry-run`
needs neither GitHub nor Xray. Existing cached binaries are reused only when
they match the selected tag and recorded digest and pass a binary version check.

```bash
./bin/xray-finalmask-scanner --latest-core  # query latest prerelease tag
./bin/xray-finalmask-scanner --update-core  # ensure SHA256-verified core
./bin/xray-finalmask-scanner                # guided scan
./bin/xray-finalmask-scanner --method optimize --link-file ~/private-link.txt --dry-run
```

**Compatibility:** Stable `v26.3.27` implements the older scalar FinalMask
`length`/`delay` structure; prerelease `v26.10.10` implements the array-based
`lengths`/`delays` structure required by the scanner's current preset generator.
Always verify imported `fm` links on your destination client as well.

Source of truth: [Official Xray-core releases](https://github.com/XTLS/Xray-core/releases),
[FinalMask configuration](https://github.com/XTLS/Xray-docs-next/blob/main/docs/en/config/transports/finalmask.md).
