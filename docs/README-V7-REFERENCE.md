> **Historical reference (V7):** Content below was the earlier comprehensive bilingual README. New V8 instructions take precedence. / مرجع قدیمی V7؛ برای V8 از راهنماهای جدید استفاده کنید.

> **V8 PRIVATE DRAFT / پیش‌نویس منتشرنشده** — این بسته از نسخهٔ V7 جداست. [راهنمای فارسی V8](V8-DRAFT.fa.md) | [English V8 guide](V8-DRAFT.en.md). حالت Progressive Scanning برای V9 برنامه‌ریزی شده است. در حال حاضر تغییری در GitHub منتشر نشده است.

### V8 Quickstart (Debian — Draft)

```bash
sudo apt update && sudo apt install -y python3 curl ca-certificates unzip
./bin/xray-finalmask-scanner --web
# Open http://127.0.0.1:8765
```

---

<div align="center">

# Xray Fragment & FinalMask Scanner

**Scan • Compare • Verify • Export** · **اسکن • مقایسه • اعتبارسنجی • خروجی لینک**

[![Tests](https://github.com/malekjani/xray-fragment-scanner/actions/workflows/scanner-tests.yml/badge.svg)](https://github.com/malekjani/xray-fragment-scanner/actions/workflows/scanner-tests.yml)
[![Xray-core](https://img.shields.io/badge/core-Xray--core-blue)](https://github.com/XTLS/Xray-core)
[![Linux](https://img.shields.io/badge/platform-Linux-brightgreen)](#requirements--پیشنیازها)

[فارسی](#فارسی--راهنمای-کامل) · [English](#english--complete-guide) · [Wizard](WIZARD.md) · [Optimizer](OPTIMIZE.md) · [Network scanner](NETWORK_SCAN.md)

</div>

> **Safety & scope / نکته مهم:** This is a **local experimental scanner**, not a bypass guarantee. Tests depend on your own network, Xray build and server. Never publish your subscription URI, UUID, Trojan password, private result files, or JSON credentials. / این برنامه ابزار آزمایش محلی است؛ نتیجهٔ واقعی وابسته به اینترنت شماست. لینک‌ها و فایل‌های خصوصی را عمومی نکنید.

---

# فارسی — راهنمای کامل

## این پروژه چیست؟

اسکنر متن‌باز Fragment و FinalMask برای **Xray-core** که لینک اتصال را می‌گیرد، کاندیداهای قابل تکرار می‌سازد، آنها را جداگانه روی همان اینترنت آزمایش می‌کند، زمان پاسخ درخواست‌های HTTPS و نرخ موفقیت را می‌سنجد و **برای هر آزمون، لینک قابل واردکردن به کلاینت و جدول دقیق پارامترها** تحویل می‌دهد.

در مسیر جدید `optimize`، مقادیر **ECH، TLS، Fingerprint، SNI، WebSocket Host/Path، ALPN و رمزنگاری** لینک اولیه بدون انتخاب صریح شما تغییر نمی‌کنند. در اسکن شبکهٔ `irancell` نیز از نسخهٔ جدید به بعد همین اصل پیش‌فرض است؛ `unsafe` فقط به‌صورت انتخابی فعال می‌شود. کد قدیمی Bash/Legacy هم اکنون `ech` و تنظیمات TLS مرتبط را از لینک استخراج می‌کند.

## پیش‌نیازها

- **Linux**: Manjaro / Arch، Ubuntu / Debian و توزیع‌های مشابه.
- Python 3.10+؛ **Xray-core سازگار با FinalMask و ECH** و `curl` برای تست واقعی. برای ساخت لینک و جدول بدون اتصال از `--dry-run` استفاده کنید؛ نیازی به Xray نیست.
- `jq` و ابزارهای معمول Bash برای حالت تاریخی `--legacy-menu`. حالت جدید `optimize` و اسکن شبکه **بدون sudo** اجرا می‌شوند؛ سرویس systemd و تنظیمات جاری سیستم را تغییر نمی‌دهند.
- بهتر است قبل از تست، نسخهٔ Core را با `xray version` بررسی کنید. ساختار جدید `FinalMask` و `ECH` در Xray-core نسخه‌های جدید توسعه یافته است؛ کلاینت مقصد نیز باید `fm` و `ech` را پشتیبانی کند.

```bash
# Manjaro / Arch — dependencies for new modes
sudo pacman -S --needed python curl

# Ubuntu / Debian
sudo apt update && sudo apt install -y python3 curl

# Download and run
git clone https://github.com/malekjani/xray-fragment-scanner.git
cd xray-fragment-scanner
chmod +x bin/xray-finalmask-scanner
./bin/xray-finalmask-scanner
```

> **Xray-core** باید جداگانه و از منبع معتبر نصب شده باشد. `which xray` و `xray version` را بررسی کنید. گزینهٔ `--xray` مسیر Core دلخواه را تعیین می‌کند. برای فعالیت معمول برنامه نیازی به اجرای آن با دسترسی root نیست.

## عیب‌یابی INVALID_CONFIG روی Debian / Diagnose Xray config validation

اگر هنگام تست اکثر پروفایل‌ها `INVALID_CONFIG` شدند، معنی‌اش رد شدن JSON توسط
`xray run -test -c` است، **نه شکست تست اینترنت**. برای بررسی همان خروجی قبلی
بدون وارد کردن دوبارهٔ لینک یا انجام تست شبکه، این دستور را اجرا کنید:

```bash
xray version
./bin/xray-finalmask-scanner --diagnose \
  ~/.local/share/xray-finalmask-scanner/optimize-YYYYMMDD-HHMMSS
```

ابزار، لینک اول (Baseline) و نخستین لینک تغییر‌یافته را از `links.csv` می‌خواند،
کانفیگ‌شان را دوباره می‌سازد و نتیجهٔ اعتبارسنجی هر کدام را همراه با نام نسخهٔ
Xray نمایش می‌دهد. فایل خصوصی `xray-diagnose.log` در همان پوشه شامل خطای اصلی
Xray است و **ممکن است حاوی اطلاعات حساس** باشد؛ آن را عمومی نکنید.
از اجرای دوبارهٔ تمام حالت‌ها تا تعیین علت خودداری کنید. قابلیت FinalMask به
Xray-core سازگار نیاز دارد. اگر Baseline در آزمون اتصال `FAILED` شده، آن مسئله
از خطای نحوی FinalMask جداست و باید سرور، TLS/ECH و مسیر اتصال بررسی شود.

## شروع تعاملی؛ دریافت لینک و سؤال مرحله‌ای

با اجرای بدون پارامتر، برنامه لینک **VLESS**، **VMess AEAD**، **VMess قدیمی Base64 JSON** یا **Trojan** را دریافت می‌کند و سپس به ترتیب این پرسش‌ها را مطرح می‌کند:

1. تشخیص مشخصات لینک و وجود ECH و FinalMask؛ نمایش خلاصه بدون چاپ رمز عبور یا UUID.
2. انتخاب `Fragment`، `FinalMask` یا `Both`.
3. واردکردن IP یا دامنهٔ جایگزین (اختیاری؛ SNI و Host اصلی ثابت‌اند).
4. انتخاب presetها یا تعیین دستی `packets`، `lengths`، `delays`، `maxSplit` و لایهٔ دوم (اختیاری).
5. تعیین تعداد درخواست، Timeout، تعداد کاندیدا و Dry Run یا تست واقعی.
6. تأیید، اجرای اسکن و ذخیرهٔ فایل‌های تحلیل و لینک‌ها.

برای ساخت کانفیگ‌ها بدون اتصال، در سؤال پنجم **Dry Run** را انتخاب کنید. در این حالت هیچ «بهترین اتصال» ساختگی اعلام نمی‌شود.

## روش‌های اسکن و تفاوتشان

| روش | دستور یا انتخاب | قابلیت و نکته |
|---|---|---|
| **Wizard** | اجرای بدون آرگومان | VLESS / VMess / Trojan؛ مرحله‌ای و مناسب شروع |
| **Optimize** | `--method optimize` | Fragment تک‌لایه، FinalMask چندلایه، جدول و لینک هر آزمایش؛ تنظیمات اصلی حفظ می‌شوند |
| **IP + ECH** | `--method ech` | آزمایش IPها و عبارت‌های ECH دلخواه؛ Fingerprint و FinalMask به‌طور پیش‌فرض حفظ می‌شوند |
| **IP + FinalMask** | `--method irancell` | آزمایش presetهای PattNG، همراه با حفظ ECH و Fingerprint و بقیهٔ تنظیمات اصلی |
| **PattNG TLS experiment** | `--method irancell --tls-profile pattng-unsafe` | **فقط با درخواست صریح**: استفاده از `unsafe` و آزمایش Cipher Suites؛ ECH همچنان حفظ می‌شود |
| **Legacy Bash** | `--legacy-menu` → 1 → 3 | اسکن کلاسیک `freedom.fragment`، فقط VLESS؛ نیازمند root، دارای اثر روی Xray سیستم |

نام `irancell` فقط برچسب تاریخی این روش است؛ نتایج روی هر ISP باید جداگانه آزمایش شوند.

## پارامترهایی که قابل تغییرند

| پارامتر | فرمت/نمونه | کاربرد |
|---|---|---|
| `--scan` | `fragment`, `finalmask`, `both` | انتخاب خانوادهٔ آزمون |
| `--packets` | `tlshello` یا `1-2` | تعیین نوشتن/بسته‌هایی که قطعه‌بندی می‌شوند؛ قابل تکرار |
| `--lengths` | `'0,104,1'` یا `'6,98,1'` | آرایهٔ اندازه‌های Fragment؛ قابل تکرار برای چند کاندیدا |
| `--delays` | `'0'` یا `'1-5,10'` | آرایهٔ تأخیر بر حسب میلی‌ثانیه |
| `--max-split` | `0` یا `2-4` | سقف تقسیم؛ طبق مستندات ۰ = بدون محدودیت |
| `--layer2-*` | `'114,1'`, `'1'`, `11` | ساخت Fragment دوم در زنجیرهٔ FinalMask |
| `--mask-file` | `mask.json` | آزمایش Fragmentهای لایه‌ای از فایل JSON |
| `--ip`, `--ip-file` | `188.114.97.2`, `2001:db8::2`, `example.com`, CIDR | نشانی‌های انتخابی برای اسکن |
| `--ech`, `--ech-file` | `cloudflare-ech.com+udp://1.1.1.1` | مقادیر کامل ECH؛ در حالت `ech` |
| `--ech-domain`, `--ech-resolver` | `crypto.cloudflare.com`, `https://1.1.1.1/dns-query` | ساخت ترکیب‌های ECH |
| `--tls-profile` | `preserve` / `pattng-unsafe` | حالت TLS روش ایرانسل؛ پیش‌فرض **preserve** |
| `--ech-chrome` | فعال با حضور فلگ | در اسکن ECH، Chrome را **صریحاً** جایگزین Fingerprint اصلی می‌کند |
| `--requests`, `--timeout` | `5`, `10` | تعداد درخواست HTTPS و زمان انتظار هر درخواست |
| `--limit`, `--all` | `25`, بدون حدِ نمونه‌برداری | کنترل تعداد کاندیدا |
| `--dry-run`, `--output` | `--dry-run`, `~/scan-1` | خروجی آفلاین / مسیر نتایج |

در اسکن‌های شبکه، ۷ IP و ۱۸ Resolver قدیمی **فقط نمونه‌اند**. می‌توانید هر IP، hostname، CIDR کوچک یا ترکیب ECH دلخواه وارد کنید؛ مقادیر بالا «لیست بستهٔ آی‌پی‌های سالم» نیستند. `--example-ips` و `--example-ech` نمونه‌ها را به‌صورت اختیاری اضافه می‌کنند.

### مثال ۱: بهترین Fragment و FinalMask برای یک لینک

لینک را در فایل خصوصی بگذارید (`chmod 600` را فراموش نکنید):

```bash
chmod 600 ~/my-vless.txt
./bin/xray-finalmask-scanner --method optimize \
  --link-file ~/my-vless.txt --scan both \
  --packets tlshello --lengths '0,104,1' --lengths '6,98,1' \
  --delays 0 --delays '1-5' --max-split 0 \
  --layer2-lengths '114,1' --layer2-delays 1 \
  --layer2-max-split 11 --requests 5 --timeout 10 --limit 30
```

### مثال ۲: روش ایرانسل، **حفظ ECH و Firefox**

```bash
./bin/xray-finalmask-scanner --method irancell \
  --link-file ~/my-vless.txt --ip cf1.example.net \
  --requests 5 --timeout 10 --limit 15 --no-prompt
```

در این دستور ECH، Fingerprint و دیگر پارامترهای TLS اولیه تغییر نمی‌کنند؛ فقط IP انتخاب‌شده و Fragmentهای TCP در FinalMask آزمایش می‌شوند. presetهای دقیق `tlshello-0-len`، `tlshello` و `zero-free` نیز بررسی می‌شوند. برای بازآفرینی آزمایش TLS قدیمی PattNG، **صرفاً در صورت تمایل** فلگ `--tls-profile pattng-unsafe` را اضافه کنید؛ این حالت Fingerprint را تغییر می‌دهد، ولی ECH را حذف نمی‌کند.

### مثال ۳: اسکن ECH با DNSهای سفارشی

```bash
./bin/xray-finalmask-scanner --method ech \
  --link-file ~/my-vless.txt --ip 188.114.97.2 \
  --ech 'cloudflare-ech.com+udp://9.9.9.9' \
  --ech-domain crypto.cloudflare.com \
  --ech-resolver 'https://1.1.1.1/dns-query' \
  --requests 5 --timeout 10 --no-prompt
```

### مثال ۴: فقط تولید جدول و لینک، بدون اینترنت

```bash
./bin/xray-finalmask-scanner --method optimize \
  --link-file ~/my-vless.txt --scan both --dry-run --limit 12
```

## خروجی‌ها و روش تحلیل

فایل‌ها به‌صورت پیش‌فرض زیر `~/.local/share/xray-finalmask-scanner/` در پوشه‌ای مخصوص همان اسکن قرار می‌گیرند:

| فایل | محتوا |
|---|---|
| `results.csv` | تمام ردیف‌ها با **شناسهٔ آزمایش**، پارامترها، موفقیت‌ها، تأخیر و خطا |
| `ranked.csv` | رده‌بندی بر اساس موفقیت اتصال، P95 و سپس میانگین زمان HTTPS |
| `links.csv` | ستون‌های `id` و `link`؛ **لینک دقیق هر کاندیدا، حتی ناموفق** |
| `links.txt` | لینک‌های آمادهٔ واردکردن در کلاینت، هر خط یک لینک |
| `manifest.jsonl` | JSON مستقل هر آزمون، آرایه‌های دقیق Fragment، تمام FinalMask، زمان‌های پاسخ و SHA-256 لینک |
| `best-link.txt` | لینک برتر **فقط پس از تست واقعی و موفقیت تمام درخواست‌ها** |
| `best-vless.txt` | خروجی سازگار VLESS در موتور `optimize`، در صورت موفقیت |
| `best-config.json` | کانفیگ Xray برنده پس از موفقیت واقعی |
| `summary.json` | خلاصهٔ نتیجه، وقتی نتیجهٔ موفق وجود دارد |

برای اتصال ردیف‌ها از `id` استفاده کنید: `OPT-0002` یا `NET-0002` در همهٔ فایل‌های مربوط به یک تست ثابت است. `avg_ms` و `p95_ms` **تأخیر درخواست HTTPS از مسیر پروکسی** هستند؛ ICMP Ping یا سرعت دانلود نیستند. `DRY_RUN` اتصال واقعی را اثبات نمی‌کند.

**راهنمای انتخاب:** اول نرخ موفقیت اتصال، سپس P95 و میانگین زمان پاسخ؛ یک نتیجهٔ سریع ولی با قطع‌ووصلی را بهتر از نتیجهٔ پایدار تلقی نکنید. برای ارزیابی واقعی چند نوبت و در ساعت‌های متفاوت آزمایش کنید.

## تفاوت Legacy و مدرن

روش قدیمی `freedom.fragment` از `sockopt.dialerProxy = "fragment"` و فیلدهای `packets / length / interval` استفاده می‌کند. این حالت اکنون هنگام تبدیل لینک، **ECH و سایر تنظیمات TLS اصلی و FinalMask موجود** را نگه می‌دارد، ولی فایل لینک کامل برای هر ترکیب تولید نمی‌کند. **برای گرفتن لینک‌های `fm` در خروجی از `optimize` استفاده کنید.** برنامهٔ قدیمی در `--legacy-menu` ممکن است سرویس Xray سیستم را موقتاً متوقف و Core را نصب/به‌روزرسانی کند؛ روی سیستم در حال سرویس‌دهی بدون بررسی اجرا نکنید.

روش جدید Xray با `streamSettings.finalmask.tcp` از چند لایه و آرایه‌های `lengths` و `delays` پشتیبانی می‌کند؛ ترتیب لایه‌ها مهم است. تغییرات فقط در Fragmentها انجام می‌شود و اجزای غیر Fragment از FinalMask موجود تا حد امکان حفظ می‌شوند. [مستندات رسمی FinalMask](https://github.com/XTLS/Xray-docs-next/blob/main/docs/en/config/transports/finalmask.md) · [مستندات TLS / ECH](https://github.com/XTLS/Xray-docs-next/blob/main/docs/en/config/transports/tls.md).

> **سازگاری:** VMess قدیمی Base64 پس از افزودن `fm` به فرم VMess AEAD URI صادر می‌شود؛ لزوماً همهٔ کلاینت‌ها آن را وارد نمی‌کنند. Trojan به TLS نیاز دارد. `unsafe` در این پروژه نام یک Fingerprint است، **نه** `allowInsecure=true`. تمام کاندیداهای قابل اشتراک دوباره Parse و با JSON آزمایش‌شده مقایسه می‌شوند؛ بااین‌حال، واردکردن لینک در کلاینت مقصد را باید جداگانه بررسی کنید.

---

# English — Complete guide

### Diagnostics: INVALID_CONFIG / Xray versions

An `INVALID_CONFIG` result means that Xray rejected a generated JSON configuration
*before* probing the network. Use the saved `links.csv` to reproduce the failure
without re-entering credentials or running the full scan:

```bash
xray version
./bin/xray-finalmask-scanner --diagnose \
  ~/.local/share/xray-finalmask-scanner/optimize-YYYYMMDD-HHMMSS
```

The command validates the unmodified baseline and the first modified link. It
prints **only a classified error** and stores Xray's verbatim error privately
in `xray-diagnose.log` (mode 0600); do not upload that log without redaction.
Xray builds without FinalMask support will reject all modified variants.
A baseline status `FAILED` is a distinct connection failure: 0 successful HTTPS
probes does not prove the server itself is offline.


## Overview

A reproducible, local **Xray-core Fragment & FinalMask scanner**. Supply a **VLESS**, **VMess AEAD**, **VMess legacy Base64 JSON**, or **Trojan** share link to the interactive wizard. The scanner varies selected traffic-mask or connection parameters, benchmarks proxied HTTPS requests, and exports **an exact share URI and full analytical row for every candidate**.

Default behavior **preserves** the original TLS/REALITY, encryption, ECH, fingerprint, SNI, ALPN, WebSocket Host/path and non-Fragment FinalMask layers unless a mode/flag explicitly varies them. An original unmodified baseline is always included.

## Requirements & installation

- Linux; Python 3.10+; `curl`, plus a compatible **Xray-core** executable for **live** tests. Dry runs do not require Xray.
- Main wizard, `optimize`, `ech`, and `irancell` modes operate **without root**, do not modify system services, and write private outputs.
- Historical Bash scanner (`--legacy-menu` → 1) requires root and `jq` and may install/update Xray or temporarily stop the running Xray service. Consider that an opt-in maintenance operation.

```bash
# Arch / Manjaro
sudo pacman -S --needed python curl
# Ubuntu / Debian
sudo apt install -y python3 curl

git clone https://github.com/malekjani/xray-fragment-scanner.git
cd xray-fragment-scanner
chmod +x bin/xray-finalmask-scanner
./bin/xray-finalmask-scanner
```

Install Xray-core independently from a trusted release and check `xray version`. To choose a specific executable, pass `--xray /path/to/xray`. Upstream FinalMask and ECH support depends on your core version and the importer's `fm`/`ech` support.

## Guided wizard

Running without arguments prompts for a private share link, identifies the protocol, then walks through **scan family → optional addresses → Fragment parameters / custom layers → live test settings or dry run → confirmation**. Paste links directly into the hidden prompt on a terminal; no credential-containing CLI argument is necessary.

## Modes and options

| Mode | What it varies | What's preserved |
|---|---|---|
| `--method optimize --scan fragment` | `packets`, `lengths[]`, `delays[]`, `maxSplit` in a single FinalMask fragment layer | Other connection settings and non-Fragment masks |
| `--method optimize --scan finalmask` | Exact PattNG profiles, multi-layer presets and custom masks | TLS, ECH, fingerprint, WS Host/path, non-Fragment masks |
| `--method optimize --scan both` | Both sets above, deduplicated and benchmarked | Same |
| `--method ech` | IP/hostname and complete ECH expressions | Original fingerprint and FinalMask by default; `--ech-chrome` opts into Chrome |
| `--method irancell` | IP and PattNG-derived Fragment profiles | **Original ECH, fingerprint and cipher settings by default** |
| `--method irancell --tls-profile pattng-unsafe` | Optional native TLS fingerprint / cipher experiments | ECH, SNI, Host/path, ALPN; this explicitly changes fingerprint/ciphers |
| `--legacy-menu` → 1 → 3 | Classic `freedom.fragment` `packets/length/interval` | ECH/TLS settings from the VLESS link; this path does **not** export per-variant share links |

### Supported parameter shapes

| Flag / field | Values / syntax |
|---|---|
| `--packets` / `packets` | `tlshello`, `1-1`, `1-2`, `1-5` and other supported write ranges |
| `--lengths` / `lengths[]` | `'0,104,1'`, `'6,98,1'`, `'5-10,10-20'` (repeat flag for alternatives) |
| `--delays` / `delays[]` | `'0'`, `'1-5'`, `'0,1-5'` milliseconds |
| `--max-split` / `maxSplit` | `0` (unlimited), `2-4`, etc. |
| `--layer2-packets`, `--layer2-lengths`, `--layer2-delays`, `--layer2-max-split` | Optional second Fragment layer in the FinalMask chain |
| `--mask-file` | File containing custom FinalMask JSON with TCP fragments |
| `--ip`, `--ip-file` | IPv4, IPv6, hostname, restricted CIDR networks; options are repeatable |
| `--ech`, `--ech-file` | Complete ECHConfigList values such as `'cloudflare-ech.com+udp://1.1.1.1'` |
| `--ech-domain` + `--ech-resolver` | Cartesian product of DNS lookup domain and resolver URI (`udp://`, DoH etc.) |
| `--tls-profile` | `preserve` (**default**), `pattng-unsafe` (explicit opt-in) |
| `--cipher-file` | Custom colon-separated cipher list **requires** `--tls-profile pattng-unsafe` |
| `--ech-chrome` | Explicitly override fingerprint to Chrome in the ECH mode |
| `--requests`, `--timeout`, `--limit`, `--all`, `--dry-run`, `--output` | Benchmark and output controls |

Seven Cloudflare IPs and eighteen ECH resolvers from an early community example are **optional test samples, not an enforced allowlist**. Provide your own values; `--example-ips` and `--example-ech` explicitly add historical sample sets.

### Examples

**1. Guided VLESS / VMess / Trojan workflow**

```bash
./bin/xray-finalmask-scanner
```

**2. Live full Fragment + FinalMask optimization, original TLS/ECH kept**

```bash
chmod 600 ~/private-link.txt
./bin/xray-finalmask-scanner --method optimize \
  --link-file ~/private-link.txt --scan both \
  --packets tlshello --lengths '0,104,1' --lengths '6,98,1' \
  --delays 0 --max-split 0 --requests 5 --timeout 10 --limit 30
```

**3. Irancell-labelled IP+FinalMask experiment, original fingerprint/ECH kept**

```bash
./bin/xray-finalmask-scanner --method irancell \
  --link-file ~/private-link.txt --ip example.net \
  --requests 5 --timeout 10 --limit 15 --no-prompt
```

Add `--tls-profile pattng-unsafe` **only** when deliberately comparing PattNG-style unsafe/native TLS and cipher variants. ECH stays in place.

**4. Flexible IP/ECH search, optional custom resolvers**

```bash
./bin/xray-finalmask-scanner --method ech --link-file ~/private-link.txt \
  --ip 188.114.97.2 --ech 'cloudflare-ech.com+udp://9.9.9.9' \
  --ech-domain crypto.cloudflare.com \
  --ech-resolver 'https://1.1.1.1/dns-query' --no-prompt
```

**5. Generate tables and importable share links without connecting**

```bash
./bin/xray-finalmask-scanner --method optimize \
  --link-file ~/private-link.txt --scan both --dry-run --limit 12
```

## Output schema and analysis

A unique scan directory under `~/.local/share/xray-finalmask-scanner/` contains:

| File | Contents |
|---|---|
| `results.csv` | Full parameters, exact mask JSON, success count/rate, HTTPS timing and failures |
| `ranked.csv` | Candidate ordering: highest success rate, lowest P95, then lowest mean HTTPS time |
| `links.csv` | **One-to-one `id,link` mapping** for every candidate, even failures |
| `links.txt` | Complete importable links in candidate order |
| `manifest.jsonl` | Exact per-candidate masks, fragment arrays, individual HTTPS timings, link SHA-256 |
| `best-link.txt` | Only written after real network testing and 100% request success |
| `best-vless.txt` | Additional VLESS-specific winning link in the optimizer |
| `best-config.json` | The corresponding tested Xray JSON of a fully successful winner |

Join the tables using `OPT-0001`/`NET-0001` IDs and validate `link_sha256` when comparing exports. `avg_ms` and `p95_ms` measure **proxied HTTPS request time**, not ICMP RTT, sustained throughput, or guaranteed censorship resistance. Dry runs create artifacts but never mark a winner. Use repeated live runs on the target ISP to assess stability.

**Compatibility and privacy:** Xray FinalMask uses **ordered** `streamSettings.finalmask.tcp[]` layers; each `fragment` supports `packets`, `lengths[]`, `delays[]`, and `maxSplit`. No blanket promise is made for every client. Legacy VMess QR input with `alterId=0` converts to AEAD-style VMess URI when modified; clients must understand that URI and `fm`. `unsafe` is a TLS fingerprint selector, **not** disabling certificate verification. Links include UUID/password; output folders are private (0700) and secret-containing files use 0600. Do not commit generated links/configs.

## Development, testing & references

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile lib/network_scan.py lib/optimize.py lib/share_codec.py lib/wizard.py
bash -n bin/xray-finalmask-scanner lib/config.sh
```

Code modules: `lib/network_scan.py` (IP/ECH and IP/FinalMask), `lib/optimize.py` (ranking, per-ID links/manifest), `lib/share_codec.py` (VLESS/VMess/Trojan), `lib/wizard.py` (interactive flow), `lib/config.sh` (historical Bash converter). Documentation: [WIZARD](WIZARD.md) · [OPTIMIZE](OPTIMIZE.md) · [NETWORK_SCAN](NETWORK_SCAN.md) · [USAGE](USAGE.md).

Upstream: [Xray FinalMask documentation](https://github.com/XTLS/Xray-docs-next/blob/main/docs/en/config/transports/finalmask.md) · [Xray TLS/ECH documentation](https://github.com/XTLS/Xray-docs-next/blob/main/docs/en/config/transports/tls.md) · [Xray-core releases](https://github.com/XTLS/Xray-core/releases).

> **Testing status:** Unit tests and config/share-link round-trip checks cannot substitute for on-device live tests. No claim is made that a given IP/ECH/Fragment will work on a specific Iranian ISP or with a particular client build.
