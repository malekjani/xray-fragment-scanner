# راهنمای کامل فارسی — Xray Fragment Scanner V8

> **پیش‌نویس خصوصی؛ منتشر نشده در GitHub.** نسخهٔ V8 را از ZIP خصوصی باز کنید، نه از شاخهٔ عمومی که ممکن است هنوز V7 باشد. [صفحهٔ اصلی](../README.md) · [English](README.en.md) · [رتبه‌بندی](RANKING.md) · [تست گرم](LIVE-BENCHMARK.md)

## شروع سریع در Debian

```bash
sudo apt update && sudo apt install -y python3 curl ca-certificates unzip
cd ~/xray-fragment-scanner
chmod +x bin/xray-finalmask-scanner
./bin/xray-finalmask-scanner --web
```

آدرس پنل فقط روی همان سیستم: `http://127.0.0.1:8765`. با اجرای بدون آرگومان، Wizard نسخهٔ قبل در دسترس است؛ برای اسکن V8 از پنل یا `--method v8` استفاده کنید. Core اصلی سیستم دست‌نخورده می‌ماند.

## دو حالت اسکن V8

- **Auto:** چند آزمون ابتدایی روی Baseline انجام می‌دهد و *یک‌بار* ماتریس اولیهٔ ثابت را انتخاب می‌کند؛ دامنهٔ آزمایش در طول اسکن گسترش نمی‌یابد. Progressive Scanning برای V9 است.
- **Expert:** چهار محور آدرس، ECH، Fingerprint و پروفایل‌های مرتب FinalMask TCP را با بودجهٔ `max_candidates` انتخاب می‌کند. مقدار `original` همیشه مقدار لینک اصلی را حفظ می‌کند و حذف ECH فقط با مقدار صریح `none` انجام می‌شود.

### راهنمای دقیق پارامترها

| پارامتر | مثال | رفتار |
|---|---|---|
| `addresses` | `["original", "203.0.113.10"]` | فقط مقصد اتصال تغییر کند؛ SNI/Host ثابت بماند مگر صریحاً قابل پشتیبانی باشد |
| `ech_values` | `["original", "none", "...ECHConfig..."]` | حفظ، حذف صریح یا جایگزینی `echConfigList` در TLS |
| `fingerprints` | `["original", "firefox", "chrome"]` | تغییر `tlsSettings.fingerprint`؛ رفتار uTLS ممکن است بعضی فیلدها را بی‌اثر کند |
| `mask_profiles` | `"original"` یا آبجکت `layers` | FinalMask TCP، ترتیب لایه‌ها از **داخل به خارج** |
| Fragment `packets` | `"tlshello"` یا `"1-2"` | انتخاب ClientHello یا محدودهٔ نوشتن TCP |
| Fragment `lengths` | `["6", "98", "1"]` | اندازه‌های متوالی بر حسب بایت، عضو آخر تکرارشونده |
| Fragment `delays` | `["0", "1-5"]` | تأخیرهای میلی‌ثانیه‌ای |
| Fragment `maxSplit` | `"0"`, `"3-6"` | حداکثر تعداد تقسیم‌ها؛ `0` یعنی بدون محدودیت |
| `header-custom` | `clients`, `servers`, `errors` | ساختار لایهٔ ماسک TCP؛ **متفاوت** از هدر `Host` وب‌سوکت |
| `stage1_requests` | `5` | تعداد درخواست غربالگری هر کاندیدا |
| `stage2_requests` | `25` | تعداد درخواست مرحلهٔ تأیید |
| `verify_top` | `5` | چند کاندیدا به مرحلهٔ تأیید بروند |
| `baseline_every` | `5` | بازآزمایی Baseline بعد از چند کاندیدا |
| `min_success` | `0.90` | آستانهٔ موفقیت در مرحلهٔ تأیید؛ به‌تنهایی تضمین پایداری نیست |
| `seed` | `2026` | تصادفی‌سازی قابل تکرارِ ترتیب آزمایش |
| `targets` | `https://...` | ۱ تا ۵ هدف HTTPS؛ تست‌ها با مسیر پروکسی انجام می‌شوند |
| `throughput_url` | `null` یا URL HTTPS | دانلود اختیاری با سقف پاسخ ۵ MiB |
| `timeout` | `8` | ثانیه برای هر درخواست |
| `max_candidates` | `60` | سقف تعداد ترکیب‌ها؛ در صورت تجاوز درخواست رد می‌شود، مخفیانه کاهش نمی‌یابد |

**ساختار Fragment جدید:** `lengths` و `delays` باید آرایه باشند. ترکیب چند لایه در `finalmask.tcp` با ترتیب مشخص انجام می‌شود. مقدار طول صفر در بخش‌های اولیهٔ `tlshello` ممکن است رکورد TLS خالی تولید کند و باعث شکست اتصال شود. سازگاری نهایی باید با همان نسخهٔ Pre-release و سپس روی شبکهٔ واقعی بررسی شود.

**سازگاری:** Browser Dialer به دلیل وابستگی به مرورگر، CORS، کنترل TLS و محدودیت SNI/Host در اسکن خودکار V8 غیرفعال است. `REALITY` و `TLS+ECH` ترکیب معادل نیستند. Mask TCP برای مسیر صرفاً QUIC/UDP معتبر نیست. اعتبار JSON برابر موفقیت اتصال نیست.

## فایل‌های تحلیلی و محرمانگی

`results.csv`, `ranked.csv`, `links.csv`, `links.txt`, `probes.csv`, `manifest.jsonl`, `history.sqlite3`, `verified-links.txt`, `provisional-links.txt`, `summary.json`, `excluded.json`. شناسهٔ `V8-0001` را برای اتصال ردیف‌های آزمایش با لینک دقیق و ساختار ماسک استفاده کنید. هر لینک باید با کانفیگ تست‌شده مطابقت داشته باشد.

شرح الگوریتم و معنای `VERIFIED`: [رتبه‌بندی](RANKING.md). روش اجرای تست واقعی و تشخیص `INVALID_CONFIG`: [تست گرم](LIVE-BENCHMARK.md). **هرگز لینک‌ها یا SQLite را عمومی نکنید.**

---

# مستندات اختصاصی V8 و مثال کامل

# Xray Fragment Scanner V8 — پیش‌نویس خصوصی

> **V8 — انتشار آزمایشی اسکنر فاینال‌مسک.** **Progressive Scanning مربوط به V9 است.**

## نصب و اجرای آزمایشی در Debian

```bash
sudo apt update && sudo apt install -y python3 curl ca-certificates unzip
# در پوشهٔ سورس آزمایشی استخراج‌شده:
chmod +x bin/xray-finalmask-scanner
./bin/xray-finalmask-scanner --web
```

پنل را روی همان دستگاه در `http://127.0.0.1:8765` باز کنید. از رایانهٔ دیگر با SSH Tunnel دسترسی بگیرید، نه پورت باز عمومی:

```bash
ssh -L 8765:127.0.0.1:8765 mahmood@debian
```

برای تست آفلاین و صرفاً ساخت ماتریس و لینک‌ها:

```bash
umask 077
printf '%s\n' 'vless://YOUR_PRIVATE_LINK' > ~/scanner-link.txt
chmod 600 ~/scanner-link.txt
./bin/xray-finalmask-scanner --method v8 --link-file ~/scanner-link.txt \
  --spec examples/v8-expert-matrix.json --dry-run --output ~/v8-offline
```

**لینک و فایل‌های نتایج محرمانه‌اند.** نباید فایل `history.sqlite3` یا `links.csv` را در مخزن عمومی قرار داد.

## قابلیت‌ها

- دو روش **Auto/Adaptive** و **Expert Fixed Matrix**. Auto با چند تست اولیهٔ لینک اصلی، پروفایل اولیهٔ Fragment را یک بار انتخاب می‌کند. انتخاب تدریجی و گسترش ماتریس در طول اسکن وجود ندارد (V9).
- Expert امکان تغییر آدرس، ECH، Fingerprint و لایه‌های مرتب FinalMask TCP (`fragment`، `header-custom`) را می‌دهد. پارامترهای انتخاب‌نشده از لینک اصلی باقی می‌مانند.
- Browser Dialer در V8 برای تست خودکار **غیرفعال** است؛ چون مرورگر واقعی، CORS و مسیر مستقیم می‌خواهد و `tlsSettings` را تحت کنترل Browser قرار می‌دهد.
- اعتبارسنجی استاتیک (BLOCK/WARN/INFO)، تطبیق لینک/JSON و تست `xray run -test` قبل از اتصال واقعی.
- اسکن دومرحله‌ای Discovery و Verification، Baseline ابتدای اسکن/دوره‌ای/پایان، ترتیب شبه‌تصادفی ثابت بر اساس seed.
- ثبت وضعیت هر درخواست HTTP، median، P95، jitter، Wilson lower bound، دریافتی و throughput اختیاری؛ رتبه‌بندی با موفقیت اتصال و تأخیر.
- وضعیت VERIFIED فقط برای کاندیداهایی با حداقل ۲۰ درخواست مرحلهٔ دوم و عبور از آستانهٔ موفقیت تعریف‌شده ثبت می‌شود. این وضعیت تضمین اتصال دائمی نیست.
- هستهٔ آخرین Pre-release رسمی Xray در شروع هر اسکن توسط ماژول قبلی دانلود و با SHA256 تأیید می‌شود؛ نسخه در میانهٔ اسکن تغییر نمی‌کند. نسخهٔ سیستم دست‌نخورده می‌ماند.
- رابط HTTP محلی 127.0.0.1 با توکن نشست، محافظت ضد CSRF، عدم بارگذاری منابع خارجی و عدم لاگ‌گرفتن لینک‌ها.

## فرمت Expert Matrix

```json
{
  "mode": "expert",
  "addresses": ["original"],
  "fingerprints": ["original", "firefox", "chrome"],
  "ech_values": ["original", "none"],
  "mask_profiles": [
    "original",
    {
      "name": "one-layer",
      "layers": [
        {"type": "fragment", "settings": {
          "packets": "tlshello", "lengths": ["6", "98", "1"],
          "delays": ["0"], "maxSplit": "0"
        }}
      ]
    }
  ],
  "stage1_requests": 5,
  "stage2_requests": 25,
  "verify_top": 5,
  "baseline_every": 5,
  "min_success": 0.90,
  "timeout": 8,
  "max_candidates": 60,
  "seed": 2026,
  "targets": ["https://www.gstatic.com/generate_204"],
  "throughput_url": null
}
```

در `ech_values` مقدار `original` یعنی ECH لینک اصلی حفظ شود و `none` یعنی ECH **عمداً حذف شود**. برای آزمایش ECH جدید باید مقدار کامل `echConfigList` را وارد کرد. در `fingerprints` از مقادیر پشتیبانی‌شدهٔ Xray مانند `chrome` و `firefox` استفاده کنید. `mask_profiles.layers` ترتیب **داخل به خارج** دارد؛ لایهٔ اول داخلی‌ترین لایه است. برای Custom Header باید `clients` را مطابق مستندات Xray تعریف کنید. این قسمت با WebSocket `Host` header فرق دارد.

### قوانین ایمنی و تداخل

- مسیرهای QUIC/UDP با `finalmask.tcp` ترکیب نمی‌شوند.
- Browser Dialer به‌صورت خودکار تست نمی‌شود و با SNI و Host مستقل سازگار نیست.
- REALITY را با Transport ناسازگار یا ECH نوع TLS ترکیب نکنید.
- اولین طول صفر در `tlshello` ممکن است رکورد TLS خالی ایجاد کند؛ ریسک اجرا نمایش داده می‌شود.
- گذرکردن از `xray run -test` به معنی عملکرد صحیح شبکه یا اثرگذاری واقعی ECH/Fragment نیست.
- از به‌روزرسانی ناخواستهٔ ALPN، TLS، SNI، Fingerprint یا ECH بدون انتخاب صریح جلوگیری شده است. هر کانفیگ/لینک از تبدیل معکوس کنترل می‌شود.

## خروجی‌ها

| فایل | نقش |
|---|---|
| `history.sqlite3` | تاریخچهٔ محلی، کاندیداها و اندازه‌گیری‌های خام هر درخواست |
| `results.csv`, `ranked.csv` | مقادیر پارامترها، نرخ موفقیت، رتبه و شاخص‌های عملکرد |
| `links.csv`, `links.txt` | لینک کامل متناظر با هر شناسهٔ کاندیدا |
| `verified-links.txt`, `provisional-links.txt` | لینک‌های تأییدشده و موقت؛ ادعای تضمین اتصال ندارند |
| `probes.csv` | جزئیات تک‌تک آزمایش‌های واقعی |
| `manifest.jsonl` | هش‌ها، شرایط سازگاری، ترتیب لایه‌ها و تنظیمات FinalMask |
| `summary.json` | اطلاعات مقایسهٔ Baseline، رانش شبکه و دلیل انتخاب برنده |
| `excluded.json` | ترکیب‌هایی که توسط موتور سازگاری کنار گذاشته شدند |

CSV و SQLite، اطلاعات خصوصی اتصال را دارند و روی دیسک با مجوز محدود ذخیره می‌شوند. فایل‌های خروجی در حالت Dry Run برنده ندارند.

## محدودیت‌های V8

1. پیش‌نمایش Auto بدون تست شبکه دقیقاً معادل تولید کاندیدای Live نیست؛ مرحلهٔ Live بعد از سنجش Baseline می‌تواند فهرست ثابت متفاوتی بسازد.
2. موتور سازگاری فقط قواعد مستند را اعمال می‌کند؛ بعضی ترکیب‌های معتبر ممکن است از نظر محیط و سرور اثر مطلوب نداشته باشند.
3. دسته‌بندی خطاهای DNS، TCP، TLS و HTTP بر اساس کدهای curl و لاگ‌های محدود Xray است و ادعای تشخیص قطعی DPI یا شکست ECH نیست.
4. تست Throughput اختیاری است؛ با محدودیت ۵MB انجام می‌شود و باید هدفی مطمئن با پاسخ حجیم انتخاب شود.
5. Browser Dialer، سیاست‌های پیچیدهٔ چندحاملی و Progressive Search برای نسخه‌های بعدی باقی مانده‌اند.
6. در Draft فعلی توقف و ذخیرهٔ داده‌های انجام‌شده وجود دارد، ولی **Resume خودکار پس از قطع فرایند هنوز تکمیل نشده است**.
7. نتایج اتصال روی اینترنت ایران در این محیط تأیید نشده‌اند؛ قبل از انتشار عمومی نیازمند تست میدانی‌اند.

**مستندات مبنا:** [Xray FinalMask](https://github.com/XTLS/Xray-docs-next/blob/main/docs/en/config/transports/finalmask.md)، [TLS/uTLS](https://github.com/XTLS/Xray-docs-next/blob/main/docs/en/config/transports/tls.md)، [Browser Dialer](https://github.com/XTLS/Xray-docs-next/blob/main/docs/en/config/features/browser_dialer.md).

## جدول جدید نتایج FinalMask در V8

در کنسول و وب همان ستون‌های Instance، Packets، Length، Delay، Max Split، Average Response (ms)، Success و Status دیده می‌شوند. جدول دوم سه نتیجه با کمترین **میانگین اندازه‌گیری‌شده** را نشان می‌دهد و تأیید شدن آن‌ها را جداگانه مشخص می‌کند. زمان پاسخ مربوط به HTTPS از مسیر پروکسی است، نه Ping معمولی. ترتیب لایه‌های چندگانه حفظ می‌شود. در حالت FinalMask Only، ECH و Fingerprint و IP تغییر نمی‌کنند. فایل `examples/v8-finalmask-only.json` پانزده پروفایل آزمایشی صرفاً برای نمونهٔ ماتریس دارد. خروجی‌های `finalmask-instances.csv` و `top-three-lowest-average.csv` را ببینید.
