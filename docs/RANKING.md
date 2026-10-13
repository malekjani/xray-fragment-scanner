# V8 ranking & confidence / رتبه‌بندی و میزان اطمینان

[Home / صفحهٔ اصلی](../README.md) · [فارسی](README.fa.md) · [English](README.en.md)

## فارسی — منطق واقعی نسخهٔ پیش‌نویس

1. **Discovery:** هر کاندیدا با `stage1_requests` درخواست HTTPS تست می‌شود. در شروع، به‌صورت دوره‌ای (`baseline_every`) و در پایان، کانفیگ اصلی مجدداً آزموده می‌شود. ترتیب آزمون با `seed` تصادفیِ قابل تکرار است.
2. **Verification:** به تعداد `verify_top` از کاندیداهای غربالگری‌شده، با `stage2_requests` درخواست جدید اختصاص داده می‌شود. الگوریتم جست‌وجوی تدریجی/Progressive در V8 وجود ندارد.
3. **آمار:** `success_rate = successes / requests`. `median_ms` میانهٔ زمان کامل درخواست‌های موفق است، `p95_ms` صدک ۹۵ طبق روش nearest-rank، `jitter_ms` انحراف معیار جمعیت برای زمان‌های موفق است؛ این مقدار **Jitter شبکهٔ ICMP نیست**. `wilson_lower95` کران پایین تقریبی ۹۵٪ نرخ موفقیت به روش Wilson است.
4. **رتبه‌بندی:** ابتدا `VERIFIED`، سپس `PROVISIONAL` و بعد سایر وضعیت‌ها؛ درون هر گروه ابتدا **success_rate بیشتر**، سپس **Wilson lower بیشتر**، سپس **P95 کمتر**. تابع داخلی `quality()` برای مرتب‌سازی مقدماتی Discovery، median را بعد از P95 می‌سنجد.
5. **Verified:** فقط وقتی آزمون مرحلهٔ دوم انجام شده، حداقل ۲۰ درخواست غیر-Throughput در آن ثبت شده، نرخ موفقیت آن به `min_success` رسیده و اجرای اسکن کامل بوده است. این وضعیت به معنای موفقیت کامل ۱۰۰٪، قطع‌نشدن آینده یا اثبات بهبود نسبت به Baseline نیست.
6. **Provisional:** در کد فعلی برچسب محدود به کاندیدایی است که مرحلهٔ دوم را *تا حدی* گذرانده و اسکن هنوز کامل نشده؛ هر کاندیدای امیدوارکننده الزاماً Provisional نام نمی‌گیرد. اگر مرحلهٔ دوم انجام شود و شرط Verified برقرار نباشد، `REJECTED` خواهد بود.
7. **Baseline drift:** `summary.json` اختلاف نرخ موفقیت و median بین Baseline شروع و پایان را نگه می‌دارد؛ این معیار نشانهٔ تغییر شرایط است، نه اثبات علت آن.

**نکته:** تعداد نمونهٔ کم باعث می‌شود P95 ناپایدار باشد. ۲۵/۲۵ موفقیت نیز تضمین نرخ موفقیت حقیقی ۱۰۰٪ نیست. هیچ‌یک از امتیازهای بالا تحلیل قطعی DPI یا تضمین بهترشدن کانفیگ ارائه نمی‌کنند.

## English — implementation-specific semantics

1. **Discovery:** run `stage1_requests` requests per candidate, interleave untouched baseline checks every `baseline_every` candidates, and repeat baseline at the end. The order is randomized using a reproducible `seed`.
2. **Verification:** retest up to `verify_top` candidates with `stage2_requests` fresh requests each. **No progressive matrix expansion** until V9.
3. **Metrics:** `success_rate = successes / requests`. `median_ms` and nearest-rank `p95_ms` use **successful HTTPS request total durations only**. `jitter_ms` is the population standard deviation of those durations, not ICMP/network-layer jitter. `wilson_lower95` is the approximate Wilson 95% lower bound for a binomial success rate.
4. **Ordering:** `VERIFIED` first, `PROVISIONAL` second, then others. Sort within groups by descending `success_rate`, descending `wilson_lower95`, and ascending `p95_ms`. Discovery selection separately uses ascending median as a final tie-breaker.
5. **VERIFIED:** second-stage results exist, at least 20 non-throughput requests were recorded, second-stage success rate meets `min_success`, and the scan completed. **Not** a guaranteed uptime claim, 100% success requirement, or proof of improvement over the baseline.
6. **PROVISIONAL:** in the current draft, specifically denotes an incomplete run with some successful second-stage requests; it is **not** a general label for all promising candidates. Failed verification candidates may be marked `REJECTED`.
7. **Network drift:** differences between initial and final baseline median and success rate are reported; they are contextual controls, not conclusive causal diagnosis.

**Reproducibility:** keep the exact Xray pre-release SHA-256, matrix specification, target URLs, sampling `seed`, per-request raw records and finalmask_json alongside candidate `id` and `link_sha256`. Sharing any of these raw files may reveal private addresses and credentials.
