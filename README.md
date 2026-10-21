# پروفایل IPv4 و IPv6 آیفون برای اپراتورهای ایران

**MCI · MTN Irancell · RighTel · Shatel Mobile**

این مخزن شامل چهار فایل تنظیم APN با فرمت `.mobileconfig` و مقدار `AllowedProtocolMask = 3` (اجازه IPv4 و IPv6) است. فایل‌ها ساخته‌شده توسط کاربر هستند، **رسمی یا امضاشده از طرف اپراتورها نیستند**. دریافت IPv6 به شبکه سیم‌کارت و پشتیبانی اپراتور بستگی دارد و تضمین نشده است. پشتیبانی IPv6 شاتل موبایل به‌صورت رسمی برای همه مشترکان احراز نشده است.

![پوستر تصویری آموزش نصب IPv6 روی آیفون](POSTER.svg)

## دریافت پروفایل

| اپراتور | APN | دانلود مستقیم |
|---|---|---|
| همراه اول (MCI) | `mcinet` | [دریافت mobileconfig](https://raw.githubusercontent.com/malekjani/xray-fragment-scanner/iran-ios-ipv6/profiles/MCI_Dual_Stack_IPv4_IPv6.mobileconfig) |
| ایرانسل | `mtnirancell` | [دریافت mobileconfig](https://raw.githubusercontent.com/malekjani/xray-fragment-scanner/iran-ios-ipv6/profiles/Irancell_Dual_Stack_IPv4_IPv6.mobileconfig) |
| رایتل | `RighTel` | [دریافت mobileconfig](https://raw.githubusercontent.com/malekjani/xray-fragment-scanner/iran-ios-ipv6/profiles/RighTel_IPv4_IPv6_Dual_Stack.mobileconfig) |
| شاتل موبایل | `shatelmobile` | [دریافت mobileconfig](https://raw.githubusercontent.com/malekjani/xray-fragment-scanner/iran-ios-ipv6/profiles/ShatelMobile_IPv4_IPv6_Dual_Stack.mobileconfig) |

> لینک‌های مستقیم GitHub Raw ممکن است به‌جای شروع فوری نصب، فایل را دانلود کنند. این طبیعی است؛ فایل را باز کنید یا از Apple Mail برای دریافت پروفایل استفاده کنید. Safari اجباری نیست.

## نصب روی آیفون
۱. پروفایل مربوط به سیم‌کارت را از منبع معتبر دریافت کنید. ۲. در صورت نمایش اعلان دانلود پروفایل، روی **Allow** بزنید. ۳. وارد **Settings → Profile Downloaded** شوید، جزئیات پروفایل را ببینید و **Install** را بزنید. ۴. در صورت نبود گزینه، **Settings → General → VPN & Device Management** را بررسی کنید. ۵. با رمز دستگاه نصب را تأیید کنید. ۶. برای تست، Wi-Fi و VPN را خاموش کرده و `https://test-ipv6.com/` را باز کنید.

**راهنمای کامل:** [INSTALL_FA.md](INSTALL_FA.md) · **پوستر مستقل:** [POSTER.svg](POSTER.svg).

## نکات مهم
- مقدار `AllowedProtocolMask=3` فقط IPv4 و IPv6 را مجاز می‌کند؛ لزوماً IPv6 عمومی اختصاص نمی‌دهد.
- تنظیمات اپراتور، محدودیت‌های iOS یا مدیریت سازمانی می‌تواند مانع اعمال تنظیمات شود.
- قبل از نصب، محتویات پروفایل را بررسی کنید. این فایل‌ها امضای دیجیتال ندارند.
- اگر اینترنت مختل شد، پروفایل را از **VPN & Device Management** حذف کنید.
- مرجع اپل: [Install a configuration profile on your iPhone or iPad](https://support.apple.com/en-us/102400).
- پوستر شماتیک است و تصویر زنده محیط سیستم‌عامل محسوب نمی‌شود.
