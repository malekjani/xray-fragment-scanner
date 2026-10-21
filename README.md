# پروفایل IPv4/IPv6 آیفون برای اپراتورهای ایرانی

![پوستر آموزشی نصب IPv6 در آیفون](POSTER.svg)

**این مخزن حاوی فایل‌های غیررسمی `.mobileconfig` برای پیکربندی APN در آیفون است.** پوستر بالا بازسازی برداری همان طرح چهاراپراتوری با شش مرحله نصب است. لوگوها و صفحه‌های آیفون در SVG به‌صورت شماتیک بازسازی شده‌اند، نه تصویر رسمی Apple/اپراتورها.

## دانلود چهار پروفایل

| اپراتور | APN رسمی | فایل پروفایل |
|---|---|---|
| همراه اول (MCI) | `mcinet` | [دانلود مستقیم](https://raw.githubusercontent.com/malekjani/xray-fragment-scanner/iran-ios-ipv6/profiles/MCI_Dual_Stack_IPv4_IPv6.mobileconfig) |
| ایرانسل (MTN Irancell) | `mtnirancell` | [دانلود مستقیم](https://raw.githubusercontent.com/malekjani/xray-fragment-scanner/iran-ios-ipv6/profiles/Irancell_Dual_Stack_IPv4_IPv6.mobileconfig) |
| رایتل (RighTel) | `RighTel` | [دانلود مستقیم](https://raw.githubusercontent.com/malekjani/xray-fragment-scanner/iran-ios-ipv6/profiles/RighTel_IPv4_IPv6_Dual_Stack.mobileconfig) |
| شاتل موبایل (Shatel Mobile) | `shatelmobile` | [دانلود مستقیم](https://raw.githubusercontent.com/malekjani/xray-fragment-scanner/iran-ios-ipv6/profiles/ShatelMobile_IPv4_IPv6_Dual_Stack.mobileconfig) |

**این‌ها پروفایل رسمی اپراتورها نیستند و امضای دیجیتال ندارند.** مقادیر APN از وب‌سایت‌های رسمی گرفته شده‌اند. مقدار `AllowedProtocolMask=3` مطابق مستندات Apple استفاده از هر دو پروتکل IPv4 و IPv6 را **مجاز** می‌کند؛ اتصال IPv6 را تضمین نمی‌کند. پشتیبانی واقعی به اپراتور، SIM، پوشش و تنظیمات iOS بستگی دارد. برای شاتل موبایل تأیید مستقلی از ارائه عمومی IPv6 در تمام سیم‌کارت‌ها نداریم.

## نصب، تست و حذف
راهنمای کامل فارسی: **[INSTALL_FA.md](INSTALL_FA.md)**

در Safari یا Apple Mail فایل مربوط به اپراتور خود را دریافت کنید؛ در صورت نمایش پیام دانلود، `Allow` را بزنید. سپس **Settings → Profile Downloaded → Install**؛ یا **Settings → General → VPN & Device Management**. پس از نصب Wi-Fi و VPN را خاموش کنید، اتصال دیتای همان سیم‌کارت را روشن کنید و با [test-ipv6.com](https://test-ipv6.com/) آزمایش کنید.

نکته: مرورگر GitHub Raw ممکن است صرفاً فایل را دانلود کند و پنجره نصب ندهد. Safari تنها راه دریافت فایل نیست. تنها **یک پروفایل دانلودشده** هم‌زمان آماده نصب است و طبق Apple اگر ظرف **۸ دقیقه** نصب نشود از فهرست نصب حذف می‌شود. قبل از نصب مشخصات پروفایل را مطالعه کنید و از پروفایل ناشناس استفاده نکنید.

## منابع معتبر و وضعیت تأیید
- [Apple — Cellular payload](https://developer.apple.com/documentation/devicemanagement/cellular) و [APNs Item / AllowedProtocolMask](https://developer.apple.com/documentation/devicemanagement/cellular/apnsitem)
- [Apple — نصب پروفایل](https://support.apple.com/en-us/102400)
- [همراه اول — تنظیمات اینترنت](https://mci.ir/internet-settings)
- [ایرانسل — تنظیمات APN](https://irancell.ir/p/292429)
- [رایتل — راهنمای IPv6](https://www.rightel.ir/en/p/1516/ipv6-settings-help)
- [شاتل موبایل — راهنمای iOS](https://shatelmobile.ir/setting/راهنمای-ios/)

### وضعیت اعتبارسنجی
- بررسی انجام‌شده: ساختار XML/Plist، نام APN هر چهار اپراتور، کلیدهای `com.apple.cellular`، مقدار `AllowedProtocolMask=3` و عدم وجود VPN/MDM/گواهی در پروفایل‌ها.
- اصلاح ایمنی: بخش غیرضروری `AttachAPN` از پروفایل شاتل حذف شد تا APN پیش‌فرض ثبت‌شدن در شبکه تغییر نکند.
- بررسی انجام‌نشده: نصب و اعمال روی آیفون واقعی، دریافت آدرس IPv6 از شبکه هر اپراتور، سازگاری با همه نسخه‌های iOS و کنترل‌گر اپراتور.
- اگر اینترنت بعد از نصب مختل شد، پروفایل را از **Settings → General → VPN & Device Management** حذف کنید.

**توصیه:** APN اشتباه می‌تواند اینترنت موبایل را قطع کند. استفاده و تست با مسئولیت کاربر و با بررسی تنظیمات سیم‌کارت انجام شود.
