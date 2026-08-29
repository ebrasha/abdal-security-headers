# 🛡️ هدرهای امنیتی ابدال — راهنمای توسعه‌دهنده

<div align="center">
  <img src="../abdal-security-headers.png" alt="هدرهای امنیتی ابدال">
</div>

[English Developer Guide](README_Developer_en.md) · [English User Guide](../README.md) · [راهنمای کاربر](../README_fa.md)

<div dir="rtl">

## 🧠 دستیار هوشمند CSP

کشف ترکیبی است. نتایج جدا از `ash_options` ذخیره می‌شوند. فیلدهای CSP فقط وقتی عوض می‌شوند که مدیر مبدأهای انتخاب‌شده را اعمال کند (ادغام، نه جایگزینی).

| لایه | نقش |
| --- | --- |
| ایستا | اسکریپت، استایل، رسانه و endpointهای REST/AJAX ثبت‌شده در وردپرس |
| Report-Only | ارسال `Content-Security-Policy-Report-Only` هنگام مشاهده؛ CSP مسدودکننده در یادگیری ارسال نمی‌شود |
| زمان اجرا | مشاهده‌گر فرانت برای بارگذاری‌های پویا |
| دیسک | اسکن اختیاری تکه‌تکهٔ فایل‌های افزونه و پوسته روی دیسک؛ قابل‌لغو؛ فهرست استثناهای قابل‌ویرایش؛ امکان محدود کردن به افزونه و پوستهٔ انتخاب‌شده؛ لیست سفید خودکار نمی‌شود |

مدت یادگیری: `15min`، `1hour`، `6hours`، `24hours`، `manual`. پایش پیوسته پس از یادگیری اختیاری است. اسکن عمیق فایل‌ها مدت را روی `manual` می‌گذارد تا زمان‌سنج اسکن دیسک را قطع نکند.

وضعیت **افزوده شده** یعنی مبدأ از قبل در فیلد همان دستور پوشش داده شده (`'self'`، میزبان، wildcard). مقادیر خطرناک تأیید می‌خواهند. نوع ناشناخته فقط برای بررسی نگه داشته می‌شود و خودکار اعمال نمی‌شود.

## 📁 ساختار پروژه

```
abdal-security-headers/
├── abdal-security-headers.php
├── includes/
│   ├── class-ash-admin.php
│   ├── class-ash-admin-ui.php
│   ├── class-ash-headers.php
│   ├── class-ash-csp-assistant.php
│   ├── class-ash-csp-normalizer.php
│   ├── class-ash-csp-repository.php
│   ├── class-ash-csp-static-detector.php
│   └── class-ash-csp-disk-scanner.php
├── assets/css/admin.css
├── assets/js/admin.js
├── assets/js/csp-assistant.js
├── assets/js/csp-runtime-observer.js
└── languages/
```

جدول کشف: `{prefix}ash_csp_sources`. وضعیت دستیار: `ash_csp_assistant_state`.

## 🔧 کلاس‌های اصلی

- `ASH_Headers` — ارسال هدرها؛ در یادگیری CSP مسدودکننده را رد می‌کند
- `ASH_Admin` / `ASH_Admin_UI` — منوی سطح‌بالا، رابط تنظیمات، مودال ویرایش CSP
- `ASH_CSP_Assistant` — یادگیری، Report-Only، AJAX اعمال/تفاوت/نادیده‌گرفتن
- `ASH_CSP_Normalizer` — استخراج مبدأ، طبقه‌بندی، پوشش سیاست
- `ASH_CSP_Repository` — ذخیره و ادغام کشفیات
- `ASH_CSP_Static_Detector` — اسکن دارایی‌های ثبت‌شده

AJAX ادمین: `ash_csp_assistant_*`. جمع‌کننده‌های عمومی: `ash_csp_report`، `ash_csp_runtime`.

## 🚀 راه‌اندازی

1. افزونه را در `wp-content/plugins/abdal-security-headers` قرار دهید
2. فعال کنید
3. در wp-admin منوی **هدرهای امنیتی** را باز کنید

وردپرس ۵.۰+ و PHP ۷.۲+. وابستگی Composer ندارد.

## 🐛 گزارش مشکلات

اگر با مشکلی مواجه شدید یا در پیکربندی مشکل دارید، لطفاً از طریق ایمیل Prof.Shafiei@Gmail.com با ما در تماس باشید. همچنین می‌توانید مشکلات را در GitLab یا GitHub گزارش دهید.

## ❤️ حمایت مالی

اگر این پروژه برای شما مفید بود و مایل به حمایت از توسعه بیشتر هستید، لطفاً در نظر داشته باشید که کمک مالی کنید:
- [اینجا اهدا کنید](https://t.me/AbdalDonationBot)

## 🤵 برنامه‌نویس

ساخته شده با عشق توسط **ابراهیم شفیعی (EbraSha)**
- **ایمیل**: Prof.Shafiei@Gmail.com
- **تلگرام**: [@ProfShafiei](https://t.me/ProfShafiei)

## 📜 مجوز

این پروژه تحت مجوز GPLv2 or later منتشر شده است.

</div>
