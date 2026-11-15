
# 🛡️ حِماك | Himaak Security Scan

> **الهدف المفحوص:** `https://example-corp.ai-asaas.com`
> **توقيت الفحص:** `Sun, 8 Nov 2026 12:45:00` | **محرك الفحص:** `2.14.0`

| مؤشر السلامة | قرار الإطلاق | عالية | متوسطة | منخفضة | معلوماتية | إجمالي الحالات |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **52 / 100**<br>_متوسط / مخاطر محتملة_ | **⛔ محجوب عن الإطلاق (Blocked)** | **1** | **2** | **1** | **1** | **6** |

### 🔍 الثغرات المرصودة

| الخطورة | الثغرة | الحالات | CWE |
| :--- | :--- | :---: | :---: |
| 🔴 High | **حقن لغة الاستعلامات (SQL Injection)**<br>_SQL Injection_ | 1 | `CWE-89` |
| 🟡 Medium | **غياب ترويسة سياسة أمان المحتوى (CSP Header Missing)**<br>_Content Security Policy (CSP) Header Not Set_ | 2 | `CWE-693` |
| 🟡 Medium | **غياب رموز الحماية من تزوير الطلبات (Anti-CSRF Missing)**<br>_Anti-CSRF Tokens Check_ | 1 | `CWE-352` |
| 🟢 Low | **غياب ترويسة النقل الصارم الآمن (HSTS Missing)**<br>_Strict-Transport-Security Header Not Set_ | 1 | `CWE-319` |
| ⚪ Info | **كشف التوقيت الزمني للخادم (Unix Timestamp Disclosure)**<br>_Timestamp Disclosure - Unix_ | 1 | `CWE-200` |

---
💡 التقرير التفاعلي الكامل مرفوع كملف ناتج (Artifact) في هذا التشغيل.
