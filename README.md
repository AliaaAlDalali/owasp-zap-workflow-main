<p align="center">
  <img src="assets/images/logo-dark.png" alt="Himaak by ASAAS AI" width="90">
</p>

<h1 align="center">
  حِماك | منظومة الفحص الأمني المؤتمت<br>
  <span style="color: #ba9555;">Himaak — Automated Security Assessment, by ASAAS AI</span>
</h1>

<p align="center">
  منظومة أتمتة متكاملة لفحص تطبيقات الويب واكتشاف الثغرات الأمنية بالاعتماد على <strong>OWASP ZAP</strong> ومخرجات تفاعلية مطابقة بالكامل لـ <strong>الهوية البصرية لشركة أساس</strong> (Liquid Glass Design & Thmanyah Typography).
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Himaak-by_ASAAS_AI-ba9555?style=for-the-badge" alt="Himaak by ASAAS AI">
  <img src="https://img.shields.io/badge/OWASP-ZAP_Baseline-221f1f?style=for-the-badge&logo=owasp" alt="OWASP ZAP">
  <img src="https://img.shields.io/badge/Design-Liquid_Glass-d3c6b4?style=for-the-badge" alt="Liquid Glass">
  <img src="https://img.shields.io/badge/Typography-Thmanyah-8f6626?style=for-the-badge" alt="Thmanyah">
  <img src="https://img.shields.io/badge/Language-Arabic_RTL_%2F_English-23744a?style=for-the-badge" alt="Bilingual">
</p>

---

## 🌟 نظرة عامة | Overview

**حِماك** (Himaak) منتج من شركة أساس للذكاء الاصطناعي، يقوم بتنفيذ فحص أمني سلبي مؤتمت (Baseline Security Scan) ضد تطبيقات وواجهات الويب باستخدام محرك **OWASP ZAP** داخل بيئة GitHub Actions أو محلياً، مع تحويل مخرجات الفحص الخام تلقائياً إلى **تقارير تنفيذية عالية الاحترافية** مصممة بالكامل وفق لغة التصميم الخاصة بشركة أساس:

1. **الواجهات التفاعلية (Interactive Dashboard):**
   - منصة ويب متكاملة (`index.html`) تتيح معاينة فورية لتقارير الفحص أو رفع أي ملف `zap_report.json` عبر السحب والإفلات.
   - دعم التبديل الفوري بين **الوضع الليلي والنهاري** (Light / Dark Themes).
   - دعم كامل للغتين **العربية (RTL)** والإنجليزية (LTR).
   - أدوات فرز ذكية وتصفية بالاسم ومعرّفات CWE ومستوى الخطورة.

2. **التقرير التنفيذي المستقل (Stand-alone Branded HTML Report):**
   - توليد ملف HTML متكامل ومستقل بذاته يحتوي على شعارات الشركة مدمجة (Base64) وكافة أنماط الزجاج السائل (Liquid Glass).
   - قابل للتصدير والطباعة كتقرير PDF رسمي جاهز للإدارة والمطورين.

3. **لوحة معلومات سير العمل (GitHub Actions Step Summary):**
   - إبراز مؤشرات الأداء الأمني ومؤشر السلامة (Security Health Score) وقرار الإطلاق مباشرة داخل واجهة GitHub Actions.

4. **بوابة قرار الإطلاق (Release Gate):** سياسة واحدة يطبقها التقرير ولوحة التحكم وسير العمل:
   - **مؤشر السلامة** = 100 − (25 × عالية + 10 × متوسطة + 3 × منخفضة)، بحد أدنى صفر.
   - **محجوب (Blocked):** عند وجود أي ثغرة عالية الخطورة أو انخفاض المؤشر دون 50.
   - **مشروط (Conditional):** عند وجود ثغرات متوسطة فقط (مهلة معالجة 14 يوماً).
   - **معتمد (Approved):** لا ثغرات عالية ولا متوسطة.
   - يمكن جعل سير العمل يفشل تلقائياً عبر الخيار `--fail-on blocked` أو `--fail-on conditional`.

---

## 🎨 المعايير البصرية المعتمدة (Asaas Design Standards)

تم تطبيق جميع مواصفات الهوية البصرية من حزمة `asaas-ui`:

* **لوحة الألوان الرسمية (Brand Colors):**
  * **Ink (`#221f1f`):** للنصوص الأساسية والخلفيات الداكنة.
  * **Gold (`#ba9555` / `#d8b36f`):** للأزرار الرئيسية، حواف التركيز، والمؤشرات النشطة.
  * **Sand & Clay (`#d3c6b4` / `#c3ad8d`):** للمسات الثانوية والأسطح الزجاجية الناعمة.
  * **Cream & Paper (`#ede7da` / `#fcf9f5`):** لخلفيات الصفحات والبطاقات الفاتحة.
* **دلالات الحالات (State Colors):**
  * 🔴 **عالي الخطورة (High Risk):** اللون الأحمر المعياري (`--unpaid: #b0342c`).
  * 🟡 **متوسط الخطورة (Medium Risk):** اللون الذهبي/العنبري (`--partial: #9a5f05`).
  * 🟢 **منخفض الخطورة / آمن (Low / Pass):** اللون الأخضر المعياري (`--paid: #23744a`).
  * 🔵 **معلوماتي (Informational):** اللون الأزرق السماوي (`--chart-out: #00849e`).
* **خامات الزجاج السائل (Liquid Glass):**
  * انعكاسات ناعمة مع `backdrop-filter: blur(24px) saturate(175%)`.
  * حواف مضيئة سفلية وعلوية (`--glass-rim`, `--glass-sheen`, `--glass-shadow`).
  * خلفية التوهج المحيطي (`.ambient` مع الكرات الضوئية `--orb-1`, `--orb-2`, `--orb-3`).
* **الخطوط والطباعة (Typography):**
  * اعتماد خط **ثمانية (Thmanyah)** برخصته الأصلية:
    * `Thmanyah Sans`: للنصوص الرقمية وواجهات الأزرار والأرقام.
    * `Thmanyah Serif Display`: للعناوين الرئيسية والفرعية مع خاصية الكشيدة والتمديد (`.swash`).
    * `Thmanyah Serif Text`: للمقاطع الوصفية وشروحات الثغرات.

---

## 🚀 طريقة الاستخدام | How to Use

### 1. التشغيل عبر GitHub Actions (سير العمل الآلي)

1. توجه إلى تبويب **Actions** داخل مستودع المشروع على GitHub.
2. اختر سير العمل المسمى **🛡️ Himaak Security Scan**.
3. انقر على زر **Run workflow**.
4. أدخل رابط الموقع المستهدف في حقل `target_url` (مثال: `https://example.com`)، واختر اختيارياً `fail_on` لإفشال التشغيل حسب قرار الإطلاق.
   > افحص فقط المواقع التي تملكها أو لديك إذن مكتوب بفحصها.
5. بعد اكتمال الفحص، ستظهر لوحة المؤشرات التنفيذية في ملخص التشغيل (**Job Summary**)، وستجد تقارير الفحص متاحة للتحميل في قسم **Artifacts**:
   - `himaak-security-report-html`: تقرير حماك التفاعلي.
   - `zap-raw-reports`: تقرير ZAP الأصلي بصيغة HTML وملف `zap_report.json` لمعالجات CI/CD.

### 2. الاستعراض والتشغيل المحلي (Local Dashboard & Runner)

#### أ) فتح لوحة التحكم المحلية:
افتح ملف `index.html` في أي متصفح ويب، وستتمكن من:
- استعراض تقرير نموذجي تفاعلي بالكامل.
- سحب وإفلات أي ملف `zap_report.json` لعرضه فوراً (يُقرأ محلياً في المتصفح ولا يُرفع لأي خادم).
- توليد أوامر التشغيل عبر سطر الأوامر.

#### ب) تشغيل الفحص عبر Docker محلياً:
```bash
# إنشاء مجلد حفظ التقارير
mkdir -p zap-reports

# تشغيل فحص ZAP Baseline
docker run --rm -v $(pwd)/zap-reports:/zap/wrk/:rw \
  ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
  -t "https://example.com" \
  -r zap_raw_report.html \
  -J zap_report.json
```

#### ج) تحويل ملف JSON إلى تقرير حماك:
```bash
python scripts/generate_report.py \
  --json zap-reports/zap_report.json \
  --output-html zap-reports/himaak_report.html   --fail-on blocked        # اختياري: يعيد رمز خروج 1 إذا كان الإطلاق محجوباً
```

#### د) إعادة بناء لوحة التحكم والتحقق منها:
```bash
python scripts/build_index.py
python scripts/generate_report.py --json zap/wrk/sample_zap_report.json --output-html docs/sample_report.html
python scripts/verify_all_pages.py
```

---

## 📁 هيكلة المشروع | Project Structure

```text
owasp-zap-workflow-main/
│
├── .github/
│   └── workflows/
│       └── zap-scan.yml           # سير عمل GitHub Actions (فحص ZAP + تقرير حماك)
│
├── assets/                        # أصول ومعايير الهوية البصرية لشركة أساس
│   ├── fonts/
│   │   └── thmanyah/              # خطوط ثمانية الأصلية (Sans, Serif Display, Serif Text)
│   ├── images/
│   │   ├── logo-dark.png          # الشعار الداكن لأساس
│   │   ├── logo-light.png         # الشعار الفاتح لأساس
│   │   └── favicon.png            # أيقونة الموقع
│   └── styles/
│       ├── tokens.css             # متغيرات التصميم (الألوان، الإشعاع، الحواف)
│       ├── glass.css              # خامات الزجاج السائل والخلفية المحيطية
│       ├── base.css               # القواعد الأساسية والطباعة
│       ├── components.css         # الأزرار، الحقول، الشارات، البطاقات
│       ├── layout.css             # تخطيط الشبكات وتجاوب الهواتف
│       ├── report.css             # أنماط تقرير الثغرات ومؤشر السلامة والطباعة
│       └── index.css              # ملف الربط الشامل للأنماط
│
├── scripts/
│   ├── generate_report.py         # يحوّل zap_report.json إلى تقرير HTML وملخص Markdown وقرار الإطلاق
│   ├── build_index.py             # يبني لوحة التحكم index.html
│   └── verify_all_pages.py        # فحوصات سلامة للصفحات المولّدة
│
├── himaak_core/                   # منطق مشترك بين الأداة والمنصة (مصدر واحد للحقيقة)
│   ├── zap.py                     # قراءة تقارير ZAP وتحويل HTML إلى نص آمن
│   ├── policy.py                  # مؤشر السلامة وسياسة قرار الإطلاق
│   └── knowledge.py               # قاعدة المعرفة العربية للثغرات
│
├── backend/                       # منصة حماك (FastAPI) — انظر backend/README.md
│
├── docs/                          # وثائق ونماذج توضيحية
│   ├── sample_report.html         # نموذج تقرير حماك من zap/wrk/sample_zap_report.json
│   └── sample_summary.md          # نموذج ملخص سير العمل في GitHub Actions
│
├── zap/wrk/sample_zap_report.json # مثال لمخرجات ZAP يُستخدم في النماذج
├── index.html                     # منصة الويب التفاعلية ولوحة استعراض تقارير الفحص
├── LICENSE                        # ترخيص المشروع (MIT)
└── README.md                      # دليل التوثيق الرسمي للمشروع
```

---

## 🛡️ معايير الأمان والامتثال (Security & Compliance)

تعتمد المنظومة على مبادئ دليل المراجعة الأمنية الخاص بشركة أساس (`cyber/security-review`):
- التحقق الإلزامي من ترويسات الأمان الأساسية: CSP, HSTS, X-Content-Type-Options, Anti-Clickjacking.
- حماية نماذج البيانات والتحقق من متانة رموز منع تزوير الطلبات (Anti-CSRF).
- كشف مؤشرات تسريب المعلومات وأرقام الإصدارات في ترويسات الخوادم.
- فحص قيود ملفات تعريف الارتباط (`HttpOnly`, `Secure`, `SameSite`).
- **أمان التقرير نفسه:** كل ما يأتي من ملف ZAP (أوصاف الثغرات، الروابط، الأدلة، حمولات الهجوم) يُعامل كبيانات غير موثوقة؛ يُهرَّب في Python ويُعرض كنص فقط في المتصفح، ولا تُقبل إلا روابط `http/https`، فلا يمكن لموقع مفحوص حقن سكربت في التقرير.

---

<p align="center">
  <strong>حِماك · من شركة أساس للذكاء الاصطناعي &copy; 2026</strong><br>
  جميع الحقوق محفوظة | Himaak by ASAAS AI
</p>
