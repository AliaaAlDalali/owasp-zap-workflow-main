# -*- coding: utf-8 -*-
"""
Cybersecurity Knowledge Base & Metadata
Maps OWASP ZAP alerts to Modern Standard Arabic titles, OWASP Top 10 (2021),
CWE IDs, CVSS v3.1 scores & vectors, CIA Triad impact ratings, multi-language
remediation patches (Nginx, Apache, Python, Node.js, PHP), and verification checklists.
"""

CYBER_KNOWLEDGE = {
    "SQL Injection": {
        "name_ar": "حقن لغة الاستعلامات (SQL Injection)",
        "owasp": "A03:2021 - Injection",
        "cwe": "CWE-89",
        "cvss": "8.6 (High)",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "category_ar": "حقن الأوامر والبيانات (Injection)",
        "cia": {"c": "حرج (Critical)", "i": "مرتفع (High)", "a": "متوسط (Medium)"},
        "remediation_title": "الاستعلامات المجهزة واستخدام الـ ORM",
        "remediation_code": """# بايثون مع Psycopg2 أو SQLite:
cursor.execute("SELECT * FROM users WHERE email = %s AND status = %s", (email, status))

// Node.js مع مكتبة PostgreSQL (pg):
const query = 'SELECT * FROM users WHERE email = $1 AND status = $2';
const result = await pool.query(query, [email, status]);

// PHP مع PDO Prepared Statements:
$stmt = $pdo->prepare('SELECT * FROM users WHERE email = :email AND status = :status');
$stmt->execute(['email' => $email, 'status' => $status]);""",
        "checklist": [
            "حظر استخدام الربط النصي (String Concatenation) في كافة استعلامات قواعد البيانات.",
            "تطبيق مبدأ الصلاحيات الأقل (Least Privilege) لحسابات الربط بقواعد البيانات.",
            "إجراء فحص أمان الكود الثابت (SAST) والتحقق من سلامة كافة الدوال."
        ]
    },
    "Content Security Policy (CSP) Header Not Set": {
        "name_ar": "غياب ترويسة سياسة أمان المحتوى (CSP Header Missing)",
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-693",
        "cvss": "6.5 (Medium)",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "category_ar": "أخطاء التكوين الأمني (Security Misconfiguration)",
        "cia": {"c": "متوسط (Medium)", "i": "متوسط (Medium)", "a": "منخفض (Low)"},
        "remediation_title": "تفعيل ترويسة سياسة أمان المحتوى الصارمة",
        "remediation_code": """# إعدادات Nginx (في كتلة server):
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';" always;

# Node.js مع Express & Helmet:
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", "data:", "https:"],
    frameAncestors: ["'none'"]
  }
}));""",
        "checklist": [
            "تقييد مصادر تحميل السكربتات بـ 'self' وتجنب استخدام 'unsafe-eval'.",
            "حظر تضمين الموقع في إطارات خارجية عبر توجيه frame-ancestors 'none'.",
            "اختبار الترويسة أولاً عبر وضع Content-Security-Policy-Report-Only قبل التطبيق الصارم."
        ]
    },
    "Strict-Transport-Security Header Not Set": {
        "name_ar": "غياب ترويسة النقل الصارم الآمن (HSTS Missing)",
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-319",
        "cvss": "3.7 (Low)",
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "category_ar": "فشل التشفير والتكوين (Cryptographic Failures)",
        "cia": {"c": "متوسط (Medium)", "i": "منخفض (Low)", "a": "محدود (Minimal)"},
        "remediation_title": "إلزام التشفير الصارم عبر ترويسة HSTS",
        "remediation_code": """# إعدادات Nginx:
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

# التحويل الإجباري من HTTP إلى HTTPS برمز 301:
server {
    listen 80;
    server_name example.com *.example.com;
    return 301 https://$host$request_uri;
}""",
        "checklist": [
            "التأكد من سريان شهادة SSL/TLS لجميع النطاقات الفرعية.",
            "تعيين فترة صلاحية لا تقل عن عام كامل (max-age=31536000).",
            "إدراج النطاق في قائمة HSTS Preload للمتصفحات العالمية."
        ]
    },
    "Anti-CSRF Tokens Check": {
        "name_ar": "غياب رموز الحماية من تزوير الطلبات (Anti-CSRF Missing)",
        "owasp": "A01:2021 - Broken Access Control",
        "cwe": "CWE-352",
        "cvss": "6.5 (Medium)",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
        "category_ar": "كسر التحكم بالوصول (Broken Access Control)",
        "cia": {"c": "منخفض (Low)", "i": "مرتفع (High)", "a": "منخفض (Low)"},
        "remediation_title": "توليد والتحقق من رموز الحماية Anti-CSRF",
        "remediation_code": """<!-- تضمين رمز الحماية المشفر في جميع النماذج -->
<input type="hidden" name="csrf_token" value="{{ session.csrf_token }}" />

// إرسال الرمز برمجياً في ترويسات Fetch / Axios:
fetch('/api/v1/update-profile', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]').content
  },
  body: JSON.stringify(userData)
});

// تعيين كوكيز الجلسة بخاصية SameSite الصارمة:
Set-Cookie: session_id=xyz; Secure; HttpOnly; SameSite=Strict; Path=/;""",
        "checklist": [
            "ربط رمز CSRF بجلسة المستخدم والتحقق من تطابقه في الخادم مع كل طلب POST/PUT/DELETE.",
            "ضبط كوكيز الجلسة بخاصية SameSite=Strict و Secure.",
            "تجنب الاعتماد على طلبات GET لتنفيذ أي عمليات تعديل بيانات أو حذف."
        ]
    },
    "X-Content-Type-Options Header Missing": {
        "name_ar": "غياب ترويسة نوع المحتوى الصارم (X-Content-Type-Options)",
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-16",
        "cvss": "3.5 (Low)",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "category_ar": "أخطاء التكوين الأمني (Security Misconfiguration)",
        "cia": {"c": "منخفض (Low)", "i": "منخفض (Low)", "a": "محدود (Minimal)"},
        "remediation_title": "منع تخمين نوع المحتوى MIME-Type",
        "remediation_code": """# إعدادات Nginx:
add_header X-Content-Type-Options "nosniff" always;

# إعدادات Apache (.htaccess):
<IfModule mod_headers.c>
  Header always set X-Content-Type-Options "nosniff"
</IfModule>""",
        "checklist": [
            "تفعيل ترويسة nosniff لجميع أنواع الملفات بدون استثناء.",
            "التأكد من إرسال ترويسة Content-Type السليمة لملفات JavaScript و CSS."
        ]
    },
    "Missing Anti-clickjacking Header": {
        "name_ar": "غياب ترويسة منع الاختطاف بالنقر (Anti-Clickjacking Missing)",
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-1021",
        "cvss": "4.3 (Medium)",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
        "category_ar": "أخطاء التكوين الأمني (Security Misconfiguration)",
        "cia": {"c": "منخفض (Low)", "i": "متوسط (Medium)", "a": "محدود (Minimal)"},
        "remediation_title": "الحماية من الاختطاف بالنقر (Anti-Clickjacking)",
        "remediation_code": """# Nginx:
add_header X-Frame-Options "DENY" always;

# أو حصر التضمين في نفس النطاق:
add_header X-Frame-Options "SAMEORIGIN" always;""",
        "checklist": [
            "استخدام X-Frame-Options: DENY كخيار أساسي لمنع التضمين تماماً.",
            "تفعيل توجيه frame-ancestors 'none' داخل ترويسة CSP كطبقة دفاع ثانية."
        ]
    },
    "Server Leaks Version Information via \"Server\" HTTP Response Header Field": {
        "name_ar": "تسريب معلومات الخادم عبر ترويسة Server",
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-200",
        "cvss": "2.6 (Info)",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "category_ar": "كشف معلومات النظام (Information Disclosure)",
        "cia": {"c": "منخفض (Low)", "i": "محدود (Minimal)", "a": "محدود (Minimal)"},
        "remediation_title": "حجب معلومات إصدار الخادم ونوع البرمجيات",
        "remediation_code": """# في ملف nginx.conf داخل كتلة http:
http {
    server_tokens off;
}

# في خوادم Apache (httpd.conf):
ServerTokens Prod
ServerSignature Off""",
        "checklist": [
            "تعطيل server_tokens لمنع كشف رقم إصدار Nginx أو Apache.",
            "إزالة أو تعتيم ترويسات X-Powered-By التابعة لـ PHP أو Express."
        ]
    },
    "Timestamp Disclosure - Unix": {
        "name_ar": "كشف التوقيت الزمني للخادم (Unix Timestamp Disclosure)",
        "owasp": "A04:2021 - Insecure Design / Info Disclosure",
        "cwe": "CWE-200",
        "cvss": "2.1 (Info)",
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "category_ar": "كشف معلومات النظام (Information Disclosure)",
        "cia": {"c": "منخفض (Low)", "i": "محدود (Minimal)", "a": "محدود (Minimal)"},
        "remediation_title": "إزالة الطوابع الزمنية الخام من الاستجابات العامة",
        "remediation_code": """# بايثون / FastAPI:
@app.middleware("http")
async def sanitize_headers(request, call_next):
    response = await call_next(request)
    response.headers.pop("X-Timestamp", None)
    return response""",
        "checklist": [
            "مراجعة استجابات الـ API والتأكد من عدم كشف تواريخ بناء البرمجية الداخلية.",
            "استخدام تواريخ قياسية بصيغة ISO-8601 عند الحاجة لتبادل التواريخ."
        ]
    },
    "Cross Site Scripting (Reflected)": {
        "name_ar": "هجمات البرمجة عبر المواقع المنعكسة (Reflected XSS)",
        "owasp": "A03:2021 - Injection",
        "cwe": "CWE-79",
        "cvss": "7.1 (High)",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "category_ar": "حقن الأوامر والبيانات (Injection)",
        "cia": {"c": "متوسط (Medium)", "i": "مرتفع (High)", "a": "منخفض (Low)"},
        "remediation_title": "الترميز الآمن للمخرجات واستخدام محركات القوالب الآمنة",
        "remediation_code": """# في جافاسكريبت / React / Vue:
// تجنب استخدام dangerouslySetInnerHTML أو innerHTML
element.textContent = sanitizeUserInput(input);

# في بايثون / Jinja2:
{{ user_input | e }}  {# التشفير التلقائي لمخرجات HTML #}""",
        "checklist": [
            "الاعتماد على الترميز السياقي لكافة المدخلات المنعكسة (Contextual Encoding).",
            "تفعيل ترويسة Content-Security-Policy مع منع unsafe-inline.",
            "حظر استخدام eval() أو innerHTML مع بيانات المستخدم."
        ]
    },
    "Cookie No HttpOnly Flag": {
        "name_ar": "ملف تعريف ارتباط يفتقر إلى حماية HttpOnly",
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-1004",
        "cvss": "5.3 (Medium)",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "category_ar": "إدارة الجلسات والكوكيز (Session Management)",
        "cia": {"c": "مرتفع (High)", "i": "منخفض (Low)", "a": "محدود (Minimal)"},
        "remediation_title": "إلزام حماية HttpOnly لكوكيز الجلسة",
        "remediation_code": """# في ترويسات الاستجابة:
Set-Cookie: session_id=abc123xyz; Secure; HttpOnly; SameSite=Strict; Path=/;""",
        "checklist": [
            "منع وصول سكربتات المتصفح لكوكيز الجلسة عبر document.cookie.",
            "إقران السمة بسمات Secure و SameSite=Strict دائماً."
        ]
    }
}


# ZAP plugin IDs for the entries above. ZAP renames alerts between versions
# (e.g. "Anti-CSRF Tokens Check" is now "Absence of Anti-CSRF Tokens"), but plugin IDs stay.
PLUGIN_KNOWLEDGE = {
    "40018": "SQL Injection",
    "10038": "Content Security Policy (CSP) Header Not Set",
    "10035": "Strict-Transport-Security Header Not Set",
    "10202": "Anti-CSRF Tokens Check",
    "20012": "Anti-CSRF Tokens Check",
    "10021": "X-Content-Type-Options Header Missing",
    "10020": "Missing Anti-clickjacking Header",
    "10036": 'Server Leaks Version Information via "Server" HTTP Response Header Field',
    "10096": "Timestamp Disclosure - Unix",
    "40012": "Cross Site Scripting (Reflected)",
    "10010": "Cookie No HttpOnly Flag",
}

# Arabic titles for common ZAP baseline alerts that have no full entry yet.
# Shown as "Arabic (ZAP name)", so variants that share a plugin ID stay distinct.
ARABIC_TITLES = {
    "2": "كشف عنوان IP داخلي",
    "10003": "مكتبة JavaScript معروفة الثغرات",
    "10009": "تسريب معلومات الخادم داخل الصفحة",
    "10011": "ملف تعريف ارتباط بدون خاصية Secure",
    "10015": "مراجعة توجيهات التخزين المؤقت",
    "10017": "تضمين ملفات JavaScript من نطاق خارجي",
    "10019": "غياب ترويسة نوع المحتوى (Content-Type)",
    "10023": "كشف رسائل تصحيح الأخطاء",
    "10024": "كشف معلومات حساسة في الرابط",
    "10025": "كشف معلومات حساسة في ترويسة Referer",
    "10027": "تعليقات في الشيفرة قد تكشف معلومات",
    "10028": "إعادة توجيه إلى موقع خارجي",
    "10031": "خاصية HTML يتحكم بها المستخدم (احتمال XSS)",
    "10037": "تسريب معلومات الخادم عبر ترويسة X-Powered-By",
    "10039": "تسريب معلومات عبر ترويسة X-Backend-Server",
    "10040": "محتوى غير مشفّر داخل صفحات آمنة",
    "10041": "نموذج ينتقل من HTTP إلى HTTPS بشكل غير آمن",
    "10042": "نموذج يرسل من HTTPS إلى HTTP بشكل غير آمن",
    "10043": "حدث JavaScript يتحكم به المستخدم (احتمال XSS)",
    "10044": "إعادة توجيه تكشف محتوى الصفحة",
    "10049": "محتوى قابل للتخزين المؤقت",
    "10050": "استجابة مسترجعة من التخزين المؤقت",
    "10054": "ملف تعريف ارتباط بدون خاصية SameSite",
    "10055": "ضعف في سياسة أمان المحتوى",
    "10056": "كشف معلومات تصحيح عبر ترويسة X-Debug-Token",
    "10061": "كشف إصدار ASP.NET في الترويسات",
    "10062": "كشف معلومات شخصية",
    "10063": "غياب ترويسة سياسة الأذونات (Permissions Policy)",
    "10094": "كشف بيانات مرمّزة بـ Base64",
    "10097": "كشف قيم تجزئة (Hash)",
    "10098": "إعدادات خاطئة لمشاركة الموارد بين النطاقات",
    "10099": "كشف الشيفرة المصدرية",
    "10105": "طريقة مصادقة ضعيفة",
    "10106": "موقع يعمل بـ HTTP فقط دون HTTPS",
    "10108": "ثغرة الاستيلاء على التبويب العكسي (Reverse Tabnabbing)",
    "10109": "تطبيق ويب حديث",
    "10110": "استخدام دوال JavaScript خطرة",
    "10111": "رصد طلب مصادقة",
    "10112": "رصد استجابة لإدارة الجلسات",
    "90003": "غياب خاصية سلامة الموارد الفرعية (SRI)",
    "90004": "غياب ترويسات العزل بين المصادر",
    "90011": "عدم تطابق ترميز الأحرف",
    "90022": "كشف رسائل أخطاء التطبيق",
    "90033": "ملف تعريف ارتباط بنطاق واسع",
}


def knowledge_for(plugin_id, alert_name):
    """The knowledge entry for an alert: exact name first, then ZAP plugin ID, then an Arabic title only."""
    if alert_name in CYBER_KNOWLEDGE:
        return CYBER_KNOWLEDGE[alert_name]
    key = PLUGIN_KNOWLEDGE.get(plugin_id)
    if key:
        return CYBER_KNOWLEDGE[key]
    title = ARABIC_TITLES.get(plugin_id)
    return {"name_ar": f"{title} ({alert_name})"} if title else {}
