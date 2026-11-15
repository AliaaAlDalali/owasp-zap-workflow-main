# -*- coding: utf-8 -*-
"""
Builds index.html, the Himaak (حِماك) dashboard: sample reports switcher,
client-side viewer for any zap_report.json, finding inspector and assistant.

Run from anywhere:  python scripts/build_index.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from generate_report import (  # noqa: E402
    PROJECT_ROOT, SAFE_RENDER_JS, esc, json_for_script, summarize_report,
    get_inlined_brand_css, get_assistant_assets_b64, load_file_b64,
)

project_root = PROJECT_ROOT

inlined_css = get_inlined_brand_css(project_root)
asst_b64 = get_assistant_assets_b64(project_root)
favicon_b64 = load_file_b64(os.path.join(project_root, "assets", "images", "favicon.png"))

# Pre-configured reports data with rich arabic remediation
REPORTS_DATA = {
    "webapp": {
        "@version": "OWASP ZAP 2.14.0",
        "@generated": "Sun, 8 Nov 2026 12:45:00",
        "site": [{
            "@name": "https://example-corp.ai-asaas.com",
            "alerts": [
                {
                    "pluginid": "40018",
                    "name": "SQL Injection",
                    "name_ar": "حقن لغة الاستعلامات (SQL Injection)",
                    "riskcode": "3",
                    "count": 1,
                    "cweid": "89",
                    "wascid": "19",
                    "desc": "<p>تم رصد احتمالية وجود ثغرة حقن أوامر SQL. يمكن للمهاجم التلاعب باستعلامات قاعدة البيانات الخلفية مما يتيح الوصول غير المصرح به للبيانات وتجاوز قيود التحقق.</p>",
                    "solution": "<p>استخدم الاستعلامات المجهزة (Prepared Statements / Parameterized Queries) أو أطر عمل ORM الحديثة مع تجنب دمج المدخلات نصياً إطلاقاً.</p>",
                    "reference": "<p>https://owasp.org/www-community/attacks/SQL_Injection<br>https://cwe.mitre.org/data/definitions/89.html</p>",
                    "remediation_code": "# بايثون مع Psycopg2 / SQLite:\ncursor.execute('SELECT * FROM users WHERE email = %s AND status = %s', (email, status))\n\n// Node.js مع PostgreSQL (pg):\nconst res = await pool.query('SELECT * FROM users WHERE email = $1', [email]);",
                    "instances": [
                        {
                            "uri": "https://example-corp.ai-asaas.com/api/v1/search?q=test",
                            "method": "GET",
                            "param": "q",
                            "attack": "' OR '1'='1' --",
                            "evidence": "syntax error at or near 'OR' at character 42"
                        }
                    ]
                },
                {
                    "pluginid": "10038",
                    "name": "Content Security Policy (CSP) Header Not Set",
                    "name_ar": "غياب ترويسة سياسة أمان المحتوى (CSP Header Missing)",
                    "riskcode": "2",
                    "count": 2,
                    "cweid": "693",
                    "wascid": "15",
                    "desc": "<p>ترويسة Content Security Policy غير محددة في استجابة الخادم. هذه الترويسة أساسية لتقييد مصادر تحميل السكربتات ومنع هجمات XSS وتضمين الإطارات الخبيثة.</p>",
                    "solution": "<p>قم بتهيئة خادم الويب أو البوابة العكسية (Nginx) لإرسال ترويسة Content-Security-Policy مع تقييد المصادر المصرح بها.</p>",
                    "reference": "<p>https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP<br>https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html</p>",
                    "remediation_code": "# Nginx Configuration:\nadd_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none';\" always;",
                    "instances": [
                        {
                            "uri": "https://example-corp.ai-asaas.com/",
                            "method": "GET",
                            "param": "",
                            "attack": "",
                            "evidence": ""
                        },
                        {
                            "uri": "https://example-corp.ai-asaas.com/login",
                            "method": "GET",
                            "param": "",
                            "attack": "",
                            "evidence": ""
                        }
                    ]
                },
                {
                    "pluginid": "10202",
                    "name": "Anti-CSRF Tokens Check",
                    "name_ar": "غياب رموز الحماية من تزوير الطلبات (Anti-CSRF Missing)",
                    "riskcode": "2",
                    "count": 1,
                    "cweid": "352",
                    "wascid": "9",
                    "desc": "<p>تم العثور على نموذج إرسال بيانات يفتقر إلى رمز التحقق ضد تزوير الطلبات عبر المواقع (Anti-CSRF Token). يمكن للمهاجم خداع مستخدم مسجل الدخول لتنفيذ عمليات غير مرغوب فيها.</p>",
                    "solution": "<p>قم بتوليد رموز CSRF مشفرة عشوائية لكل جلسة وتحقق منها في كافة طلبات POST و PUT و DELETE، واستخدم كوكيز SameSite=Strict.</p>",
                    "reference": "<p>https://owasp.org/www-community/attacks/csrf<br>https://cwe.mitre.org/data/definitions/352.html</p>",
                    "remediation_code": "<!-- تضمين رمز الحماية في النموذج -->\n<input type=\"hidden\" name=\"csrf_token\" value=\"{{ session.csrf_token }}\" />\n\n// التحقق في ترويسات Fetch:\nfetch('/api/v1/action', {\n  headers: { 'X-CSRF-Token': csrfToken }\n});",
                    "instances": [
                        {
                            "uri": "https://example-corp.ai-asaas.com/account/update",
                            "method": "POST",
                            "param": "email",
                            "attack": "",
                            "evidence": "<form action=\"/account/update\" method=\"POST\">"
                        }
                    ]
                },
                {
                    "pluginid": "10035",
                    "name": "Strict-Transport-Security Header Not Set",
                    "name_ar": "غياب ترويسة النقل الصارم الآمن (HSTS Missing)",
                    "riskcode": "1",
                    "count": 1,
                    "cweid": "319",
                    "wascid": "15",
                    "desc": "<p>ترويسة Strict-Transport-Security غير مفعلة. يتيح غيابها للمهاجمين محاولة خفض التشفير (SSL Stripping) وتوجيه المستخدم لاتصال غير مشفر.</p>",
                    "solution": "<p>قم بتهيئة الخادم لإرسال ترويسة Strict-Transport-Security مع صلاحية لا تقل عن عام كامل وتضمين النطاقات الفرعية.</p>",
                    "reference": "<p>https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security</p>",
                    "remediation_code": "# Nginx Configuration:\nadd_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;",
                    "instances": [
                        {
                            "uri": "https://example-corp.ai-asaas.com/",
                            "method": "GET",
                            "param": "",
                            "attack": "",
                            "evidence": ""
                        }
                    ]
                },
                {
                    "pluginid": "10096",
                    "name": "Timestamp Disclosure - Unix",
                    "name_ar": "كشف التوقيت الزمني للخادم (Unix Timestamp Disclosure)",
                    "riskcode": "0",
                    "count": 1,
                    "cweid": "200",
                    "wascid": "13",
                    "desc": "<p>تم رصد كشف طابع زمني بتنسيق Unix Epoch في استجابة الخادم. قد يفيد ذلك المهاجمين في استنتاج توقيت بناء البرمجية أو تزامن الخوادم.</p>",
                    "solution": "<p>تأكد من عدم كشف توقيتات الخوادم الداخلية أو تواريخ التصحيح في الاستجابات العامة.</p>",
                    "reference": "<p>https://cwe.mitre.org/data/definitions/200.html</p>",
                    "remediation_code": "# إزالة الترويسات التي تكشف التوقيت الداخلي\nresponse.headers.pop('X-Timestamp', None)",
                    "instances": [
                        {
                            "uri": "https://example-corp.ai-asaas.com/assets/app.js",
                            "method": "GET",
                            "param": "",
                            "attack": "",
                            "evidence": "1731062700"
                        }
                    ]
                }
            ]
        }]
    },
    "api": {
        "@version": "OWASP ZAP 2.14.0 API Scan",
        "@generated": "Sun, 8 Nov 2026 11:30:00",
        "site": [{
            "@name": "https://api.ai-asaas.com/v1",
            "alerts": [
                {
                    "pluginid": "10038",
                    "name": "Content Security Policy (CSP) Header Not Set",
                    "name_ar": "غياب ترويسة سياسة أمان المحتوى (CSP Header Missing)",
                    "riskcode": "2",
                    "count": 1,
                    "cweid": "693",
                    "wascid": "15",
                    "desc": "<p>غياب ترويسة CSP عن نقاط نهاية واجهة برمجة التطبيقات API.</p>",
                    "solution": "<p>إضافة ترويسة CSP قياسية حتى لو كانت الاستجابة JSON لمنع حقن نصوص في المتصفحات.</p>",
                    "reference": "<p>https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP</p>",
                    "remediation_code": "add_header Content-Security-Policy \"default-src 'none'; frame-ancestors 'none';\" always;",
                    "instances": [{ "uri": "https://api.ai-asaas.com/v1/users", "method": "GET", "param": "", "attack": "", "evidence": "" }]
                },
                {
                    "pluginid": "10036",
                    "name": "Server Leaks Version Information via \"Server\" HTTP Response Header Field",
                    "name_ar": "تسريب معلومات الخادم عبر ترويسة Server",
                    "riskcode": "1",
                    "count": 1,
                    "cweid": "200",
                    "wascid": "13",
                    "desc": "<p>ترويسة Server تكشف اسم الخادم وإصداره التفصيلي (nginx/1.24.0).</p>",
                    "solution": "<p>قم بتعطيل كشف إصدار الخادم عبر server_tokens off في Nginx.</p>",
                    "reference": "<p>https://cwe.mitre.org/data/definitions/200.html</p>",
                    "remediation_code": "# nginx.conf\nserver_tokens off;",
                    "instances": [{ "uri": "https://api.ai-asaas.com/v1/health", "method": "GET", "param": "", "attack": "", "evidence": "Server: nginx/1.24.0 (Ubuntu)" }]
                },
                {
                    "pluginid": "10096",
                    "name": "Timestamp Disclosure - Unix",
                    "name_ar": "كشف التوقيت الزمني للخادم (Unix Timestamp Disclosure)",
                    "riskcode": "0",
                    "count": 1,
                    "cweid": "200",
                    "wascid": "13",
                    "desc": "<p>كشف حقل التوقيت في استجابة فحص الصحة health check.</p>",
                    "solution": "<p>لا يشكل خطراً مباشراً إذا كان توقيت استجابة قياسياً.</p>",
                    "reference": "<p>https://cwe.mitre.org/data/definitions/200.html</p>",
                    "remediation_code": "// توثيق الحقل فقط دون حاجة لتغيير",
                    "instances": [{ "uri": "https://api.ai-asaas.com/v1/status", "method": "GET", "param": "", "attack": "", "evidence": "\"ts\": 1731062800" }]
                }
            ]
        }]
    },
    "auth": {
        "@version": "OWASP ZAP 2.14.0 Auth Suite",
        "@generated": "Sat, 7 Nov 2026 18:20:00",
        "site": [{
            "@name": "https://auth.ai-asaas.com",
            "alerts": [
                {
                    "pluginid": "10096",
                    "name": "Timestamp Disclosure - Unix",
                    "name_ar": "كشف التوقيت الزمني للخادم (Unix Timestamp Disclosure)",
                    "riskcode": "0",
                    "count": 1,
                    "cweid": "200",
                    "wascid": "13",
                    "desc": "<p>كشف توقيت صلاحية توكن OAuth في ترويسات المصادقة.</p>",
                    "solution": "<p>استخدام تواريخ بتنسيق ISO-8601 القياسي.</p>",
                    "reference": "<p>https://cwe.mitre.org/data/definitions/200.html</p>",
                    "remediation_code": "// ممارسة مقبولة وفق معايير JWT",
                    "instances": [{ "uri": "https://auth.ai-asaas.com/oauth/token", "method": "POST", "param": "", "attack": "", "evidence": "\"exp\": 1731066400" }]
                }
            ]
        }]
    }
}

reports_json_str = json_for_script(REPORTS_DATA)

# Sample report cards: score, status and finding counts are computed from the data
# with the same policy as the report generator, so the labels can never drift.
REPORT_CARDS = [
    ("webapp", "تقرير فحص بوابة الخدمات الرئيسية", "Production Web Application Scan", "OWASP ZAP 2.14"),
    ("api", "تقرير فحص واجهات البرمجة (APIs)", "REST & GraphQL Gateway Scan", "ZAP API Scan"),
    ("auth", "تقرير فحص بوابة الهوية والنفاذ", "Identity & SSO Service Scan", "Auth Hardening"),
]
RELEASE_PILL = {"blocked": "pill--high", "conditional": "pill--medium", "approved": "pill--paid"}


def build_report_cards():
    cards = []
    for i, (key, title_ar, title_en, tag) in enumerate(REPORT_CARDS):
        s = summarize_report(REPORTS_DATA[key])
        date = " ".join(s["generated_at"].split(" ")[:4])
        active = " is-active" if i == 0 else ""
        cards.append(f"""
        <div class="card glass report-select-card{active}" id="card-{esc(key)}" onclick="switchReport('{esc(key)}', this)">
          <div class="report-select-header">
            <span class="pill {RELEASE_PILL[s['release_status']]}" data-ar="{esc(s['status_ar'])} ({s['score']}/100)" data-en="{esc(s['status_en'])} ({s['score']}/100)">{esc(s['status_ar'])} ({s['score']}/100)</span>
            <span class="pill pill--tag">{esc(tag)}</span>
          </div>
          <div class="report-select-title">
            <span class="swash" data-ar="{esc(title_ar)}" data-en="{esc(title_en)}">{esc(title_ar)}</span>
          </div>
          <div class="subtle" style="font-size: 13px; direction: ltr; text-align: start;">{esc(s['target_url'])}</div>
          <div class="report-select-meta">
            <span><span class="num">{s['total_alerts']}</span> <span data-ar="ملاحظات أمنية" data-en="findings">ملاحظات أمنية</span></span>
            <span class="num">{esc(date)}</span>
          </div>
        </div>""")
    return "\n".join(cards)


report_cards_html = build_report_cards()

html_content = f"""<!DOCTYPE html>
<html lang="ar" dir="rtl" data-theme="light">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
  <title>حِماك | منصة أتمتة الفحص الأمني</title>
  <link rel="icon" type="image/png" href="data:image/png;base64,{favicon_b64}">
  <style>
    {inlined_css}
  </style>
  <script>
    (function() {{
      try {{
        var t = localStorage.getItem('asaas-theme');
        if (t) {{
          document.documentElement.setAttribute('data-theme', t);
          document.documentElement.dataset.theme = t;
        }}
        var l = localStorage.getItem('asaas-lang');
        if (l) {{
          document.documentElement.setAttribute('lang', l);
          document.documentElement.setAttribute('dir', l === 'ar' ? 'rtl' : 'ltr');
        }}
      }} catch(e) {{}}
    }})();
  </script>
</head>
<body>

  <!-- Ambient glowing background -->
  <div class="ambient" aria-hidden="true">
    <div class="ambient__orb ambient__orb--1"></div>
    <div class="ambient__orb ambient__orb--2"></div>
    <div class="ambient__orb ambient__orb--3"></div>
  </div>

  <!-- Header Navigation -->
  <header class="app-header glass glass--thick">
    <div class="container app-header__inner">
      <div class="brand">
        <div class="brand__mark" aria-label="شعار حماك"></div>
        <div>
          <div class="brand__name"><span class="swash">حِمَــاك</span> <span class="hide-mobile" style="font-size: 15px; font-weight: 500; color: var(--accent);">من أساس</span></div>
          <div class="brand__tag hide-mobile" data-ar="منظومة أتمتة الفحص الأمني المتقدم" data-en="Automated Security Assessment System">منظومة أتمتة الفحص الأمني المتقدم</div>
        </div>
      </div>

      <div class="header-actions">
        <!-- Language Switcher -->
        <button class="btn btn--glass btn--sm" onclick="toggleLanguage()" title="Switch Language" id="langBtn">
          <span>English</span>
        </button>

        <!-- Theme Switcher -->
        <button class="btn btn--glass btn--icon btn--sm" id="themeBtn" onclick="toggleTheme()" title="تبديل المظهر" aria-label="تبديل المظهر">
          <svg id="themeIcon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5Z"/>
          </svg>
        </button>

        <!-- Standalone Report Links -->
        <a href="docs/sample_report.html" class="btn btn--glass btn--sm hide-mobile" title="فتح التقرير المستقل الكامل">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width: 14px; height: 14px;"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6M15 3h6v6M10 14 21 3"/></svg>
          <span data-ar="التقرير المستقل" data-en="Standalone Report">التقرير المستقل</span>
        </a>

        <!-- Print/Export -->
        <button class="btn btn--primary btn--sm hide-mobile" onclick="window.print()">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 9V2h12v7M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2M6 14h12v8H6z"/></svg>
          <span data-ar="تصدير / طباعة" data-en="Export / Print">تصدير / طباعة</span>
        </button>
      </div>
    </div>
  </header>

  <!-- Main Content Container -->
  <main class="container page" style="margin-bottom: 70px;">

    <!-- ───────── Reports Selector Deck ───────── -->
    <section class="section" style="margin-bottom: 24px;">
      <div style="display: flex; align-items: baseline; justify-content: space-between; margin-bottom: 14px; flex-wrap: wrap; gap: 8px;">
        <h3 style="font-family: var(--font-display); font-size: 20px; font-weight: 700; margin: 0;">
          <span class="swash" data-ar="التقارير الأمنية المعتمدة" data-en="Verified Security Reports">التقارير الأمنية المعتمدة</span>
        </h3>
        <span class="subtle" data-ar="انقر على أي تقرير لاستعراض تحليله الأمني فوراً" data-en="Click any report to view immediate security analysis">انقر على أي تقرير لاستعراض تحليله الأمني فوراً</span>
      </div>

      <div class="reports-grid" id="reportsDeck">
{report_cards_html}

      </div>
    </section>

      <!-- Filter Empty State -->
      <div class="card glass filter-empty" id="filterEmptyState" style="display: none; padding: 40px 20px; text-align: center; margin-top: 14px; margin-bottom: 24px;">
        <div style="font-size: 32px; margin-bottom: 8px;">🔍</div>
        <h4 style="margin: 0 0 6px; font-family: var(--font-display);" data-ar="لا توجد نتائج تطابق معايير البحث أو التصفية" data-en="No results match your search or filter">لا توجد نتائج تطابق معايير البحث أو التصفية</h4>
        <p class="subtle" style="font-size: 13.5px; margin: 0 0 16px;" data-ar="جرب تغيير مستوى الخطورة المحدد أو البحث بكلمات أخرى" data-en="Try changing the active risk level or search keyword">جرب تغيير مستوى الخطورة المحدد أو البحث بكلمات أخرى</p>
        <div>
          <button type="button" class="btn btn--glass btn--sm" onclick="resetFilters()">
            <span data-ar="إعادة ضبط التصفية" data-en="Reset Filter">إعادة ضبط التصفية</span>
          </button>
        </div>
      </div>


    <!-- Top Tools & Launcher Grid -->
    <div class="grid grid--halves no-print" style="margin-bottom: 24px;">
      
      <!-- Quick Scan Config Card -->
      <div class="card glass" style="padding: 22px;">
        <div class="card__header">
          <div class="card__title">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="m10 15 5-3-5-3v6z"/></svg>
            <h3 data-ar="تشغيل فحص جديد" data-en="Launch Security Scan">تشغيل فحص جديد</h3>
          </div>
          <span class="pill pill--paid" data-ar="جاهز للتشغيل" data-en="Ready">جاهز للتشغيل</span>
        </div>

        <div class="form">
          <div class="field">
            <label class="field__label" data-ar="رابط الموقع أو الواجهة المستهدفة:" data-en="Target Web Application URL:">رابط الموقع أو الواجهة المستهدفة:</label>
            <input type="url" id="targetUrlInput" class="input" placeholder="https://example.com" value="https://example-corp.ai-asaas.com" oninput="updateCliCommands()">
          </div>

          <div class="field">
            <label class="field__label" data-ar="أمر التشغيل عبر GitHub Actions CLI:" data-en="GitHub Actions CLI Trigger Command:">أمر التشغيل عبر GitHub Actions CLI:</label>
            <div class="cli-box" id="ghCliBox" style="position: relative;">
              <code id="cliCommandText">gh workflow run zap-scan.yml -f target_url="https://example-corp.ai-asaas.com"</code>
              <button class="btn btn--glass btn--sm" style="position: absolute; inset-inline-end: 6px; top: 6px; font-size: 11px; padding: 4px 8px;" onclick="copyCliCommand()">نسخ</button>
            </div>
          </div>
        </div>
      </div>

      <!-- JSON Report Dropzone -->
      <div class="card glass" style="padding: 22px;">
        <div class="card__header">
          <div class="card__title">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/></svg>
            <h3 data-ar="تحميل تقرير فحص خارجي (JSON)" data-en="Upload External ZAP JSON">تحميل تقرير فحص خارجي (JSON)</h3>
          </div>
          <span class="pill pill--tag" data-ar="استعراض فوري" data-en="Instant Viewer">استعراض فوري</span>
        </div>

        <div class="dropzone" id="portalDropzone" onclick="document.getElementById('fileInput').click()">
          <input type="file" id="fileInput" accept=".json" style="display: none;" onchange="handleFileSelect(event)">
          <div class="dropzone__icon">
            <svg viewBox="0 0 24 24" width="22" height="22" style="width: 22px; height: 22px;" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6M16 13H8M16 17H8M10 9H8"/>
            </svg>
          </div>
          <div>
            <strong style="font-size: 14.5px; color: var(--text);" data-ar="اسحب وأفلت ملف zap_report.json هنا" data-en="Drag & drop zap_report.json here">اسحب وأفلت ملف zap_report.json هنا</strong>
            <p class="subtle" style="margin-top: 4px;" data-ar="أو انقر لاختيار الملف من جهازك لتحليله فوراً في المتصفح" data-en="or click to browse from your device for client-side rendering">أو انقر لاختيار الملف من جهازك لتحليله فوراً في المتصفح</p>
          </div>
        </div>
      </div>

    </div>

    <!-- ───────── Live Interactive Report Section ───────── -->
    <div id="reportView">
      
      <!-- Executive Release Decision Gate -->
      <div class="card glass release-card" id="releaseDecisionCard" style="margin-bottom: 20px;">
        <div class="release-card__info">
          <div class="release-card__title">
            <span id="releaseIcon">🔴</span>
            <span id="releaseTitleAr">حظر الإطلاق للإنتاج (Release Blocked)</span>
          </div>
          <p class="release-card__desc" id="releaseDescAr">
            تم رصد ثغرات أمنية عالية الخطورة تهدد سرية وسلامة البيانات. يُمنع النشر للإنتاج حتى اكتمال المعالجة وإعادة الفحص.
          </p>
        </div>
        <div class="release-card__meta">
          <span class="pill pill--unpaid" id="releaseBadge">BLOCKED</span>
          <span class="subtle" id="releaseTimeline" style="font-size: 12px;">مهلة الترقيع: فوري قبل النشر</span>
        </div>
      </div>

      <!-- Target Info Card -->
      <div class="card glass target-card" style="margin-bottom: 20px;">
        <div class="target-url">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
          <div>
            <span class="subtle" data-ar="الهدف المفحوص:" data-en="Target System:">الهدف المفحوص:</span>
            <a href="https://example-corp.ai-asaas.com" id="displayTargetUrl" target="_blank" rel="noopener noreferrer" style="color: var(--accent); text-decoration: underline;">https://example-corp.ai-asaas.com</a>
          </div>
        </div>

        <div class="target-badge">
          <span class="pill pill--tag" id="displayZapVersion">Engine: OWASP ZAP 2.14.0</span>
          <span class="pill pill--tag"><span class="num" id="displayTimestamp">Sun, 8 Nov 2026 12:45:00</span></span>
        </div>
      </div>

      <!-- Executive Score & KPIs Grid -->
      <div class="grid grid--halves" style="margin-bottom: 20px;">
        <!-- Health Score Card -->
        <div class="card glass score-card">
          <div class="score-display">
            <div class="score-circle">
              <svg viewBox="0 0 96 96">
                <circle class="score-track" cx="48" cy="48" r="40" />
                <circle class="score-fill" id="scoreCircleFill" cx="48" cy="48" r="40" 
                        stroke="var(--partial)" 
                        stroke-dasharray="251.32" 
                        stroke-dashoffset="120.6" />
              </svg>
              <div class="score-value" id="scoreValueText" style="color: var(--partial);">
                <span class="num" id="scoreNumber">52</span>
                <small>/ 100</small>
              </div>
            </div>
            <div class="score-info">
              <div class="score-title" data-ar="مؤشر السلامة الأمنية" data-en="Security Health Score">مؤشر السلامة الأمنية</div>
              <div class="score-status">
                <span class="pill" id="scoreStatusBadge" style="background: var(--glass-inset); border: 1px solid var(--partial); color: var(--partial);">
                  <span id="scoreStatusText" data-ar="متوسط / مخاطر محتملة" data-en="Warning / Action Required">متوسط / مخاطر محتملة</span>
                </span>
              </div>
              <p class="subtle" data-ar="تقييم الامتثال الأمني وفق منهجية OWASP المعتمدة" data-en="Compliance rating based on official OWASP framework">تقييم الامتثال الأمني وفق منهجية OWASP المعتمدة</p>
            </div>
          </div>
        </div>

        <!-- Quick Stats Grid -->
        <div class="grid grid--stats" style="grid-template-columns: repeat(2, minmax(0, 1fr));">
          <div class="card glass stat">
            <div class="stat__label">
              <div class="stat__icon" style="color: var(--unpaid);"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 9v4M12 17h.01M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0z"/></svg></div>
              <span data-ar="عالية الخطورة" data-en="High Risk">عالية الخطورة</span>
            </div>
            <div class="stat__value" style="color: var(--unpaid);"><span class="num" id="statHigh">1</span></div>
            <div class="stat__foot" data-ar="تتطلب معالجة فورية" data-en="Requires immediate fix">تتطلب معالجة فورية</div>
          </div>

          <div class="card glass stat">
            <div class="stat__label">
              <div class="stat__icon" style="color: var(--partial);"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 8v4M12 16h.01M3.3 20h17.4a2 2 0 0 0 1.7-3L13.7 4a2 2 0 0 0-3.4 0L1.6 17a2 2 0 0 0 1.7 3z"/></svg></div>
              <span data-ar="متوسطة الخطورة" data-en="Medium Risk">متوسطة الخطورة</span>
            </div>
            <div class="stat__value" style="color: var(--partial);"><span class="num" id="statMed">2</span></div>
            <div class="stat__foot" data-ar="معالجة مجدولة" data-en="Scheduled remediation">معالجة مجدولة</div>
          </div>

          <div class="card glass stat">
            <div class="stat__label">
              <div class="stat__icon" style="color: var(--paid);"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="m8 12 3 3 5-5"/></svg></div>
              <span data-ar="منخفضة الخطورة" data-en="Low Risk">منخفضة الخطورة</span>
            </div>
            <div class="stat__value" style="color: var(--paid);"><span class="num" id="statLow">1</span></div>
            <div class="stat__foot" data-ar="تحسينات وقائية" data-en="Preventive hardening">تحسينات وقائية</div>
          </div>

          <div class="card glass stat">
            <div class="stat__label">
              <div class="stat__icon" style="color: var(--chart-out);"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 16v-4M12 8h.01"/></svg></div>
              <span data-ar="معلوماتية" data-en="Informational">معلوماتية</span>
            </div>
            <div class="stat__value" style="color: var(--chart-out);"><span class="num" id="statInfo">1</span></div>
            <div class="stat__foot" data-ar="ملاحظات توثيقية" data-en="Informational notes">ملاحظات توثيقية</div>
          </div>
        </div>
      </div>

      <!-- Filter & Search Toolbar -->
      <div class="toolbar" style="margin-top: 10px;">
        <div class="segmented" id="riskFilters">
          <button class="segmented__option" data-filter="all" aria-pressed="true" onclick="filterByRisk('all')">
            <span data-ar="الكل" data-en="All">الكل</span>
            <span class="segmented__count num" id="filterCountAll">5</span>
          </button>
          <button class="segmented__option" data-filter="3" aria-pressed="false" onclick="filterByRisk('3')">
            <span data-ar="عالية" data-en="High">عالية</span>
            <span class="segmented__count num" id="filterCountHigh">1</span>
          </button>
          <button class="segmented__option" data-filter="2" aria-pressed="false" onclick="filterByRisk('2')">
            <span data-ar="متوسطة" data-en="Medium">متوسطة</span>
            <span class="segmented__count num" id="filterCountMed">2</span>
          </button>
          <button class="segmented__option" data-filter="1" aria-pressed="false" onclick="filterByRisk('1')">
            <span data-ar="منخفضة" data-en="Low">منخفضة</span>
            <span class="segmented__count num" id="filterCountLow">1</span>
          </button>
          <button class="segmented__option" data-filter="0" aria-pressed="false" onclick="filterByRisk('0')">
            <span data-ar="معلوماتية" data-en="Info">معلوماتية</span>
            <span class="segmented__count num" id="filterCountInfo">1</span>
          </button>
        </div>

        <div class="search-wrapper">
          <svg class="search-icon" viewBox="0 0 24 24" width="18" height="18" style="width: 18px; height: 18px;" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
          <input type="text" id="searchInput" class="search-input" 
                 placeholder="ابحث عن ثغرة، CWE، أو رابط مصاب..." 
                 aria-label="البحث في الثغرات"
                 oninput="filterSearch()">
        </div>
      </div>

      <!-- Findings Cards List -->
      <section id="findingsList" style="margin-top: 14px;">
        <!-- Rendered dynamically by renderReport() -->
      </section>

      <!-- Methodology Note -->
      <div class="card glass" style="margin-top: 20px; padding: 22px;">
        <h3 style="font-family: var(--font-display); font-size: 17px; margin-bottom: 8px;">
          <span class="swash" data-ar="معايير حماك للفحص الأمني المؤتمت" data-en="Himaak Automated Security Baseline">معايير حماك للفحص الأمني المؤتمت</span>
        </h3>
        <p class="prose subtle" style="font-size: 13.5px; line-height: 1.7;" data-ar="تعتمد منصة حماك على محرك OWASP ZAP المتقدم لتنفيذ اختبارات الاختراق السلبية والتحقق من الترويسات ومسارات الحقن. انقر على أي ثغرة لفتح بطاقة المعاينة والحلول الهندسية، أو اسأل مساعد حماك الآلي في أسفل الصفحة للاستشارة المباشرة." data-en="ASAAS platform utilizes OWASP ZAP baseline scanner for automated security assessment. Click any finding card to open the comprehensive inspection modal, or ask the Asaas Robot assistant in the bottom corner.">
          تعتمد منصة حماك على محرك OWASP ZAP المتقدم لتنفيذ اختبارات الاختراق السلبية والتحقق من الترويسات ومسارات الحقن. انقر على أي ثغرة لفتح بطاقة المعاينة والحلول الهندسية، أو اسأل مساعد حماك الآلي في أسفل الصفحة للاستشارة المباشرة.
        </p>
      </div>

    </div>

  </main>

  <!-- ───────── Comprehensive Finding Inspector Modal ───────── -->
  <div class="modal-backdrop is-hidden" id="findingModalBackdrop" onclick="closeModal()">
    <div class="modal-window glass glass--thick" onclick="event.stopPropagation()">
      <div class="modal-header-bar">
        <div class="modal-title-area">
          <div style="display: flex; align-items: center; gap: 8px;">
            <span class="pill" id="mRiskBadge">عالي</span>
            <span class="pill pill--tag" id="mCweBadge">CWE-89</span>
            <span class="pill pill--tag" id="mCvssBadge">CVSS 3.1</span>
            <span class="pill pill--tag" id="mCountBadge">1 حالة</span>
          </div>
          <h2 id="mTitle" style="font-family: var(--font-display); font-size: 20px; font-weight: 700; margin: 4px 0 0;">عنوان الثغرة</h2>
          <div id="mSubTitle" class="subtle" style="font-size: 13px;">English Title</div>
        </div>

        <div style="display: flex; align-items: center; gap: 8px;">
          <button class="btn btn--glass btn--sm" onclick="consultAssistantAboutCurrentFinding()" title="استشارة مساعد حماك حول هذه الثغرة">
            <span>🤖 استشارة المساعد الأمني</span>
          </button>
          <button class="btn btn--glass btn--icon btn--sm" onclick="closeModal()" title="إغلاق">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6 6 18M6 6l12 12"/></svg>
          </button>
        </div>
      </div>

      <!-- Modal Tabs -->
      <div class="modal-tabs">
        <button class="modal-tab-btn is-active" data-tab="overview" onclick="switchModalTab('overview')">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width: 15px; height: 15px;"><circle cx="12" cy="12" r="9"/><path d="M12 8v4M12 16h.01"/></svg>
          <span data-ar="نظرة عامة والأثر" data-en="Overview & Impact">نظرة عامة والأثر</span>
        </button>
        <button class="modal-tab-btn" data-tab="instances" onclick="switchModalTab('instances')">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width: 15px; height: 15px;"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/></svg>
          <span data-ar="الأدلة والمواضع المصابة" data-en="Evidence & Instances">الأدلة والمواضع المصابة</span>
        </button>
        <button class="modal-tab-btn" data-tab="solution" onclick="switchModalTab('solution')">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width: 15px; height: 15px;"><path d="m5 12 5 5L20 7"/></svg>
          <span data-ar="خطة المعالجة المعتمدة" data-en="Remediation Plan">خطة المعالجة المعتمدة</span>
        </button>
        <button class="modal-tab-btn" data-tab="refs" onclick="switchModalTab('refs')">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width: 15px; height: 15px;"><circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
          <span data-ar="المعايير والمراجع" data-en="References">المعايير والمراجع</span>
        </button>
      </div>

      <!-- Modal Scrollable Content -->
      <div class="modal-scroll-body">
        
        <!-- Pane 1: Overview -->
        <div class="modal-pane" id="pane-overview">
          <div class="section-block">
            <div class="section-label">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 9v4M12 17h.01M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0z"/></svg>
              <span data-ar="شرح الثغرة والخطورة الأمنية" data-en="Vulnerability Assessment">شرح الثغرة والخطورة الأمنية</span>
            </div>
            <div class="prose" id="mDesc" style="font-size: 15px; line-height: 1.7;">-</div>
          </div>

          <div class="section-block" style="margin-top: 14px;">
            <div class="section-label">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="m8 12 3 3 5-5"/></svg>
              <span data-ar="مصفوفة التأثير الأمني (Security Impact Rating)" data-en="Security Impact Rating">مصفوفة التأثير الأمني (Security Impact Rating)</span>
            </div>
            <div class="impact-grid">
              <div class="impact-tile">
                <span class="impact-tile__label" data-ar="السرية (Confidentiality)" data-en="Confidentiality">السرية (Confidentiality)</span>
                <span class="impact-tile__value" id="mImpactConf">مرتفع (High)</span>
              </div>
              <div class="impact-tile">
                <span class="impact-tile__label" data-ar="سلامة البيانات (Integrity)" data-en="Integrity">سلامة البيانات (Integrity)</span>
                <span class="impact-tile__value" id="mImpactInteg">متوسط (Medium)</span>
              </div>
              <div class="impact-tile">
                <span class="impact-tile__label" data-ar="التوفر (Availability)" data-en="Availability">التوفر (Availability)</span>
                <span class="impact-tile__value" id="mImpactAvail">منخفض (Low)</span>
              </div>
            </div>
          </div>
        </div>

        <!-- Pane 2: Instances -->
        <div class="modal-pane" id="pane-instances" style="display: none;">
          <div class="section-label">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/></svg>
            <span data-ar="قائمة الروابط والأدلة التقنية المرصودة" data-en="Technical Evidence & Endpoints">قائمة الروابط والأدلة التقنية المرصودة</span>
          </div>
          <div id="mInstancesList" style="margin-top: 8px;"></div>
        </div>

        <!-- Pane 3: Solution -->
        <div class="modal-pane" id="pane-solution" style="display: none;">
          <div class="section-label">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m5 12 5 5L20 7"/></svg>
            <span data-ar="إرشادات المعالجة والحل الهندسي" data-en="Remediation Guidelines">إرشادات المعالجة والحل الهندسي</span>
          </div>
          <div class="solution-box" id="mSolution" style="font-size: 15px; margin-top: 8px;">-</div>

          <!-- Structured Remediation Code Box -->
          <div id="mCustomRemediation" style="margin-top: 14px; display: none;">
            <div class="section-label">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
              <span>كود المعالجة المعتمد</span>
            </div>
            <div style="position: relative; margin-top: 8px;">
              <pre class="evidence-box" style="margin: 0; padding-bottom: 38px;"><code id="mCustomRemediationCode"></code></pre>
              <button class="btn btn--glass btn--sm" style="position: absolute; bottom: 8px; inset-inline-end: 8px; font-size: 12px;" onclick="copyRemediationCode()">
                <span id="copyRemediationBtnText">نسخ كود المعالجة</span>
              </button>
            </div>
          </div>

          <div class="section-block" style="margin-top: 14px;">
            <div class="section-label">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 8v4M12 16h.01"/></svg>
              <span data-ar="إجراءات التحقق المقترحة من حماك" data-en="Himaak Verification Checklist">إجراءات التحقق المقترحة من حماك</span>
            </div>
            <div class="card glass" style="padding: 16px; font-size: 13.5px; line-height: 1.7;">
              <div id="mChecklistContainer" style="display: none;"></div>
              <ul style="margin: 0; padding-inline-start: 20px;">
                <li data-ar="إجراء فحص الكود المصدري (Static Code Review) للتحقق من إغلاق الموضع المصاب." data-en="Perform static code analysis to confirm sink/source sanitization.">إجراء فحص الكود المصدري (Static Code Review) للتحقق من إغلاق الموضع المصاب.</li>
                <li data-ar="إعادة تشغيل فحص OWASP ZAP والتأكد من اختفاء التنبيه تماماً." data-en="Re-run OWASP ZAP scan and verify zero alert regression.">إعادة تشغيل فحص OWASP ZAP والتأكد من اختفاء التنبيه تماماً.</li>
                <li data-ar="تحديث إعدادات الخوادم أو جدران الحماية (WAF) وتفعيل الحظر الاستباقي." data-en="Update web server or WAF rules for proactive blocking.">تحديث إعدادات الخوادم أو جدران الحماية (WAF) وتفعيل الحظر الاستباقي.</li>
              </ul>
            </div>
          </div>
        </div>

        <!-- Pane 4: References -->
        <div class="modal-pane" id="pane-refs" style="display: none;">
          <div class="section-label">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1 4-10z"/></svg>
            <span data-ar="الروابط والمراجع الرسمية" data-en="Official References & Links">الروابط والمراجع الرسمية</span>
          </div>
          <div class="refs-box" id="mRefs" style="margin-top: 8px;">-</div>
        </div>

      </div>

      <!-- Modal Footer -->
      <div class="modal-footer-bar">
        <div style="display: flex; gap: 8px;">
          <button class="btn btn--glass btn--sm" onclick="copyFindingDetails()">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width: 14px; height: 14px;"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>
            <span id="copyBtnText" data-ar="نسخ تقرير الثغرة" data-en="Copy Details">نسخ تقرير الثغرة</span>
          </button>
          <button class="btn btn--primary btn--sm" onclick="consultAssistantAboutCurrentFinding()">
            <span>🤖 استشارة مساعد حماك</span>
          </button>
        </div>

        <button class="btn btn--glass btn--sm" onclick="closeModal()">
          <span data-ar="إغلاق النافذة" data-en="Close">إغلاق النافذة</span>
        </button>
      </div>

    </div>
  </div>

  <!-- ───────── REAL ASAAS AI ROBOT ASSISTANT WIDGET ───────── -->
  <!-- Launcher Floating Robot Button -->
  <button class="assistant-launcher" id="asaasLauncher" onclick="toggleAsaasAssistant()" title="مساعد حماك للأمن السيبراني" aria-label="مساعد حماك للأمن السيبراني">
    <img src="data:image/webp;base64,{asst_b64['robot_wave']}" class="assistant-robot" id="launcherRobotImg" alt="روبوت حماك للأمن السيبراني" draggable="false">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" id="launcherCloseSvg" style="display: none; width: 24px; height: 24px;"><path d="M18 6 6 18M6 6l12 12"/></svg>
  </button>

  <!-- Interactive Chat Panel -->
  <section class="assistant-panel glass glass--thick" id="asaasPanel" role="dialog" aria-label="مساعد حماك الأمني" style="display: none;">
    <header class="assistant-panel__head">
      <img src="data:image/webp;base64,{asst_b64['face_smile']}" class="assistant-face" id="asstHeadFace" alt="وجه مساعد حماك" draggable="false">
      <div class="assistant-panel__title">
        <h2 style="font-family: var(--font-display); font-size: 17px; margin: 0;">مساعد حماك الأمني</h2>
        <p style="margin: 0; font-size: 11.5px; color: var(--text-3);">مساعدك الذكي لفحص وتحليل الثغرات</p>
      </div>
      <button type="button" class="btn btn--ghost btn--sm btn--icon" onclick="resetAssistantChat()" title="محادثة جديدة" aria-label="محادثة جديدة">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width: 17px; height: 17px;"><path d="M12 5v14M5 12h14"/></svg>
      </button>
      <button type="button" class="btn btn--ghost btn--sm btn--icon" onclick="toggleAsaasAssistant()" title="إغلاق" aria-label="إغلاق">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width: 17px; height: 17px;"><path d="M18 6 6 18M6 6l12 12"/></svg>
      </button>
    </header>

    <div class="assistant-panel__thread" id="asstThread" aria-live="polite">
      <!-- Welcome View -->
      <div class="assistant-welcome" id="asstWelcome">
        <img src="data:image/webp;base64,{asst_b64['robot_wave']}" class="assistant-welcome__robot" alt="مساعد حماك يرحب بك" draggable="false">
        <h3 id="asstGreeting">مساء الخير يا مهندس الأمان</h3>
        <p class="assistant-welcome__lead">أنا مساعد حماك الذكي، كيف أقدر أساعدك اليوم في مراجعة التقرير الأمني؟</p>
        <p>اسألني عن أي ثغرة أو اطلب كود الحماية المعياري لترويسات الخادم وتوصيات المعالجة.</p>

        <div class="assistant-welcome__suggestions">
          <button type="button" class="chip" onclick="askAssistantPrompt('لخص لي الوضع الأمني العام وأهم المخاطر في التقرير المعروض حالياً')">
            ⚡ لخص لي الوضع الأمني للتقرير الحالي
          </button>
          <button type="button" class="chip" onclick="askAssistantPrompt('ما هي أخطر الثغرات المرصودة في هذا الفحص؟')">
            🛡️ ما هي أخطر الثغرات المرصودة؟
          </button>
          <button type="button" class="chip" onclick="askAssistantPrompt('كيف أقوم بمعالجة ثغرة حقن SQL بشكل جذري؟')">
            💉 كيف أعالج ثغرة حقن SQL؟
          </button>
          <button type="button" class="chip" onclick="askAssistantPrompt('ما هي إعدادات Nginx الموصى بها لترويسات CSP و HSTS؟')">
            🔒 إعدادات Nginx لترويسات الأمان
          </button>
          <button type="button" class="chip" onclick="askAssistantPrompt('هل النظام مؤهل ومعتمد للإطلاق في بيئة الإنتاج؟')">
            📋 هل النظام مؤهل للاعتماد والإنتاج؟
          </button>
        </div>
      </div>
    </div>

    <form class="composer" id="asstComposer" onsubmit="handleAssistantSubmit(event)">
      <textarea class="composer__input" id="asstInput" rows="1" placeholder="اكتب سؤالك للمساعد الأمني..." aria-label="سؤالك للمساعد الأمني" onkeydown="handleAssistantKeyDown(event)"></textarea>
      <button type="submit" class="btn btn--primary composer__send" id="asstSendBtn" aria-label="إرسال">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width: 17px; height: 17px;"><path d="M3 3l18 9-18 9 3.5-9z"/><path d="M6.5 12H13"/></svg>
      </button>
    </form>

    <p class="assistant-panel__disclaimer">يجيب من بيانات الفحص الأمني وفق معايير حماك، وقد يخطئ.</p>
  </section>

  <!-- Footer -->
  <footer class="container" style="text-align: center; padding: 24px 0 40px; border-top: 1px solid var(--hairline); color: var(--text-3); font-size: 13px;">
    <div>
      <span class="swash">حِماك</span> · من شركة أساس للذكاء الاصطناعي &copy; <span class="num">2026</span> | Himaak by ASAAS AI
    </div>
  </footer>

  <!-- ───────── Core JavaScript Engine ───────── -->
  <script>
{SAFE_RENDER_JS}
    const REPORTS_DATA = {reports_json_str};
    const ASST_FACES = {{
      smile: 'data:image/webp;base64,{asst_b64["face_smile"]}',
      happy: 'data:image/webp;base64,{asst_b64["face_happy"]}',
      waiting: 'data:image/webp;base64,{asst_b64["face_waiting"]}',
      celebrate: 'data:image/webp;base64,{asst_b64["face_celebrate"]}'
    }};

    let activeReportKey = 'webapp';
    let currentAlertsList = [];
    let currentAlert = null;
    let currentLang = 'ar';
    let currentReportScore = 52;
    let currentTargetUrl = "https://example-corp.ai-asaas.com";
    let currentReleaseStatus = 'blocked';
    let currentCounts = {{ high: 0, med: 0, low: 0, info: 0 }};
    let isAssistantOpen = false;
    let assistantChatHistory = [];

    // Switch report by key
    function switchReport(key, cardEl) {{
      activeReportKey = key;
      document.querySelectorAll('#reportsDeck .report-select-card').forEach(c => c.classList.remove('is-active'));
      if (cardEl) cardEl.classList.add('is-active');

      const data = REPORTS_DATA[key];
      if (data) {{
        renderReport(data);
        const reportView = document.getElementById('reportView');
        if (reportView) {{
          reportView.scrollIntoView({{ behavior: 'smooth', block: 'nearest' }});
        }}
      }}
    }}

    // Release policy — mirrors assess_release() in scripts/generate_report.py
    function assessRelease(high, med, low) {{
      const score = Math.max(0, Math.min(100, 100 - (high * 25 + med * 10 + low * 3)));
      let status;
      if (score >= 90) status = {{ color: 'var(--paid)', ar: 'ممتاز / آمن', en: 'Secure / Excellent' }};
      else if (score >= 75) status = {{ color: 'var(--brand-gold)', ar: 'جيد / يتطلب معالجة طفيفة', en: 'Moderate / Minor Issues' }};
      else if (score >= 50) status = {{ color: 'var(--partial)', ar: 'متوسط / مخاطر محتملة', en: 'Warning / Action Required' }};
      else status = {{ color: 'var(--unpaid)', ar: 'حرج / يتطلب تدخلاً عاجلاً', en: 'Critical / Urgent Action Needed' }};
      const release = (high > 0 || score < 50) ? 'blocked' : (med > 0 ? 'conditional' : 'approved');
      return {{ score, status, release }};
    }}

    const RISK_META = {{
      3: {{ badge: 'pill--high', ar: 'عالي الخطورة', en: 'High' }},
      2: {{ badge: 'pill--medium', ar: 'متوسط الخطورة', en: 'Medium' }},
      1: {{ badge: 'pill--low', ar: 'منخفض الخطورة', en: 'Low' }},
      0: {{ badge: 'pill--info', ar: 'معلوماتي', en: 'Info' }}
    }};

    function riskCodeOf(a) {{
      const rc = parseInt(a && a.riskcode, 10);
      return [0, 1, 2, 3].includes(rc) ? rc : 0;
    }}

    function asArray(value) {{
      if (value === undefined || value === null) return [];
      return Array.isArray(value) ? value : [value];
    }}

    // Collects alerts from every site in the report (ZAP can scan several), highest risk first.
    function normalizeReport(data) {{
      const targets = [];
      const alerts = [];
      asArray(data && data.site).forEach(site => {{
        if (!site || typeof site !== 'object') return;
        if (site['@name']) targets.push(String(site['@name']));
        asArray(site.alerts).forEach(a => {{ if (a && typeof a === 'object') alerts.push(a); }});
      }});
      alerts.sort((x, y) => riskCodeOf(y) - riskCodeOf(x));
      return {{ targets, alerts }};
    }}

    // Render report data into UI. Everything taken from the report is written as text.
    function renderReport(data) {{
      const report = normalizeReport(data);
      const targetUrl = report.targets.join(', ') || '—';
      const zapVer = String((data && data['@version']) || 'OWASP ZAP');
      const timestamp = String((data && data['@generated']) || new Date().toLocaleString());

      currentTargetUrl = targetUrl;
      const targetLink = document.getElementById('displayTargetUrl');
      targetLink.textContent = targetUrl;
      targetLink.href = safeHttpUrl(report.targets[0]) || '#';
      document.getElementById('displayZapVersion').textContent = 'Engine: ' + zapVer;
      document.getElementById('displayTimestamp').textContent = timestamp;
      document.getElementById('targetUrlInput').value = safeHttpUrl(report.targets[0]) || '';
      updateCliCommands();

      const alerts = report.alerts;
      currentAlertsList = alerts;

      let high = 0, med = 0, low = 0, info = 0;
      alerts.forEach(a => {{
        const rc = riskCodeOf(a);
        if (rc === 3) high++;
        else if (rc === 2) med++;
        else if (rc === 1) low++;
        else info++;
      }});
      currentCounts = {{ high, med, low, info }};

      document.getElementById('statHigh').textContent = high;
      document.getElementById('statMed').textContent = med;
      document.getElementById('statLow').textContent = low;
      document.getElementById('statInfo').textContent = info;

      document.getElementById('filterCountAll').textContent = alerts.length;
      document.getElementById('filterCountHigh').textContent = high;
      document.getElementById('filterCountMed').textContent = med;
      document.getElementById('filterCountLow').textContent = low;
      document.getElementById('filterCountInfo').textContent = info;

      const assessment = assessRelease(high, med, low);
      const score = assessment.score;
      currentReportScore = score;
      currentReleaseStatus = assessment.release;
      document.getElementById('scoreNumber').textContent = score;

      const circumference = 251.32;
      const offset = circumference - (circumference * score / 100);
      const circleFill = document.getElementById('scoreCircleFill');
      circleFill.style.strokeDashoffset = offset;

      const statusColor = assessment.status.color;
      circleFill.setAttribute('stroke', statusColor);
      document.getElementById('scoreValueText').style.color = statusColor;
      const statusBadge = document.getElementById('scoreStatusBadge');
      statusBadge.style.borderColor = statusColor;
      statusBadge.style.color = statusColor;
      const statusText = document.getElementById('scoreStatusText');
      statusText.setAttribute('data-ar', assessment.status.ar);
      statusText.setAttribute('data-en', assessment.status.en);
      statusText.textContent = currentLang === 'ar' ? assessment.status.ar : assessment.status.en;
      updateReleaseGate(assessment.release, high);

      // Render Findings List
      const container = document.getElementById('findingsList');
      container.textContent = '';

      if (alerts.length === 0) {{
        container.innerHTML = `
          <div class="card glass empty">
            <div class="empty__icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="m8 12.3 2.8 2.8L16.2 9.6"/></svg></div>
            <h3 data-ar="لم يتم رصد أي ثغرات أمنية" data-en="No Vulnerabilities Detected">${{currentLang === 'en' ? 'No Vulnerabilities Detected' : 'لم يتم رصد أي ثغرات أمنية'}}</h3>
            <p data-ar="اجتاز هذا الهدف كافة اختبارات الفحص بنجاح تام وفق معايير OWASP." data-en="The target successfully passed baseline scans according to OWASP standards.">${{currentLang === 'en' ? 'The target successfully passed baseline scans according to OWASP standards.' : 'اجتاز هذا الهدف كافة اختبارات الفحص بنجاح تام وفق معايير OWASP.'}}</p>
          </div>
        `;
        applyFilters();
        return;
      }}

      alerts.forEach((a, idx) => {{
        const rc = riskCodeOf(a);
        const meta = RISK_META[rc];
        const name = String(a.name || a.alert || 'Unknown Issue');
        const nameAr = String(a.name_ar || name);
        const count = parseInt(a.count, 10) || (a.instances ? asArray(a.instances).length : 1);
        const cwe = /^[0-9]+$/.test(String(a.cweid || '')) ? String(a.cweid) : '';

        const card = document.createElement('div');
        card.className = 'finding-card glass';
        card.setAttribute('data-risk', rc);
        card.setAttribute('data-search', `${{name}} ${{nameAr}} ${{cwe}} ${{a.pluginid || ''}}`);

        const primaryTitle = currentLang === 'en' ? name : nameAr;
        const secondaryTitle = currentLang === 'en' ? (nameAr !== name ? `(${{nameAr}})` : '') : `(${{name}})`;

        // Static markup only; scan values are filled in below with textContent.
        card.innerHTML = `
          <div class="finding-header">
            <div class="finding-title-group">
              <span class="pill ${{meta.badge}}">
                <span data-ar="${{meta.ar}}" data-en="${{meta.en}}"></span>
              </span>
              <div class="finding-name">
                <span class="title-primary"></span>
                <span class="title-secondary subtle hide-mobile" style="font-size: 13px; margin-inline-start: 6px;"></span>
              </div>
            </div>
            <div class="finding-meta">
              <span class="pill pill--tag"><span class="num"></span> <span data-ar="حالة" data-en="instances"></span></span>
              <span class="pill pill--tag js-cwe"></span>
              <button class="finding-action-btn" type="button">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width: 14px; height: 14px;"><circle cx="12" cy="12" r="3"/><path d="M2.5 12S6 5 12 5s9.5 7 9.5 7-3.5 7-9.5 7S2.5 12 2.5 12Z"/></svg>
                <span data-ar="معاينة التقرير والتفاصيل" data-en="Inspect Finding Details"></span>
              </button>
            </div>
          </div>
        `;
        card.querySelector('.pill span').textContent = currentLang === 'ar' ? meta.ar : meta.en;
        card.querySelector('.finding-name').title = name;
        card.querySelector('.title-primary').textContent = primaryTitle;
        card.querySelector('.title-secondary').textContent = secondaryTitle;
        card.querySelector('.finding-meta .num').textContent = count;
        card.querySelector('.finding-meta [data-ar="حالة"]').textContent = currentLang === 'en' ? 'instances' : 'حالة';
        const cweEl = card.querySelector('.js-cwe');
        if (cwe) cweEl.textContent = 'CWE-' + cwe; else cweEl.remove();
        card.querySelector('.finding-action-btn span').textContent = currentLang === 'en' ? 'Inspect Finding Details' : 'معاينة التقرير والتفاصيل';

        card.querySelector('.finding-header').addEventListener('click', () => openModal(idx));
        card.querySelector('.finding-action-btn').addEventListener('click', (ev) => {{ ev.stopPropagation(); openModal(idx); }});
        container.appendChild(card);
      }});
      applyFilters();
    }}

    // Modal Inspector Logic
    function openModal(index) {{
      const alert = currentAlertsList[index];
      if (!alert) return;
      currentAlert = alert;

      const rc = riskCodeOf(alert);
      const meta = RISK_META[rc];

      const riskBadge = document.getElementById('mRiskBadge');
      riskBadge.className = 'pill ' + meta.badge;
      riskBadge.textContent = currentLang === 'en' ? meta.en : meta.ar;

      const cwe = /^[0-9]+$/.test(String(alert.cweid || '')) ? String(alert.cweid) : '';
      document.getElementById('mCweBadge').textContent = cwe ? 'CWE-' + cwe : 'CWE-N/A';
      const count = parseInt(alert.count, 10) || (alert.instances ? asArray(alert.instances).length : 1);
      document.getElementById('mCountBadge').textContent = count + (currentLang === 'en' ? ' instances' : ' حالة');

      const name = String(alert.name || alert.alert || 'Unknown Issue');
      const nameAr = String(alert.name_ar || name);
      const idSuffix = alert.pluginid ? ' - ID: ' + alert.pluginid : '';
      document.getElementById('mTitle').textContent = currentLang === 'en' ? name : nameAr;
      document.getElementById('mSubTitle').textContent = (currentLang === 'en' ? nameAr : name) + idSuffix;

      setPlainText(document.getElementById('mDesc'), htmlToText(alert.desc), '-');
      setPlainText(document.getElementById('mSolution'), htmlToText(alert.solution), 'تطبيق أفضل الممارسات المعتمدة وإجراء مراجعة أمنية للكود المصدري.');
      renderReferences(document.getElementById('mRefs'), htmlToText(alert.reference), 'لا توجد روابط مرجعية مسجلة.');

      // Structured Remediation Code Box
      const customRemed = document.getElementById('mCustomRemediation');
      const remedCode = alert.remediation_code || (alert.remediation_guide && alert.remediation_guide.code);
      if (remedCode) {{
        customRemed.style.display = 'block';
        document.getElementById('mCustomRemediationCode').textContent = String(remedCode);
      }} else {{
        customRemed.style.display = 'none';
      }}

      // Impact matrix
      const conf = document.getElementById('mImpactConf');
      const integ = document.getElementById('mImpactInteg');
      const avail = document.getElementById('mImpactAvail');
      if (rc === 3) {{
        conf.textContent = 'حرج (Critical)'; conf.style.color = 'var(--unpaid)';
        integ.textContent = 'مرتفع (High)'; integ.style.color = 'var(--unpaid)';
        avail.textContent = 'متوسط (Medium)'; avail.style.color = 'var(--partial)';
      }} else if (rc === 2) {{
        conf.textContent = 'متوسط (Medium)'; conf.style.color = 'var(--partial)';
        integ.textContent = 'متوسط (Medium)'; integ.style.color = 'var(--partial)';
        avail.textContent = 'منخفض (Low)'; avail.style.color = 'var(--paid)';
      }} else {{
        conf.textContent = 'منخفض (Low)'; conf.style.color = 'var(--paid)';
        integ.textContent = 'منخفض (Low)'; integ.style.color = 'var(--paid)';
        avail.textContent = 'محدود (Minimal)'; avail.style.color = 'var(--paid)';
      }}

      // Instances list
      const instContainer = document.getElementById('mInstancesList');
      instContainer.textContent = '';
      const instances = asArray(alert.instances).filter(inst => inst && typeof inst === 'object');
      if (instances.length === 0) {{
        const empty = document.createElement('p');
        empty.className = 'subtle';
        empty.textContent = 'لا توجد حالات محددة مسجلة.';
        instContainer.appendChild(empty);
      }} else {{
        instances.forEach((inst, i) => instContainer.appendChild(buildInstanceCard(inst, i)));
      }}

      switchModalTab('overview');
      document.getElementById('findingModalBackdrop').classList.remove('is-hidden');
    }}

    function closeModal() {{
      document.getElementById('findingModalBackdrop').classList.add('is-hidden');
    }}

    function switchModalTab(tabId) {{
      document.querySelectorAll('.modal-tab-btn').forEach(btn => {{
        btn.classList.toggle('is-active', btn.getAttribute('data-tab') === tabId);
      }});
      document.querySelectorAll('.modal-pane').forEach(p => p.style.display = 'none');
      const targetPane = document.getElementById('pane-' + tabId);
      if (targetPane) targetPane.style.display = 'block';
    }}

    function copyFindingDetails() {{
      if (!currentAlert) return;
      const text = `[تقرير أمان حماك]
الثغرة: ${{currentAlert.name_ar || currentAlert.name}} (${{currentAlert.name}})
مستوى الخطورة: ${{currentAlert.riskcode}}
CWE: CWE-${{currentAlert.cweid || 'N/A'}}
الهدف: ${{currentTargetUrl}}
الوصف: ${{htmlToText(currentAlert.desc)}}`;
      safeCopy(text, () => {{
        const btn = document.getElementById('copyBtnText');
        const orig = btn.textContent;
        btn.textContent = "✓ تم النسخ بنجاح";
        setTimeout(() => {{ btn.textContent = orig; }}, 2000);
      }});
    }}

    function copyRemediationCode() {{
      const codeEl = document.getElementById('mCustomRemediationCode');
      if (!codeEl) return;
      safeCopy(codeEl.textContent, () => {{
        const btn = document.getElementById('copyRemediationBtnText');
        const orig = btn.textContent;
        btn.textContent = "✓ تم نسخ الكود";
        setTimeout(() => {{ btn.textContent = orig; }}, 2000);
      }});
    }}

    function consultAssistantAboutCurrentFinding() {{
      if (!currentAlert) return;
      closeModal();
      if (!isAssistantOpen) toggleAsaasAssistant();
      const prompt = "اشرح لي بالتفصيل كيفية معالجة ثغرة " + (currentAlert.name_ar || currentAlert.name) + " وما هو الكود الموصى به لسدها؟";
      askAssistantPrompt(prompt);
    }}

    function updateCliCommands() {{
      // Only a plain http(s) URL goes into the command, single-quoted for the shell.
      const url = safeHttpUrl(document.getElementById('targetUrlInput').value.trim()) || 'https://example.com';
      const quoted = "'" + url.replace(/'/g, "'\\\\''") + "'";
      document.getElementById('cliCommandText').textContent = `gh workflow run zap-scan.yml -f target_url=${{quoted}}`;
    }}

    function copyCliCommand() {{
      safeCopy(document.getElementById('cliCommandText').textContent);
    }}

    // Dropzone logic
    function handleFileSelect(evt) {{
      const files = evt.target.files;
      if (files.length > 0) parseJsonFile(files[0]);
    }}

    const dropzone = document.getElementById('portalDropzone');
    dropzone.addEventListener('dragover', (e) => {{ e.preventDefault(); dropzone.style.borderColor = 'var(--accent-fill)'; }});
    dropzone.addEventListener('dragleave', (e) => {{ e.preventDefault(); dropzone.style.borderColor = 'var(--hairline)'; }});
    dropzone.addEventListener('drop', (e) => {{
      e.preventDefault();
      dropzone.style.borderColor = 'var(--hairline)';
      if (e.dataTransfer.files.length > 0) parseJsonFile(e.dataTransfer.files[0]);
    }});

    function parseJsonFile(file) {{
      const reader = new FileReader();
      reader.onload = function(e) {{
        try {{
          const parsed = JSON.parse(e.target.result);
          REPORTS_DATA['custom'] = parsed;
          switchReport('custom', null);
        }} catch(err) {{
          alert("خطأ في قراءة ملف JSON: " + err.message);
        }}
      }};
      reader.readAsText(file);
    }}

    // Filtering logic
    function filterByRisk(risk) {{
      document.querySelectorAll('#riskFilters .segmented__option').forEach(btn => {{
        btn.setAttribute('aria-pressed', btn.getAttribute('data-filter') === String(risk));
      }});
      applyFilters();
    }}

    
    // Safe Copy Fallback
    function safeCopy(text, onSuccess) {{
      if (navigator.clipboard && window.isSecureContext) {{
        navigator.clipboard.writeText(text).then(onSuccess).catch(() => fallbackCopy(text, onSuccess));
      }} else {{
        fallbackCopy(text, onSuccess);
      }}
    }}
    function fallbackCopy(text, onSuccess) {{
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      try {{
        document.execCommand('copy');
        if (onSuccess) onSuccess();
      }} catch(err) {{
        console.error('Clipboard copy failed:', err);
      }}
      document.body.removeChild(ta);
    }}

    function resetFilters() {{
      const searchInput = document.getElementById('searchInput');
      if (searchInput) searchInput.value = '';
      filterByRisk('all');
    }}

    // release is 'blocked' | 'conditional' | 'approved', as decided by assessRelease().
    function updateReleaseGate(release, highCount) {{
      const card = document.getElementById('releaseDecisionCard');
      const icon = document.getElementById('releaseIcon');
      const title = document.getElementById('releaseTitleAr');
      const desc = document.getElementById('releaseDescAr');
      const badge = document.getElementById('releaseBadge');
      const timeline = document.getElementById('releaseTimeline');
      if (!card || !badge) return;
      const ar = currentLang === 'ar';

      if (release === 'blocked') {{
        card.style.borderColor = 'var(--unpaid)';
        if (icon) icon.textContent = '🔴';
        if (title) title.textContent = ar ? 'حظر الإطلاق للإنتاج (Release Blocked)' : 'Release Blocked (P1 Blocker)';
        if (desc) desc.textContent = highCount > 0
          ? (ar ? 'تم رصد ثغرات أمنية عالية الخطورة. يُمنع النشر للإنتاج حتى اكتمال المعالجة والتحقق.' : 'High-risk vulnerabilities detected. Production release is blocked until remediated.')
          : (ar ? 'مؤشر السلامة أقل من 50. يُمنع النشر للإنتاج حتى معالجة الثغرات ورفع المؤشر.' : 'Security score is below 50. Production release is blocked until findings are remediated.');
        badge.className = 'pill pill--unpaid';
        badge.textContent = 'BLOCKED';
        if (timeline) timeline.textContent = ar ? 'مهلة الترقيع: فوري قبل النشر' : 'SLA: Immediate before deployment';
      }} else if (release === 'conditional') {{
        card.style.borderColor = 'var(--partial)';
        if (icon) icon.textContent = '🟡';
        if (title) title.textContent = ar ? 'موافقة مشروطة للنشر (Conditional Release)' : 'Conditional Release (Grace Period)';
        if (desc) desc.textContent = ar ? 'توجد ملاحظات أمنية متوسطة تتطلب جدولة المعالجة خلال مهلة زمنية محددة.' : 'Medium risk findings identified. Release approved under a 14-day remediation grace period.';
        badge.className = 'pill pill--partial';
        badge.textContent = 'CONDITIONAL';
        if (timeline) timeline.textContent = ar ? 'مهلة الترقيع: 14 يوماً' : 'SLA: 14 calendar days';
      }} else {{
        card.style.borderColor = 'var(--paid)';
        if (icon) icon.textContent = '🟢';
        if (title) title.textContent = ar ? 'معتمد للنشر بالإنتاج (Approved for Production)' : 'Approved for Production (Clean)';
        if (desc) desc.textContent = ar ? 'اجتاز النظام بوابات الفحص الأمني بدون ثغرات عالية أو متوسطة الخطورة.' : 'All security quality gates passed. No high or medium risk findings.';
        badge.className = 'pill pill--paid';
        badge.textContent = 'APPROVED';
        if (timeline) timeline.textContent = ar ? 'الحالة: مستوفٍ لكافة المعايير' : 'Status: Fully Compliant';
      }}
    }}

    function filterSearch() {{
      applyFilters();
    }}

    function applyFilters() {{
      const activeFilterBtn = document.querySelector('#riskFilters .segmented__option[aria-pressed="true"]');
      const activeRisk = activeFilterBtn ? activeFilterBtn.getAttribute('data-filter') : 'all';
      const searchVal = (document.getElementById('searchInput')?.value || '').toLowerCase().trim();

      const cards = document.querySelectorAll('#findingsList .finding-card');
      let visible = 0;
      cards.forEach(card => {{
        const risk = card.getAttribute('data-risk');
        const search = (card.getAttribute('data-search') || '').toLowerCase();

        const matchRisk = activeRisk === 'all' || risk === activeRisk;
        const matchSearch = !searchVal || search.includes(searchVal);

        card.style.display = (matchRisk && matchSearch) ? 'block' : 'none';
        if (matchRisk && matchSearch) visible++;
      }});

      // "No results" only when there are findings but the filter hides all of them.
      const emptyState = document.getElementById('filterEmptyState');
      if (emptyState) emptyState.style.display = (cards.length > 0 && visible === 0) ? 'block' : 'none';
    }}

    // ───────── REAL ASAAS ASSISTANT ENGINE ─────────
    function toggleAsaasAssistant() {{
      isAssistantOpen = !isAssistantOpen;
      const panel = document.getElementById('asaasPanel');
      const launcher = document.getElementById('asaasLauncher');
      const robotImg = document.getElementById('launcherRobotImg');
      const closeSvg = document.getElementById('launcherCloseSvg');

      launcher.setAttribute('data-open', isAssistantOpen ? 'true' : 'false');

      if (isAssistantOpen) {{
        panel.style.display = 'flex';
        robotImg.style.display = 'none';
        closeSvg.style.display = 'block';
        document.getElementById('asstInput').focus();
        updateGreeting();
      }} else {{
        panel.style.display = 'none';
        robotImg.style.display = 'block';
        closeSvg.style.display = 'none';
      }}
    }}

    function closeAsaasAssistant() {{
      if (isAssistantOpen) toggleAsaasAssistant();
    }}

    function updateGreeting() {{
      const h = new Date().getHours();
      const g = h < 12 ? 'صباح الخير يا مهندس الأمان' : 'مساء الخير يا مهندس الأمان';
      const el = document.getElementById('asstGreeting');
      if (el) el.innerText = g;
    }}

    function resetAssistantChat() {{
      assistantChatHistory = [];
      const thread = document.getElementById('asstThread');
      thread.innerHTML = `
        <div class="assistant-welcome" id="asstWelcome">
          <img src="data:image/webp;base64,{asst_b64['robot_wave']}" class="assistant-welcome__robot" alt="مساعد حماك يرحب بك" draggable="false">
          <h3 id="asstGreeting">${{new Date().getHours() < 12 ? 'صباح الخير يا مهندس الأمان' : 'مساء الخير يا مهندس الأمان'}}</h3>
          <p class="assistant-welcome__lead">أنا مساعد حماك الذكي، كيف أقدر أساعدك اليوم في مراجعة التقرير الأمني؟</p>
          <p>اسألني عن أي ثغرة أو اطلب كود الحماية المعياري لترويسات الخادم وتوصيات المعالجة.</p>

          <div class="assistant-welcome__suggestions">
            <button type="button" class="chip" onclick="askAssistantPrompt('لخص لي الوضع الأمني العام وأهم المخاطر في التقرير المعروض حالياً')">
              ⚡ لخص لي الوضع الأمني للتقرير الحالي
            </button>
            <button type="button" class="chip" onclick="askAssistantPrompt('ما هي أخطر الثغرات المرصودة في هذا الفحص؟')">
              🛡️ ما هي أخطر الثغرات المرصودة؟
            </button>
            <button type="button" class="chip" onclick="askAssistantPrompt('كيف أقوم بمعالجة ثغرة حقن SQL بشكل جذري؟')">
              💉 كيف أعالج ثغرة حقن SQL؟
            </button>
            <button type="button" class="chip" onclick="askAssistantPrompt('ما هي إعدادات Nginx الموصى بها لترويسات CSP و HSTS؟')">
              🔒 إعدادات Nginx لترويسات الأمان
            </button>
            <button type="button" class="chip" onclick="askAssistantPrompt('هل النظام مؤهل ومعتمد للإطلاق في بيئة الإنتاج؟')">
              📋 هل النظام مؤهل للاعتماد والإنتاج؟
            </button>
          </div>
        </div>
      `;
      try {{ sessionStorage.removeItem('asaas-chat-history'); }} catch(e) {{}}
    }}

    function askAssistantPrompt(text) {{
      document.getElementById('asstInput').value = text;
      handleAssistantSubmit(new Event('submit'));
    }}

    function handleAssistantKeyDown(e) {{
      if (e.key === 'Enter' && !e.shiftKey) {{
        e.preventDefault();
        handleAssistantSubmit(e);
      }}
    }}

    function handleAssistantSubmit(e) {{
      e.preventDefault();
      const input = document.getElementById('asstInput');
      const text = (input.value || '').trim();
      if (!text) return;
      input.value = '';

      const welcome = document.getElementById('asstWelcome');
      if (welcome) welcome.style.display = 'none';

      appendUserBubble(text);
      assistantChatHistory.push({{ role: 'user', content: text }});

      const typingEl = appendTypingIndicator();

      setTimeout(() => {{
        typingEl.remove();
        const res = generateAssistantAIResponse(text);
        appendAssistantBubble(res.reply, res.mood || 'happy');
        assistantChatHistory.push({{ role: 'assistant', content: res.reply }});
        try {{ sessionStorage.setItem('asaas-chat-history', JSON.stringify(assistantChatHistory.slice(-12))); }} catch(err) {{}}
      }}, 550);
    }}

    function appendUserBubble(text) {{
      const thread = document.getElementById('asstThread');
      const bubble = document.createElement('div');
      bubble.className = "bubble bubble--user";
      bubble.innerHTML = `<div class="bubble__body"><div class="bubble__text">${{escapeHtml(text)}}</div></div>`;
      thread.appendChild(bubble);
      thread.scrollTo({{ top: thread.scrollHeight, behavior: 'smooth' }});
    }}

    function appendTypingIndicator() {{
      const thread = document.getElementById('asstThread');
      const typing = document.createElement('div');
      typing.className = "bubble bubble--assistant";
      typing.innerHTML = `
        <img src="${{ASST_FACES.waiting}}" class="assistant-face assistant-face--sm" alt="حماك يفكر" draggable="false">
        <span class="typing" role="status" aria-label="حماك يكتب..."><i/><i/><i/></span>
      `;
      thread.appendChild(typing);
      thread.scrollTo({{ top: thread.scrollHeight, behavior: 'smooth' }});
      return typing;
    }}

    function appendAssistantBubble(htmlText, mood = 'happy') {{
      const thread = document.getElementById('asstThread');
      const bubble = document.createElement('div');
      bubble.className = "bubble bubble--assistant";
      const faceSrc = ASST_FACES[mood] || ASST_FACES.happy;
      bubble.innerHTML = `
        <img src="${{faceSrc}}" class="assistant-face assistant-face--sm" alt="وجه حماك" draggable="false">
        <div class="bubble__body">
          <div class="bubble__text" style="font-size: 13.5px; line-height: 1.6;">${{htmlText}}</div>
        </div>
      `;
      thread.appendChild(bubble);
      thread.scrollTo({{ top: thread.scrollHeight, behavior: 'smooth' }});
    }}

    function generateAssistantAIResponse(query) {{
      const qLower = query.toLowerCase();
      let reply = "";
      let mood = "happy";

      const highCount = currentAlertsList.filter(a => riskCodeOf(a) === 3).length;
      const medCount = currentAlertsList.filter(a => riskCodeOf(a) === 2).length;
      const lowCount = currentAlertsList.filter(a => riskCodeOf(a) === 1).length;
      const infoCount = currentAlertsList.filter(a => riskCodeOf(a) === 0).length;

      if (qLower.includes('لخص') || qLower.includes('وضع') || qLower.includes('تقرير') || qLower.includes('نتيجة') || qLower.includes('score')) {{
        mood = currentReportScore >= 80 ? "celebrate" : "waiting";
        reply = `📊 <strong>ملخص تقرير الفحص الأمني للهدف (${{escapeHtml(currentTargetUrl)}}):</strong><br><br>` +
                `• <strong>مؤشر السلامة:</strong> ${{currentReportScore}}/100<br>` +
                `• <strong>الثغرات عالية الخطورة:</strong> ${{highCount}} ثغرة<br>` +
                `• <strong>الثغرات متوسطة الخطورة:</strong> ${{medCount}} ثغرة<br>` +
                `• <strong>الثغرات منخفضة الخطورة:</strong> ${{lowCount}} ثغرة<br>` +
                `• <strong>ملاحظات معلوماتية:</strong> ${{infoCount}}<br><br>` +
                (highCount > 0 ? `🚨 <em>تنبيه عاجل:</em> يتطلب النظام تدخلاً هندسياً لمعالجة الثغرات عالية الخطورة قبل الاعتماد.` : `✅ الامتثال الأمني العام للنظام في مستوى مطمئن.`);
      }}
      else if (qLower.includes('أخطر') || qLower.includes('حرجة') || qLower.includes('critical') || qLower.includes('high')) {{
        const criticals = currentAlertsList.filter(a => riskCodeOf(a) >= 2);
        if (criticals.length === 0) {{
          mood = "celebrate";
          reply = `✅ <strong>بشرى سارة:</strong> لا توجد أي ثغرات عالية أو متوسطة الخطورة في هذا التقرير! النظام يجتاز معايير الأمان الموصى بها.`;
        }} else {{
          mood = "waiting";
          const names = criticals.map(c => `• <strong>${{escapeHtml(c.name_ar || c.name)}}</strong> (Risk: ${{riskCodeOf(c) === 3 ? 'عالي' : 'متوسط'}})`).join('<br>');
          reply = `⚠️ <strong>أبرز الثغرات التي تتطلب تدخلاً هندسياً عاجلاً:</strong><br><br>${{names}}<br><br>انقر على أي منها في جدول التقرير لمعاينة الدليل التقني وتوصيات التصحيح.`;
        }}
      }}
      else if (qLower.includes('sql')) {{
        mood = "celebrate";
        reply = `💉 <strong>المعالجة الجذرية لثغرات حقن أوامر SQL:</strong><br><br>` +
                `1. <strong>الاستعلامات المجهزة (Parameterized Queries):</strong><br>` +
                `<pre class="evidence-box"><code># بايثون مع Psycopg2 / SQLite
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

// Node.js مع pg
await client.query('SELECT * FROM users WHERE id = $1', [userId]);</code></pre>` +
                `2. تجنب دمج النصوص (String Concatenation) داخل جمل الاستعلام إطلاقاً.<br>` +
                `3. اعتماد أطر عمل ORM الحديثة مثل Prisma أو SQLAlchemy.`;
      }}
      else if (qLower.includes('csp') || qLower.includes('محتوى')) {{
        mood = "happy";
        reply = `🔒 <strong>ترويسة سياسة أمان المحتوى (CSP) القياسية من حماك:</strong><br><br>` +
                `<pre class="evidence-box"><code># Nginx Config:
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; frame-ancestors 'none';" always;</code></pre>` +
                `هذه الترويسة تمنع هجمات XSS وتمنع تضمين موقعك داخل إطارات Iframe ضارة (Anti-Clickjacking).`;
      }}
      else if (qLower.includes('hsts') || qLower.includes('نقل صارم')) {{
        mood = "happy";
        reply = `🛡️ <strong>تفعيل ترويسة Strict-Transport-Security (HSTS):</strong><br><br>` +
                `<pre class="evidence-box"><code># Nginx Config:
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;</code></pre>` +
                `تضمن هذه الترويسة إجبار جميع المتصفحات على استخدام اتصال HTTPS المشفر فقط وعدم التراجع لـ HTTP العادي.`;
      }}
      else if (qLower.includes('csrf') || qLower.includes('تزوير')) {{
        mood = "happy";
        reply = `🛡️ <strong>حماية النماذج من تزوير الطلبات (Anti-CSRF):</strong><br><br>` +
                `1. توليد رمز عشوائي سري (Cryptographic Token) وربطه بجلسة المستخدم.<br>` +
                `2. التحقق من الرمز في كل طلب تعديل بيانات (POST/PUT/DELETE).<br>` +
                `3. تعيين خاصية <code>SameSite=Strict; Secure; HttpOnly</code> لكوكيز الجلسة.`;
      }}
      else if (qLower.includes('مؤهل') || qLower.includes('إطلاق') || qLower.includes('إنتاج') || qLower.includes('release')) {{
        const policy = `<br><br><em>سياسة حماك: يُحجب الإطلاق عند وجود أي ثغرة عالية الخطورة أو انخفاض المؤشر دون 50، ويكون مشروطاً عند وجود ثغرات متوسطة فقط.</em>`;
        if (currentReleaseStatus === 'blocked') {{
          mood = "waiting";
          reply = `⛔ <strong>توصية قرار الإطلاق (Release Decision):</strong><br><br>` +
                  `نوصي بـ <strong>حجب الإطلاق حالياً (Block Release)</strong> ` +
                  (highCount > 0 ? `لوجود ${{highCount}} ثغرة عالية الخطورة.` : `لأن مؤشر السلامة (${{currentReportScore}}/100) أقل من 50.`) + policy;
        }} else if (currentReleaseStatus === 'conditional') {{
          mood = "happy";
          reply = `⚠️ <strong>توصية قرار الإطلاق:</strong><br><br>` +
                  `يمكن الإطلاق المشروط (Conditional Release) مع جدولة معالجة الثغرات متوسطة الخطورة (${{medCount}} ثغرة) خلال أسبوعين.` + policy;
        }} else {{
          mood = "celebrate";
          reply = `🚀 <strong>توصية قرار الإطلاق:</strong><br><br>` +
                  `النظام <strong>مؤهل بالكامل للإطلاق في بيئة الإنتاج</strong>، ولم يتم رصد أي ثغرات مؤثرة تمنع الاعتماد.` + policy;
        }}
      }}
      else if (qLower.includes('تحقق') || qLower.includes('checklist')) {{
        reply = `📋 <strong>قائمة التحقق الأمني المعتمدة قبل الإطلاق (Himaak Baseline):</strong><br><br>` +
                `1. تفعيل ترويسات: CSP, HSTS, X-Content-Type-Options, X-Frame-Options.<br>` +
                `2. تعيين خصائص الكوكيز الحساسة: <code>HttpOnly; Secure; SameSite=Strict</code>.<br>` +
                `3. التحقق من رموز Anti-CSRF في جميع طلبات تعديل البيانات (POST/PUT/DELETE).<br>` +
                `4. حجب معلومات إصدار الخادم (Server Header).`;
      }}
      else {{
        reply = `🤖 بصفتي مساعد حماك الأمني، أنا هنا لمساعدتك في فهم كل تفاصيل هذا التقرير الأمني. ` +
                `يمكنك سؤالي عن: كيفية ترقيع أي ثغرة واردة بالتقرير، إعدادات الخوادم المشفرة، أو شرح معايير CWE المرفقة.`;
      }}

      return {{ reply, mood }};
    }}

        // Language Toggle
    function toggleLanguage() {{
      currentLang = currentLang === 'ar' ? 'en' : 'ar';
      applyLanguage(currentLang);
    }}

    function applyLanguage(lang) {{
      currentLang = lang;
      const root = document.documentElement;
      root.setAttribute('lang', lang);
      root.setAttribute('dir', lang === 'ar' ? 'rtl' : 'ltr');
      root.lang = lang;
      root.dir = lang === 'ar' ? 'rtl' : 'ltr';

      if (document.body) {{
        document.body.dir = lang === 'ar' ? 'rtl' : 'ltr';
      }}

      // 1. Language Toggle Button text
      const langBtn = document.getElementById('langBtn');
      if (langBtn) {{
        const span = langBtn.querySelector('span');
        if (span) span.innerText = lang === 'ar' ? 'English' : 'العربية';
      }}

      // 2. Document Title
      document.title = lang === 'ar' 
        ? 'حِماك | منصة أتمتة الفحص الأمني المتقدم' 
        : 'Himaak | OWASP ZAP Security Assessment Platform';

      // 3. Static elements with data-ar and data-en
      document.querySelectorAll('[data-ar][data-en]').forEach(el => {{
        const text = el.getAttribute('data-' + lang);
        if (text) {{
          if (el.children.length === 0) {{
            el.innerText = text;
          }} else {{
            const textNodes = Array.from(el.childNodes).filter(n => n.nodeType === Node.TEXT_NODE && n.textContent.trim().length > 0);
            if (textNodes.length > 0) {{
              textNodes[0].textContent = text;
            }} else {{
              el.childNodes.forEach(child => {{
                if (child.nodeType === Node.ELEMENT_NODE && (child.tagName === 'SPAN' || !child.hasAttribute('viewBox'))) {{
                  child.innerText = text;
                }}
              }});
            }}
          }}
        }}
      }});

      // 4. Input placeholders
      document.querySelectorAll('[data-ar-placeholder][data-en-placeholder]').forEach(el => {{
        el.placeholder = el.getAttribute('data-' + lang + '-placeholder');
      }});

      const searchInput = document.getElementById('searchInput');
      if (searchInput) {{
        searchInput.placeholder = lang === 'ar' 
          ? 'ابحث بالاسم، تصنيف OWASP، أو رقم CWE...' 
          : 'Search by name, OWASP category, or CWE...';
      }}

      const targetInput = document.getElementById('targetUrlInput');
      if (targetInput) {{
        targetInput.placeholder = 'https://example-corp.ai-asaas.com';
      }}

      const asstInput = document.getElementById('asstInput');
      if (asstInput) {{
        asstInput.placeholder = lang === 'ar' 
          ? 'اسأل مساعد حماك عن أي ثغرة أو خطة معالجة...' 
          : 'Ask Himaak about any alert or remediation...';
      }}

      // 5. Assistant Greeting & Chips
      const asstGreet = document.getElementById('asstGreeting');
      if (asstGreet) {{
        asstGreet.innerText = lang === 'ar'
          ? 'أهلاً بك! أنا مساعد حماك الذكي لتحليل ثغرات فحص OWASP ZAP وبوابات الجودة الأمنية. كيف يمكنني إرشادك اليوم؟'
          : 'Welcome! I am the Himaak security assistant for OWASP ZAP vulnerability analysis and release gates. How can I guide you today?';
      }}

      // 6. Update Theme Icon & button title
      const currentTheme = root.getAttribute('data-theme') || root.dataset.theme || 'light';
      updateThemeIcon(currentTheme);

      // 7. Persist preference
      try {{ localStorage.setItem('asaas-lang', lang); }} catch(e) {{}}

      // 8. Re-render active report so findings, KPIs, release decision, and modal update!
      if (typeof REPORTS_DATA !== 'undefined' && REPORTS_DATA[activeReportKey]) {{
        renderReport(REPORTS_DATA[activeReportKey]);
      }}
    }}

    // Theme Toggle
    function toggleTheme() {{
      const root = document.documentElement;
      const current = root.getAttribute('data-theme') || root.dataset.theme || 'light';
      const next = current === 'dark' ? 'light' : 'dark';
      
      root.setAttribute('data-theme', next);
      root.dataset.theme = next;
      if (document.body) {{
        document.body.setAttribute('data-theme', next);
        document.body.dataset.theme = next;
      }}
      try {{
        localStorage.setItem('asaas-theme', next);
      }} catch(e) {{}}
      updateThemeIcon(next);
    }}

    function updateThemeIcon(theme) {{
      const icon = document.getElementById('themeIcon');
      const btn = document.getElementById('themeBtn');
      const title = theme === 'dark'
        ? (currentLang === 'ar' ? 'تبديل إلى المظهر الفاتح' : 'Switch to Light Mode')
        : (currentLang === 'ar' ? 'تبديل إلى المظهر الداكن' : 'Switch to Dark Mode');
      if (btn) {{
        btn.setAttribute('title', title);
        btn.setAttribute('aria-label', title);
      }}
      if (icon) {{
        if (theme === 'dark') {{
          icon.innerHTML = '<circle cx="12" cy="12" r="4"/><path d="M12 2.5v2M12 19.5v2M4.6 4.6 6 6M18 18l1.4 1.4M2.5 12h2M19.5 12h2M4.6 19.4 6 18M18 6l1.4-1.4"/>';
        }} else {{
          icon.innerHTML = '<path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5Z"/>';
        }}
        icon.setAttribute('title', title);
      }}
    }}

    window.addEventListener('keydown', (e) => {{
      if (e.key === 'Escape') {{
        closeModal();
        closeAsaasAssistant();
      }}
    }});

    // Initialize default report on load
    window.addEventListener('DOMContentLoaded', () => {{
      try {{
        const savedTheme = localStorage.getItem('asaas-theme');
        if (savedTheme) {{
          document.documentElement.setAttribute('data-theme', savedTheme);
          document.documentElement.dataset.theme = savedTheme;
          if (document.body) {{
            document.body.setAttribute('data-theme', savedTheme);
            document.body.dataset.theme = savedTheme;
          }}
          updateThemeIcon(savedTheme);
        }}
        const savedLang = localStorage.getItem('asaas-lang');
        if (savedLang && (savedLang === 'ar' || savedLang === 'en')) {{
          applyLanguage(savedLang);
        }}
      }} catch(e) {{}}
      switchReport('webapp', document.getElementById('card-webapp'));
    }});
  </script>
</body>
</html>
"""

output_path = os.path.join(project_root, "index.html")
with open(output_path, "w", encoding="utf-8") as f:
    f.write(html_content)

print(f"Generated pristine index.html successfully! Output size: {len(html_content)} bytes")
