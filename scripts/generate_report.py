#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
═════════════════════════════════════════════════════════════════════════
Himaak (حِماك) - Security Report Generator, by ASAAS AI
Turns an OWASP ZAP JSON report into a standalone, offline HTML report
(Asaas visual identity, Thmanyah fonts, finding inspector, assistant).

Security note: every value that comes from the ZAP report is untrusted
(alert text, URIs, evidence, attack payloads). It is escaped before it is
written into HTML, and the page JavaScript renders it as text only.
═════════════════════════════════════════════════════════════════════════
"""

import os
import re
import sys
import html
import json
import base64
import argparse

# The shared himaak_core package lives at the repository root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from himaak_core.policy import assess_release, compute_score, SCORE_WEIGHTS  # noqa: E402,F401
from himaak_core.zap import (  # noqa: E402,F401
    RISK_LABELS, html_to_text, safe_url, enrich_alert, extract_urls, summarize_report, parse_zap_json,
)

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PRODUCT_NAME_AR = "حِماك"
PRODUCT_NAME_EN = "Himaak"


# ───────── Safe output helpers ─────────

def esc(value):
    """HTML-escape any value for use in element text or a quoted attribute."""
    return html.escape("" if value is None else str(value), quote=True)



def json_for_script(obj):
    """Serialises data for a <script> block so it can never close the tag or open HTML."""
    return (json.dumps(obj, ensure_ascii=False)
            .replace("<", "\\u003c")
            .replace(">", "\\u003e")
            .replace("&", "\\u0026")
            .replace(" ", "\\u2028")
            .replace(" ", "\\u2029"))


# ───────── Safe rendering helpers shared by the report and the dashboard ─────────
# Scan data is only ever written with textContent / DOM nodes, never innerHTML.
SAFE_RENDER_JS = r"""
    function escapeHtml(value) {
      return String(value === undefined || value === null ? '' : value)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    // Converts an HTML fragment (as found in raw ZAP JSON) to plain text.
    // DOMParser documents are inert: scripts do not run and images do not load.
    function htmlToText(value) {
      if (!value) return '';
      const marked = String(value).replace(/<\s*(br|\/p|\/li|\/div|\/h[1-6])\s*\/?>/gi, '$&\n');
      const doc = new DOMParser().parseFromString(marked, 'text/html');
      return (doc.body.textContent || '').replace(/[ \t]+\n/g, '\n').replace(/\n{3,}/g, '\n\n').trim();
    }

    function setPlainText(el, text, fallback) {
      if (!el) return;
      el.textContent = text || fallback || '-';
      el.style.whiteSpace = 'pre-line';
    }

    function safeHttpUrl(url) {
      const raw = String(url || '').trim();
      if (!/^https?:\/\//i.test(raw)) return null;
      try { return new URL(raw).href; } catch (e) { return null; }
    }

    function renderReferences(el, text, fallback) {
      if (!el) return;
      el.textContent = '';
      const found = (String(text || '').match(/https?:\/\/[^\s<>"']+/g) || [])
        .map(u => u.replace(/[.,);\]]+$/, ''));
      const urls = Array.from(new Set(found)).map(safeHttpUrl).filter(Boolean);
      if (!urls.length) { setPlainText(el, text, fallback); return; }
      const ul = document.createElement('ul');
      ul.style.margin = '0';
      ul.style.paddingInlineStart = '20px';
      urls.forEach(u => {
        const li = document.createElement('li');
        const a = document.createElement('a');
        a.href = u;
        a.textContent = u;
        a.target = '_blank';
        a.rel = 'noopener noreferrer';
        li.appendChild(a);
        ul.appendChild(li);
      });
      el.appendChild(ul);
    }

    function renderTextList(el, items) {
      if (!el) return;
      el.textContent = '';
      const ul = document.createElement('ul');
      ul.style.margin = '0';
      ul.style.paddingInlineStart = '20px';
      (items || []).forEach(item => {
        const li = document.createElement('li');
        li.textContent = String(item);
        ul.appendChild(li);
      });
      el.appendChild(ul);
    }

    function buildInstanceCard(inst, i) {
      const card = document.createElement('div');
      card.className = 'instance-card';
      const head = document.createElement('div');
      head.className = 'instance-card__header';
      const pill = document.createElement('span');
      pill.className = 'pill pill--tag';
      pill.textContent = '#' + (i + 1) + ' - Method: ' + (inst.method || 'GET');
      const uri = document.createElement('span');
      uri.className = 'instance-uri';
      uri.textContent = inst.uri || '-';
      head.appendChild(pill);
      head.appendChild(uri);
      card.appendChild(head);

      const addRow = (label, value, boxed) => {
        if (!value) return;
        const row = document.createElement('div');
        row.style.fontSize = '13px';
        if (boxed) row.style.marginTop = '4px';
        const strong = document.createElement('strong');
        strong.textContent = label;
        row.appendChild(strong);
        row.appendChild(document.createTextNode(' '));
        const code = document.createElement('code');
        code.textContent = String(value);
        if (boxed) {
          const box = document.createElement('div');
          box.className = 'evidence-box';
          box.appendChild(code);
          row.appendChild(box);
        } else {
          row.appendChild(code);
        }
        card.appendChild(row);
      };
      addRow('المعامل المتأثر (Parameter):', inst.param, false);
      addRow('حمولة الهجوم (Payload):', inst.attack, false);
      addRow('الدليل المكتشف (Evidence):', inst.evidence, true);
      return card;
    }
"""



def load_file_b64(filepath):
    """Loads a binary file and returns a base64 encoded string."""
    if os.path.exists(filepath):
        with open(filepath, "rb") as f:
            return base64.b64encode(f.read()).decode("utf-8")
    return ""

def load_text_file(filepath):
    """Loads a text file."""
    if os.path.exists(filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            return f.read()
    return ""


def get_inlined_brand_css(project_root):
    """Loads all CSS and embeds Base64 Thmanyah fonts and logos for zero-dependency rendering."""
    assets_dir = os.path.join(project_root, "assets")
    images_dir = os.path.join(assets_dir, "images")
    fonts_dir = os.path.join(assets_dir, "fonts", "thmanyah")
    styles_dir = os.path.join(assets_dir, "styles")
    
    sans_reg_b64 = load_file_b64(os.path.join(fonts_dir, "sans", "thmanyahsans-Regular.woff2"))
    sans_bold_b64 = load_file_b64(os.path.join(fonts_dir, "sans", "thmanyahsans-Bold.woff2"))
    disp_bold_b64 = load_file_b64(os.path.join(fonts_dir, "serif-display", "thmanyahserifdisplay-Bold.woff2"))
    text_reg_b64 = load_file_b64(os.path.join(fonts_dir, "serif-text", "thmanyahseriftext-Regular.woff2"))
    
    logo_dark_b64 = load_file_b64(os.path.join(images_dir, "logo-dark.png"))
    logo_light_b64 = load_file_b64(os.path.join(images_dir, "logo-light.png"))

    tokens_css = load_text_file(os.path.join(styles_dir, "tokens.css"))
    base_css = load_text_file(os.path.join(styles_dir, "base.css"))
    glass_css = load_text_file(os.path.join(styles_dir, "glass.css"))
    components_css = load_text_file(os.path.join(styles_dir, "components.css"))
    layout_css = load_text_file(os.path.join(styles_dir, "layout.css"))
    report_css = load_text_file(os.path.join(styles_dir, "report.css"))
    assistant_css = load_text_file(os.path.join(styles_dir, "assistant.css"))

    layout_css = layout_css.replace("url('/logo-dark.png')", "none").replace("url('/logo-light.png')", "none")

    embedded_fonts_css = f"""
    @font-face {{
      font-family: 'Thmanyah Sans';
      src: url('data:font/woff2;base64,{sans_reg_b64}') format('woff2');
      font-weight: 400;
      font-style: normal;
      font-display: swap;
    }}
    @font-face {{
      font-family: 'Thmanyah Sans';
      src: url('data:font/woff2;base64,{sans_bold_b64}') format('woff2');
      font-weight: 700;
      font-style: normal;
      font-display: swap;
    }}
    @font-face {{
      font-family: 'Thmanyah Serif Display';
      src: url('data:font/woff2;base64,{disp_bold_b64}') format('woff2');
      font-weight: 700;
      font-style: normal;
      font-display: swap;
    }}
    @font-face {{
      font-family: 'Thmanyah Serif Text';
      src: url('data:font/woff2;base64,{text_reg_b64}') format('woff2');
      font-weight: 400;
      font-style: normal;
      font-display: swap;
    }}
    """

    embedded_assets_css = f"""
    .brand__mark {{
      width: 44px;
      height: 52px;
      background-image: url('data:image/png;base64,{logo_dark_b64}') !important;
      background-size: contain;
      background-position: center;
      background-repeat: no-repeat;
      filter: drop-shadow(0 6px 12px rgba(186, 149, 85, 0.35));
    }}
    :root[data-theme='dark'] .brand__mark {{
      background-image: url('data:image/png;base64,{logo_light_b64}') !important;
    }}
    """

    return embedded_fonts_css + "\n" + tokens_css + "\n" + base_css + "\n" + glass_css + "\n" + components_css + "\n" + layout_css + "\n" + report_css + "\n" + assistant_css + "\n" + embedded_assets_css

def get_assistant_assets_b64(project_root):
    """Loads all Assistant robot and faces images as Base64."""
    asst_dir = os.path.join(project_root, "assets", "images", "assistant")
    return {
        "robot_wave": load_file_b64(os.path.join(asst_dir, "robot-wave.webp")),
        "face_smile": load_file_b64(os.path.join(asst_dir, "face-smile.webp")),
        "face_happy": load_file_b64(os.path.join(asst_dir, "face-happy.webp")),
        "face_waiting": load_file_b64(os.path.join(asst_dir, "face-waiting.webp")),
        "face_celebrate": load_file_b64(os.path.join(asst_dir, "face-celebrate.webp"))
    }

def generate_html_report(data, output_path, project_root):
    """Generates the standalone Himaak HTML report (Asaas visual identity)."""
    assets_dir = os.path.join(project_root, "assets")
    images_dir = os.path.join(assets_dir, "images")
    favicon_b64 = load_file_b64(os.path.join(images_dir, "favicon.png"))
    
    inlined_css = get_inlined_brand_css(project_root)
    asst_b64 = get_assistant_assets_b64(project_root)
    
    circumference = 251.32
    dash_offset = circumference - (circumference * data["score"] / 100)

    # Escaped copy of every scalar value, for use inside the HTML template.
    e = {k: esc(v) for k, v in data.items() if not isinstance(v, (list, dict))}
    e["target_url"] = esc(data["target_url"] or "—")

    # Pre-render findings cards (all alert text is escaped: it comes from the scanned target)
    findings_html_list = []
    for idx, alert in enumerate(data["alerts"]):
        a = {k: esc(v) for k, v in alert.items() if not isinstance(v, (list, dict))}
        cwe_tag = f'<span class="pill pill--tag">CWE-{a["cweid"]}</span>' if alert["cweid"] else ''
        owasp_tag = f'<span class="pill pill--tag hide-mobile">{a["owasp"]}</span>' if alert.get("owasp") else ''

        findings_html_list.append(f"""
        <div class="finding-card glass" data-index="{idx}" data-risk="{a['riskcode']}" data-search="{a['name']} {a['name_ar']} {a['cweid']} {a['id']} {a['owasp']}">
          <div class="finding-header" onclick="openModalByIndex({idx})">
            <div class="finding-title-group">
              <span class="pill {a['badge_class']}">
                <span data-ar="{a['risk_ar']}" data-en="{a['risk_en']}">{a['risk_ar']}</span>
              </span>
              <div class="finding-name" title="{a['name']}">
                <span class="title-primary" data-ar="{a['name_ar']}" data-en="{a['name']}">{a['name_ar']}</span>
                <span class="title-secondary subtle hide-mobile" data-ar="({a['name']})" data-en="({a['name_ar']})" style="font-size: 13px; margin-inline-start: 6px;">({a['name']})</span>
              </div>
            </div>
            <div class="finding-meta">
              <span class="pill pill--tag"><span class="num">{a['count']}</span> <span data-ar="حالة" data-en="instances">حالة</span></span>
              {owasp_tag}
              {cwe_tag}
              <button class="finding-action-btn" onclick="event.stopPropagation(); openModalByIndex({idx})">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width: 14px; height: 14px;"><circle cx="12" cy="12" r="3"/><path d="M2.5 12S6 5 12 5s9.5 7 9.5 7-3.5 7-9.5 7S2.5 12 2.5 12Z"/></svg>
                <span data-ar="معاينة التقرير والتفاصيل" data-en="Inspect Finding Details">معاينة التقرير والتفاصيل</span>
              </button>
            </div>
          </div>
        </div>
        """)

    all_findings_rendered = "\n".join(findings_html_list) if findings_html_list else """
    <div class="card glass empty">
      <div class="empty__icon">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="m8 12.3 2.8 2.8L16.2 9.6"/></svg>
      </div>
      <h3 data-ar="لم يتم رصد أي ثغرات أمنية" data-en="No Vulnerabilities Detected">لم يتم رصد أي ثغرات أمنية</h3>
      <p data-ar="اجتاز النظام كافة اختبارات الفحص بنجاح تام وفق معايير OWASP." data-en="The target successfully passed scans according to OWASP standards.">اجتاز النظام كافة اختبارات الفحص بنجاح تام وفق معايير OWASP.</p>
    </div>
    """

    alerts_json_safe = json_for_script(data["alerts"])
    metrics_json_safe = json_for_script({
        "score": data["score"],
        "high": data["high_count"],
        "med": data["med_count"],
        "low": data["low_count"],
        "info": data["info_count"],
        "target": data["target_url"],
        "statusAr": data["status_ar"],
        "statusEn": data["status_en"],
        "releaseStatus": data["release_status"],
    })

    release_icon = "⛔" if data["release_status"] == "blocked" else "⚠️" if data["release_status"] == "conditional" else "✅"

    html_content = f"""<!DOCTYPE html>
<html lang="ar" dir="rtl" data-theme="light">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
  <title>حِماك | تقرير الفحص الأمني المعتمد</title>
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

    <!-- Target Info Card -->
    <div class="card glass target-card">
      <div class="target-url">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
        <div>
          <span class="subtle" data-ar="الهدف المفحوص:" data-en="Target System:">الهدف المفحوص:</span>
          <a href="{esc(data['target_href'])}" id="displayTargetUrl" target="_blank" rel="noopener noreferrer" style="color: var(--accent); text-decoration: underline;">{e['target_url']}</a>
        </div>
      </div>

      <div class="target-badge">
        <span class="pill pill--tag">Engine: {e['zap_version']}</span>
        <span class="pill pill--tag"><span class="num">{e['generated_at']}</span></span>
      </div>
    </div>


    <!-- Executive Score & KPIs Grid -->
    <div class="grid grid--halves">
      <!-- Health Score Card -->
      <div class="card glass score-card">
        <div class="score-display">
          <div class="score-circle">
            <svg viewBox="0 0 96 96">
              <circle class="score-track" cx="48" cy="48" r="40" />
              <circle class="score-fill" id="scoreCircleFill" cx="48" cy="48" r="40" 
                      stroke="{e['status_color']}" 
                      stroke-dasharray="{circumference}" 
                      stroke-dashoffset="{dash_offset}" />
            </svg>
            <div class="score-value" style="color: {e['status_color']};">
              <span class="num">{e['score']}</span>
              <small>/ 100</small>
            </div>
          </div>
          <div class="score-info">
            <div class="score-title" data-ar="مؤشر السلامة الأمنية" data-en="Security Health Score">مؤشر السلامة الأمنية</div>
            <div class="score-status" style="color: {e['status_color']};">
              <span class="pill" style="background: var(--glass-inset); border: 1px solid {e['status_color']};">
                <span data-ar="{e['status_ar']}" data-en="{e['status_en']}">{e['status_ar']}</span>
              </span>
            </div>
            <p class="subtle" data-ar="تقييم الامتثال الأمني وفق منهجية OWASP" data-en="Compliance rating based on OWASP methodology">تقييم الامتثال الأمني وفق منهجية OWASP</p>
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
          <div class="stat__value" style="color: var(--unpaid);"><span class="num">{e['high_count']}</span></div>
          <div class="stat__foot" data-ar="تتطلب معالجة فورية" data-en="Requires immediate fix">تتطلب معالجة فورية</div>
        </div>

        <div class="card glass stat">
          <div class="stat__label">
            <div class="stat__icon" style="color: var(--partial);"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 8v4M12 16h.01M3.3 20h17.4a2 2 0 0 0 1.7-3L13.7 4a2 2 0 0 0-3.4 0L1.6 17a2 2 0 0 0 1.7 3z"/></svg></div>
            <span data-ar="متوسطة الخطورة" data-en="Medium Risk">متوسطة الخطورة</span>
          </div>
          <div class="stat__value" style="color: var(--partial);"><span class="num">{e['med_count']}</span></div>
          <div class="stat__foot" data-ar="معالجة مجدولة" data-en="Scheduled remediation">معالجة مجدولة</div>
        </div>

        <div class="card glass stat">
          <div class="stat__label">
            <div class="stat__icon" style="color: var(--paid);"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="m8 12 3 3 5-5"/></svg></div>
            <span data-ar="منخفضة الخطورة" data-en="Low Risk">منخفضة الخطورة</span>
          </div>
          <div class="stat__value" style="color: var(--paid);"><span class="num">{e['low_count']}</span></div>
          <div class="stat__foot" data-ar="تحسينات وقائية" data-en="Preventive hardening">تحسينات وقائية</div>
        </div>

        <div class="card glass stat">
          <div class="stat__label">
            <div class="stat__icon" style="color: var(--chart-out);"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 16v-4M12 8h.01"/></svg></div>
            <span data-ar="معلوماتية" data-en="Informational">معلوماتية</span>
          </div>
          <div class="stat__value" style="color: var(--chart-out);"><span class="num">{e['info_count']}</span></div>
          <div class="stat__foot" data-ar="ملاحظات توثيقية" data-en="Informational notes">ملاحظات توثيقية</div>
        </div>
      </div>
    </div>

    <!-- Executive Release Decision Card -->
    <div class="card glass release-card" id="releaseDecisionCard" style="margin-top: 14px; border-color: {e['release_color']};">
      <div class="release-card__info">
        <div class="release-card__title">
          <span>{release_icon}</span>
          <span data-ar="{e['release_title_ar']}" data-en="{e['release_title_en']}">{e['release_title_ar']}</span>
        </div>
        <p class="release-card__desc" data-ar="{e['release_desc_ar']}" data-en="{e['release_desc_en']}">
          {e['release_desc_ar']}
        </p>
      </div>
      <div class="release-card__meta" style="display: flex; flex-direction: column; align-items: flex-end; gap: 6px;">
        <span class="pill" style="border: 1px solid {e['release_color']}; color: {e['release_color']}; background: var(--glass-inset);" data-ar="{e['release_pill_ar']}" data-en="{e['release_pill_en']}">
          {e['release_pill_ar']}
        </span>
        <span class="subtle" style="font-size: 12px;" data-ar="مهلة الترقيع: {e['release_sla_ar']}" data-en="SLA: {e['release_sla_en']}">مهلة الترقيع: {e['release_sla_ar']}</span>
      </div>
    </div>

    <!-- Filter & Search Toolbar -->
    <div class="toolbar" style="margin-top: 10px;">
      <div class="segmented" id="riskFilters">
        <button class="segmented__option" data-filter="all" aria-pressed="true" onclick="filterByRisk('all')">
          <span data-ar="الكل" data-en="All">الكل</span>
          <span class="segmented__count num">{e['total_alerts']}</span>
        </button>
        <button class="segmented__option" data-filter="3" aria-pressed="false" onclick="filterByRisk('3')">
          <span data-ar="عالية" data-en="High">عالية</span>
          <span class="segmented__count num">{e['high_count']}</span>
        </button>
        <button class="segmented__option" data-filter="2" aria-pressed="false" onclick="filterByRisk('2')">
          <span data-ar="متوسطة" data-en="Medium">متوسطة</span>
          <span class="segmented__count num">{e['med_count']}</span>
        </button>
        <button class="segmented__option" data-filter="1" aria-pressed="false" onclick="filterByRisk('1')">
          <span data-ar="منخفضة" data-en="Low">منخفضة</span>
          <span class="segmented__count num">{e['low_count']}</span>
        </button>
        <button class="segmented__option" data-filter="0" aria-pressed="false" onclick="filterByRisk('0')">
          <span data-ar="معلوماتية" data-en="Info">معلوماتية</span>
          <span class="segmented__count num">{e['info_count']}</span>
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

    <!-- Findings Section -->
    <section id="findingsContainer" style="margin-top: 10px;">
      {all_findings_rendered}

      <!-- Filter Empty State -->
      <div class="card glass filter-empty" id="filterEmptyState" style="display: none;">
        <div class="filter-empty__icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
        </div>
        <h4 style="margin: 0; font-family: var(--font-display); font-size: 16px;">لم يتم العثور على أي ثغرات مطابقة</h4>
        <p class="subtle" style="margin: 0; font-size: 13px;">جرب تغيير كلمة البحث أو اختيار مستوى خطورة مختلف من الشريط أعلاه.</p>
        <button class="btn btn--glass btn--sm" onclick="resetFilters()">إعادة ضبط البحث والفلاتر</button>
      </div>
    </section>

    <!-- Standards & Methodology Notice -->
    <div class="card glass" style="margin-top: 20px; padding: 22px;">
      <h3 style="font-family: var(--font-display); font-size: 17px; margin-bottom: 8px;">
        <span class="swash" data-ar="منهجية الفحص الأمني ومعايير حماك" data-en="Security Testing Methodology & Himaak Standards">منهجية الفحص الأمني ومعايير حماك</span>
      </h3>
      <p class="prose subtle" style="font-size: 13.5px; line-height: 1.7;" data-ar="تم تنفيذ هذا الفحص السلبي المؤتمت وفق إطار عمل OWASP المعتمد من قبل فريق الأمن السيبراني في شركة أساس للذكاء الاصطناعي. انقر على أي ثغرة لفتح تقرير المعاينة والتحليل المتقدم، أو استعن بروبوت أساس الذكي في الزاوية للاستفسار فوراً." data-en="Executed under the OWASP automated security framework adopted by ASAAS AI Cybersecurity engineering. Click on any finding to open the comprehensive inspection modal, or ask the Asaas Robot assistant in the bottom corner.">
        تم تنفيذ هذا الفحص السلبي المؤتمت وفق إطار عمل OWASP المعتمد من قبل فريق الأمن السيبراني في شركة أساس للذكاء الاصطناعي. انقر على أي ثغرة لفتح تقرير المعاينة والتحليل المتقدم، أو استعن بروبوت أساس الذكي في الزاوية للاستفسار فوراً.
      </p>
    </div>

  </main>

  <!-- ───────── Comprehensive Finding Inspector Modal ───────── -->
  <div class="modal-backdrop is-hidden" id="findingModalBackdrop" onclick="closeModal()">
    <div class="modal-window glass glass--thick" onclick="event.stopPropagation()">
      <div class="modal-header-bar">
        <div class="modal-title-area">
          <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
            <span class="pill" id="mRiskBadge">عالي</span>
            <span class="pill pill--tag" id="mOwaspBadge">OWASP Top 10</span>
            <span class="pill pill--tag" id="mCweBadge">CWE-89</span>
            <span class="pill pill--tag" id="mCvssBadge">CVSS 8.6</span>
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
            <div style="margin-top: 8px; font-size: 12px; color: var(--text-3);" id="mCvssVectorText">Vector: CVSS:3.1</div>
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
              <span id="mCustomRemediationTitle">كود المعالجة المعتمد</span>
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
            <div class="card glass" style="padding: 16px; font-size: 13.5px; line-height: 1.7;" id="mChecklistContainer">
              <ul style="margin: 0; padding-inline-start: 20px;">
                <li>إجراء فحص الكود المصدري (Static Code Review) للتحقق من إغلاق الموضع المصاب.</li>
                <li>إعادة تشغيل فحص OWASP ZAP والتأكد من اختفاء التنبيه تماماً.</li>
                <li>تحديث إعدادات الخوادم أو جدران الحماية (WAF) وتفعيل الحظر الاستباقي.</li>
              </ul>
            </div>
          </div>
        </div>

        <!-- Pane 4: References -->
        <div class="modal-pane" id="pane-refs" style="display: none;">
          <div class="section-label">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
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
        <p class="assistant-welcome__lead">أنا مساعد حماك للأمن السيبراني، جاهز لمساعدتك في فحص وتحليل الثغرات واقتراح كود الترقيع البرمجي المعتمد.</p>
        <p>اسألني عن أي ثغرة أو اطلب كود الحماية المعياري لترويسات الخادم وتوصيات المعالجة.</p>

        <div class="assistant-welcome__suggestions">
          <button type="button" class="chip" onclick="askAssistantPrompt('لخص لي الوضع الأمني العام وأهم المخاطر في هذا الفحص')">
            ⚡ لخص لي الوضع الأمني العام
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

  <!-- Embedded Alert Objects & Full Interactive Logic -->
  <script>
{SAFE_RENDER_JS}
    const ALERTS_DATA = {alerts_json_safe};
    const CURRENT_REPORT_METRICS = {metrics_json_safe};
    const ASST_FACES = {{
      smile: 'data:image/webp;base64,{asst_b64["face_smile"]}',
      happy: 'data:image/webp;base64,{asst_b64["face_happy"]}',
      waiting: 'data:image/webp;base64,{asst_b64["face_waiting"]}',
      celebrate: 'data:image/webp;base64,{asst_b64["face_celebrate"]}'
    }};
    let currentAlert = null;
    let currentLang = 'ar';

    // Safe Clipboard Copy Helper with Fallback
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

    // Open Modal by Finding Index
    function openModalByIndex(index) {{
      const alert = ALERTS_DATA[index];
      if (!alert) return;
      currentAlert = alert;

      const riskBadge = document.getElementById('mRiskBadge');
      riskBadge.className = "pill " + alert.badge_class;
      riskBadge.innerText = currentLang === 'ar' ? alert.risk_ar : alert.risk_en;

      document.getElementById('mOwaspBadge').innerText = alert.owasp || 'OWASP Standard';
      document.getElementById('mCweBadge').innerText = alert.cweid ? "CWE-" + alert.cweid : "CWE-N/A";
      document.getElementById('mCvssBadge').innerText = "CVSS " + (alert.cvss || 'N/A');

      const countBadge = document.getElementById('mCountBadge');
      countBadge.innerText = alert.count + (currentLang === 'ar' ? ' حالة' : ' instances');

      document.getElementById('mTitle').innerText = currentLang === 'ar' ? alert.name_ar : alert.name;
      document.getElementById('mTitle').innerText = currentLang === 'en' ? alert.name : alert.name_ar;
      document.getElementById('mSubTitle').innerText = currentLang === 'en' ? (alert.name_ar + " - ID: " + alert.id) : (alert.name + " - ID: " + alert.id);
      document.getElementById('mRiskBadge').innerText = currentLang === 'en' ? alert.risk_en : alert.risk_ar;
      document.getElementById('mCountBadge').innerText = alert.count + (currentLang === 'en' ? ' instances' : ' حالة');

      setPlainText(document.getElementById('mDesc'), alert.desc, '-');
      setPlainText(document.getElementById('mSolution'), alert.solution, 'تطبيق أفضل الممارسات المعتمدة وإجراء مراجعة أمنية للكود المصدري.');
      renderReferences(document.getElementById('mRefs'), alert.reference, 'لا توجد روابط مرجعية مسجلة.');
      document.getElementById('mCvssVectorText').innerText = "Vector: " + (alert.cvss_vector || 'CVSS:3.1/AV:N');

      // Custom Remediation Box
      const customRemed = document.getElementById('mCustomRemediation');
      if (alert.remediation_code) {{
        customRemed.style.display = 'block';
        document.getElementById('mCustomRemediationTitle').innerText = alert.remediation_title || "كود المعالجة المعتمد";
        document.getElementById('mCustomRemediationCode').innerText = alert.remediation_code;
      }} else {{
        customRemed.style.display = 'none';
      }}

      // Custom Checklist
      const chkContainer = document.getElementById('mChecklistContainer');
      if (alert.checklist && alert.checklist.length > 0) {{
        renderTextList(chkContainer, alert.checklist);
      }}

      // CIA Triad Matrix
      const conf = document.getElementById('mImpactConf');
      const integ = document.getElementById('mImpactInteg');
      const avail = document.getElementById('mImpactAvail');
      if (alert.cia) {{
        conf.innerText = alert.cia.c;
        integ.innerText = alert.cia.i;
        avail.innerText = alert.cia.a;
        conf.style.color = alert.cia.c.includes('حرج') ? "var(--unpaid)" : alert.cia.c.includes('مرتفع') ? "var(--unpaid)" : "var(--partial)";
        integ.style.color = alert.cia.i.includes('مرتفع') ? "var(--unpaid)" : "var(--partial)";
        avail.style.color = alert.cia.a.includes('متوسط') ? "var(--partial)" : "var(--paid)";
      }}

      const instContainer = document.getElementById('mInstancesList');
      instContainer.textContent = '';
      if (!alert.instances || alert.instances.length === 0) {{
        const empty = document.createElement('p');
        empty.className = 'subtle';
        empty.textContent = 'لا توجد حالات محددة مسجلة.';
        instContainer.appendChild(empty);
      }} else {{
        alert.instances.forEach((inst, i) => instContainer.appendChild(buildInstanceCard(inst, i)));
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
      let text = `### [تقرير أمان حماك] ${{currentAlert.name_ar}}
- **اسم الثغرة الإنجليزي:** ${{currentAlert.name}}
- **مستوى الخطورة:** ${{currentAlert.risk_ar}} (${{currentAlert.risk_en}})
- **تصنيف OWASP:** ${{currentAlert.owasp || 'N/A'}}
- **معرف CWE:** CWE-${{currentAlert.cweid || 'N/A'}}
- **تقييم CVSS 3.1:** ${{currentAlert.cvss || 'N/A'}}
- **الهدف المفحوص:** ${{CURRENT_REPORT_METRICS.target}}
- **عدد الحالات المصابة:** ${{currentAlert.count}}

#### الوصف الأمني:
${{currentAlert.desc.replace(/<[^>]+>/g, '')}}

#### خطة المعالجة المعتمدة:
${{currentAlert.remediation_title || ''}}`;

      if (currentAlert.remediation_code) {{
        const fence = '`'.repeat(3);
        text += '\\n\\n' + fence + '\\n' + currentAlert.remediation_code + '\\n' + fence;
      }}

      safeCopy(text, () => {{
        const btn = document.getElementById('copyBtnText');
        const orig = btn.innerText;
        btn.innerText = "✓ تم النسخ بنجاح";
        setTimeout(() => {{ btn.innerText = orig; }}, 2000);
      }});
    }}

    function copyRemediationCode() {{
      const codeEl = document.getElementById('mCustomRemediationCode');
      if (!codeEl) return;
      safeCopy(codeEl.innerText, () => {{
        const btn = document.getElementById('copyRemediationBtnText');
        const orig = btn.innerText;
        btn.innerText = "✓ تم نسخ الكود";
        setTimeout(() => {{ btn.innerText = orig; }}, 2000);
      }});
    }}

    function copyCodeDirect(btn) {{
      const code = btn.previousElementSibling ? btn.previousElementSibling.innerText : '';
      if (!code) return;
      safeCopy(code, () => {{
        const orig = btn.innerText;
        btn.innerText = "✓ تم النسخ";
        setTimeout(() => {{ btn.innerText = orig; }}, 2000);
      }});
    }}

    function consultAssistantAboutCurrentFinding() {{
      if (!currentAlert) return;
      closeModal();
      if (!isAssistantOpen) toggleAsaasAssistant();
      const prompt = "اشرح لي بالتفصيل كيفية معالجة ثغرة " + (currentAlert.name_ar || currentAlert.name) + " وما هو الكود الموصى به لسدها؟";
      askAssistantPrompt(prompt);
    }}

    window.addEventListener('keydown', (e) => {{
      if (e.key === 'Escape') {{
        closeModal();
        closeAsaasAssistant();
      }}
    }});

    // ───────── REAL ASAAS ASSISTANT LOGIC ─────────
    let isAssistantOpen = false;
    let assistantChatHistory = [];

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
          <p class="assistant-welcome__lead">أنا مساعد حماك للأمن السيبراني، جاهز لمساعدتك في فحص وتحليل الثغرات واقتراح كود الترقيع البرمجي المعتمد.</p>
          <p>اسألني عن أي ثغرة أو اطلب كود الحماية المعياري لترويسات الخادم وتوصيات المعالجة.</p>

          <div class="assistant-welcome__suggestions">
            <button type="button" class="chip" onclick="askAssistantPrompt('لخص لي الوضع الأمني العام وأهم المخاطر في هذا الفحص')">
              ⚡ لخص لي الوضع الأمني العام
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
        appendAssistantBubble(res.reply, res.mood || 'happy', res.followups || []);
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

    function appendAssistantBubble(htmlText, mood = 'happy', followups = []) {{
      const thread = document.getElementById('asstThread');
      const bubble = document.createElement('div');
      bubble.className = "bubble bubble--assistant";
      const faceSrc = ASST_FACES[mood] || ASST_FACES.happy;

      let followupsHtml = '';
      if (followups && followups.length > 0) {{
        followupsHtml = '<div class="assistant-followups">' +
          followups.map(f => `<button type="button" class="chip--asst" onclick="askAssistantPrompt('${{f}}')">${{f}}</button>`).join('') +
          '</div>';
      }}

      bubble.innerHTML = `
        <img src="${{faceSrc}}" class="assistant-face assistant-face--sm" alt="وجه حماك" draggable="false">
        <div class="bubble__body">
          <div class="bubble__text" style="font-size: 13.5px; line-height: 1.6;">${{htmlText}}${{followupsHtml}}</div>
        </div>
      `;
      thread.appendChild(bubble);
      thread.scrollTo({{ top: thread.scrollHeight, behavior: 'smooth' }});
    }}


    function generateAssistantAIResponse(query) {{
      const qLower = query.toLowerCase();
      let reply = "";
      let mood = "happy";
      let followups = [];

      if (qLower.includes('لخص') || qLower.includes('وضع') || qLower.includes('تقرير') || qLower.includes('نتيجة') || qLower.includes('score')) {{
        mood = CURRENT_REPORT_METRICS.score >= 80 ? "celebrate" : "waiting";
        reply = `📊 <strong>ملخص تقرير الفحص الأمني للهدف (${{escapeHtml(CURRENT_REPORT_METRICS.target)}}):</strong><br><br>` +
                `• <strong>مؤشر السلامة:</strong> ${{CURRENT_REPORT_METRICS.score}}/100 (${{CURRENT_REPORT_METRICS.statusAr}})<br>` +
                `• <strong>الثغرات عالية الخطورة:</strong> ${{CURRENT_REPORT_METRICS.high}} ثغرة<br>` +
                `• <strong>الثغرات متوسطة الخطورة:</strong> ${{CURRENT_REPORT_METRICS.med}} ثغرة<br>` +
                `• <strong>الثغرات منخفضة الخطورة:</strong> ${{CURRENT_REPORT_METRICS.low}} ثغرة<br>` +
                `• <strong>ملاحظات معلوماتية:</strong> ${{CURRENT_REPORT_METRICS.info}}<br><br>` +
                (CURRENT_REPORT_METRICS.high > 0 ? `🚨 <em>تنبيه:</em> هناك ثغرات عالية الخطورة تمنع اعتماد الإطلاق حالياً.` : `✅ مؤشرات الامتثال جيدة جداً.`);
        followups = ["ما هي أخطر الثغرات المرصودة في هذا الفحص؟", "هل النظام مؤهل ومعتمد للإطلاق في بيئة الإنتاج؟"];
      }}
      else if (qLower.includes('أخطر') || qLower.includes('حرجة') || qLower.includes('critical') || qLower.includes('high')) {{
        const criticals = ALERTS_DATA.filter(a => a.riskcode >= 2);
        if (criticals.length === 0) {{
          mood = "celebrate";
          reply = `✅ <strong>بشرى سارة:</strong> لا توجد أي ثغرات عالية أو متوسطة الخطورة في هذا الفحص! النظام يجتاز معايير الأمان الموصى بها.`;
        }} else {{
          mood = "waiting";
          const names = criticals.map(c => `• <strong>${{escapeHtml(c.name_ar)}}</strong> (${{escapeHtml(c.risk_ar)}}) - [${{escapeHtml(c.owasp || 'OWASP')}}]`).join('<br>');
          reply = `⚠️ <strong>أبرز الثغرات التي تتطلب تدخلاً هندسياً عاجلاً:</strong><br><br>${{names}}<br><br>انقر على أي منها في جدول التقرير لمعاينة الدليل التقني وتوصيات التصحيح.`;
          followups = ["كيف أقوم بمعالجة ثغرة حقن SQL بشكل جذري؟", "ما هي إعدادات Nginx الموصى بها لترويسات CSP و HSTS؟"];
        }}
      }}
      else if (qLower.includes('sql')) {{
        mood = "celebrate";
        reply = `💉 <strong>المعالجة الجذرية لثغرات حقن أوامر SQL (CWE-89):</strong><br><br>` +
                `1. <strong>الاستعلامات المجهزة (Parameterized Queries):</strong><br>` +
                `<div class="code-container"><pre class="evidence-box"><code># بايثون مع Psycopg2 / SQLite
cursor.execute("SELECT * FROM users WHERE email = %s AND status = %s", (email, status))

// Node.js مع pg
await client.query('SELECT * FROM users WHERE email = $1', [userId]);</code></pre><button class="code-copy-btn" onclick="copyCodeDirect(this)">نسخ الكود</button></div>` +
                `2. تجنب دمج النصوص (String Concatenation) داخل جمل الاستعلام إطلاقاً.<br>` +
                `3. اعتماد أطر عمل ORM الحديثة مثل Prisma أو SQLAlchemy.`;
        followups = ["ما هي إعدادات Nginx الموصى بها لترويسات CSP و HSTS؟", "قائمة التحقق الأمني قبل الاعتماد"];
      }}
      else if (qLower.includes('csp') || qLower.includes('محتوى')) {{
        mood = "happy";
        reply = `🔒 <strong>ترويسة سياسة أمان المحتوى (CSP) القياسية من حماك:</strong><br><br>` +
                `<div class="code-container"><pre class="evidence-box"><code># Nginx Config:
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';" always;</code></pre><button class="code-copy-btn" onclick="copyCodeDirect(this)">نسخ الكود</button></div>` +
                `هذه الترويسة تمنع هجمات XSS وتمنع تضمين موقعك داخل إطارات Iframe ضارة (Anti-Clickjacking).`;
        followups = ["ما هي إعدادات HSTS؟", "كيف أحمي الموقع من تزوير الطلبات CSRF؟"];
      }}
      else if (qLower.includes('hsts') || qLower.includes('نقل صارم')) {{
        mood = "happy";
        reply = `🛡️ <strong>تفعيل ترويسة Strict-Transport-Security (HSTS):</strong><br><br>` +
                `<div class="code-container"><pre class="evidence-box"><code># Nginx Config:
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;</code></pre><button class="code-copy-btn" onclick="copyCodeDirect(this)">نسخ الكود</button></div>` +
                `تضمن هذه الترويسة إجبار جميع المتصفحات على استخدام اتصال HTTPS المشفر فقط وعدم التراجع لـ HTTP العادي.`;
        followups = ["ما هي إعدادات CSP؟", "قائمة التحقق الأمني قبل الاعتماد"];
      }}
      else if (qLower.includes('csrf') || qLower.includes('تزوير')) {{
        mood = "happy";
        reply = `🛡️ <strong>حماية النماذج من تزوير الطلبات (Anti-CSRF - CWE-352):</strong><br><br>` +
                `1. توليد رمز عشوائي سري (Cryptographic Token) وربطه بجلسة المستخدم.<br>` +
                `2. التحقق من الرمز في كل طلب تعديل بيانات (POST/PUT/DELETE).<br>` +
                `3. تعيين خاصية <code>SameSite=Strict; Secure; HttpOnly</code> لكوكيز الجلسة.`;
        followups = ["كيف أعالج ثغرة حقن SQL؟", "هل النظام مؤهل للإطلاق؟"];
      }}
      else if (qLower.includes('مؤهل') || qLower.includes('إطلاق') || qLower.includes('إنتاج') || qLower.includes('release')) {{
        if (CURRENT_REPORT_METRICS.releaseStatus === 'blocked') {{
          mood = "waiting";
          reply = `⛔ <strong>توصية قرار الإطلاق (Release Decision):</strong><br><br>` +
                  `نوصي بـ <strong>حجب الإطلاق حالياً (Block Release)</strong>: ${{CURRENT_REPORT_METRICS.high}} ثغرة عالية الخطورة، ومؤشر السلامة ${{CURRENT_REPORT_METRICS.score}}/100. ` +
                  `سياسة حماك: يُحجب الإطلاق عند وجود أي ثغرة عالية الخطورة أو انخفاض المؤشر دون 50، ويكون مشروطاً عند وجود ثغرات متوسطة فقط.`;
        }} else if (CURRENT_REPORT_METRICS.releaseStatus === 'conditional') {{
          mood = "happy";
          reply = `⚠️ <strong>توصية قرار الإطلاق:</strong><br><br>` +
                  `يمكن الإطلاق المشروط (Conditional Release) مع جدولة معالجة الثغرات متوسطة الخطورة (${{CURRENT_REPORT_METRICS.med}} ثغرة) خلال أسبوعين.`;
        }} else {{
          mood = "celebrate";
          reply = `🚀 <strong>توصية قرار الإطلاق:</strong><br><br>` +
                  `النظام <strong>مؤهل بالكامل للإطلاق في بيئة الإنتاج</strong>، ولم يتم رصد أي ثغرات مؤثرة تمنع الاعتماد.`;
        }}
        followups = ["ما هي أخطر الثغرات المرصودة في هذا الفحص؟", "قائمة التحقق الأمني قبل الاعتماد"];
      }}
      else if (qLower.includes('تحقق') || qLower.includes('checklist')) {{
        reply = `📋 <strong>قائمة التحقق الأمني المعتمدة قبل الإطلاق (Himaak Baseline):</strong><br><br>` +
                `1. تفعيل ترويسات: CSP, HSTS, X-Content-Type-Options, X-Frame-Options.<br>` +
                `2. تعيين خصائص الكوكيز الحساسة: <code>HttpOnly; Secure; SameSite=Strict</code>.<br>` +
                `3. التحقق من رموز Anti-CSRF في جميع طلبات تعديل البيانات (POST/PUT/DELETE).<br>` +
                `4. حجب معلومات إصدار الخادم (Server Header).`;
        followups = ["ما هي إعدادات Nginx الموصى بها لترويسات CSP و HSTS؟", "لخص لي الوضع الأمني العام"];
      }}
      else {{
        reply = `🤖 بصفتي مساعد حماك الأمني، أنا هنا لمساعدتك في فهم كل تفاصيل هذا التقرير الأمني. ` +
                `يمكنك سؤالي عن: كيفية ترقيع أي ثغرة واردة بالتقرير، إعدادات الخوادم المشفرة، أو شرح معايير CWE المرفقة.`;
        followups = ["لخص لي الوضع الأمني العام", "ما هي أخطر الثغرات المرصودة في هذا الفحص؟"];
      }}

      return {{ reply, mood, followups }};
    }}

    // Filter Logic
    function filterByRisk(risk) {{
      document.querySelectorAll('#riskFilters .segmented__option').forEach(btn => {{
        btn.setAttribute('aria-pressed', btn.getAttribute('data-filter') === String(risk));
      }});
      applyFilters();
    }}

    function filterSearch() {{
      applyFilters();
    }}

    function resetFilters() {{
      document.getElementById('searchInput').value = '';
      filterByRisk('all');
    }}

    function applyFilters() {{
      const activeFilterBtn = document.querySelector('#riskFilters .segmented__option[aria-pressed="true"]');
      const activeRisk = activeFilterBtn ? activeFilterBtn.getAttribute('data-filter') : 'all';
      const searchVal = (document.getElementById('searchInput')?.value || '').toLowerCase().trim();

      let visibleCount = 0;
      document.querySelectorAll('#findingsContainer .finding-card').forEach(card => {{
        const risk = card.getAttribute('data-risk');
        const search = (card.getAttribute('data-search') || '').toLowerCase();

        const matchRisk = activeRisk === 'all' || risk === activeRisk;
        const matchSearch = !searchVal || search.includes(searchVal);

        if (matchRisk && matchSearch) {{
          card.style.display = 'block';
          visibleCount++;
        }} else {{
          card.style.display = 'none';
        }}
      }});

      const emptyEl = document.getElementById('filterEmptyState');
      if (emptyEl) {{
        emptyEl.style.display = visibleCount === 0 ? 'grid' : 'none';
      }}
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
        ? 'حِماك | تقرير الفحص الأمني الشامل'
        : 'Himaak | OWASP ZAP Security Assessment Report';

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
    }}

    // Theme toggle
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
      try {{ localStorage.setItem('asaas-theme', next); }} catch(e) {{}}
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

    // Restore saved theme and language on load
    (function() {{
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
    }})();
  </script>
</body>
</html>
"""

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)

def _md_cell(value, code=False):
    """Makes untrusted text safe for one Markdown table cell.

    code=True is for values placed inside an inline code span, where HTML is
    already shown literally; otherwise HTML and emphasis characters are escaped too.
    """
    text = re.sub(r"[\r\n]+", " ", "" if value is None else str(value))
    text = text.replace("|", "\\|").replace("`", "'").strip()
    if not code:
        text = html.escape(text, quote=False).replace("*", "\\*").replace("_", "\\_")
    return text


def write_github_summary(data, summary_path):
    """Appends a Markdown summary to the GitHub Actions step summary file."""
    if not summary_path:
        return

    release_badge = {
        "approved": "✅ معتمد للإطلاق (Approved)",
        "conditional": "⚠️ إطلاق مشروط (Conditional)",
    }.get(data["release_status"], "⛔ محجوب عن الإطلاق (Blocked)")
    risk_icon = {3: "🔴 High", 2: "🟡 Medium", 1: "🟢 Low", 0: "⚪ Info"}

    rows = "\n".join(
        f"| {risk_icon.get(a['riskcode'], '⚪ Info')} | **{_md_cell(a['name_ar'])}**<br>_{_md_cell(a['name'])}_ "
        f"| {a['count']} | `{('CWE-' + a['cweid']) if a['cweid'] else '—'}` |"
        for a in data["alerts"]
    ) or "| — | لم يتم رصد أي ثغرات | 0 | — |"

    md = f"""
# 🛡️ {PRODUCT_NAME_AR} | {PRODUCT_NAME_EN} Security Scan

> **الهدف المفحوص:** `{_md_cell(data['target_url'], code=True) or '—'}`
> **توقيت الفحص:** `{_md_cell(data['generated_at'], code=True)}` | **محرك الفحص:** `{_md_cell(data['zap_version'], code=True)}`

| مؤشر السلامة | قرار الإطلاق | عالية | متوسطة | منخفضة | معلوماتية | إجمالي الحالات |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **{data['score']} / 100**<br>_{data['status_ar']}_ | **{release_badge}** | **{data['high_count']}** | **{data['med_count']}** | **{data['low_count']}** | **{data['info_count']}** | **{data['total_instances']}** |

### 🔍 الثغرات المرصودة

| الخطورة | الثغرة | الحالات | CWE |
| :--- | :--- | :---: | :---: |
{rows}

---
💡 التقرير التفاعلي الكامل مرفوع كملف ناتج (Artifact) في هذا التشغيل.
"""
    try:
        # GitHub expects steps to append to $GITHUB_STEP_SUMMARY, not overwrite it.
        with open(summary_path, "a", encoding="utf-8") as f:
            f.write(md)
    except OSError as err:
        print(f"[{PRODUCT_NAME_EN}] Warning: Could not write GitHub step summary: {err}")


def main():
    parser = argparse.ArgumentParser(description=f"{PRODUCT_NAME_EN}: generate a security HTML report from OWASP ZAP JSON")
    parser.add_argument("--json", required=True, help="Path to zap_report.json")
    parser.add_argument("--output-html", default="himaak_report.html", help="Path for HTML output")
    parser.add_argument("--summary", default="", help="Path to the GitHub step summary file (appended to)")
    parser.add_argument("--fail-on", choices=["none", "blocked", "conditional"], default="none",
                        help="Exit with code 1 when the release decision is at least this severe")
    args = parser.parse_args()

    print(f"[{PRODUCT_NAME_EN}] Parsing ZAP report: {args.json}")
    report_data = parse_zap_json(args.json)

    print(f"[{PRODUCT_NAME_EN}] Generating HTML report: {args.output_html}")
    generate_html_report(report_data, args.output_html, PROJECT_ROOT)

    if args.summary:
        print(f"[{PRODUCT_NAME_EN}] Writing GitHub step summary: {args.summary}")
        write_github_summary(report_data, args.summary)

    status = report_data["release_status"]
    print(f"[{PRODUCT_NAME_EN}] Done. Score: {report_data['score']}/100, release decision: {status}")

    failing = {"blocked": {"blocked"}, "conditional": {"blocked", "conditional"}}.get(args.fail_on, set())
    if status in failing:
        print(f"[{PRODUCT_NAME_EN}] Release gate failed (--fail-on {args.fail_on}).")
        sys.exit(1)


if __name__ == "__main__":
    main()
