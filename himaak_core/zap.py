# -*- coding: utf-8 -*-
"""Reads OWASP ZAP JSON reports into Himaak's normalised form.

ZAP's desc/solution/reference/otherinfo fields are HTML fragments taken from
the scanned site's responses. They are converted to plain text here, so no
consumer ever has to render scanner-supplied HTML.
"""

import json
import os
import re
from datetime import datetime
from html.parser import HTMLParser

from himaak_core.knowledge import CYBER_KNOWLEDGE
from himaak_core.policy import assess_release


RISK_LABELS = {
    3: {"en": "High Risk", "ar": "عالي الخطورة", "badge": "pill--high", "impact": "عالي جداً (Critical Impact)"},
    2: {"en": "Medium Risk", "ar": "متوسط الخطورة", "badge": "pill--medium", "impact": "متوسط (Moderate Impact)"},
    1: {"en": "Low Risk", "ar": "منخفض الخطورة", "badge": "pill--low", "impact": "محدود (Low Impact)"},
    0: {"en": "Informational", "ar": "معلوماتي", "badge": "pill--info", "impact": "توثيقي (Informational)"},
}


class _TextExtractor(HTMLParser):
    """Collects the text of an HTML fragment, turning block tags into line breaks."""
    BREAK_TAGS = {"p", "br", "li", "div", "tr", "h1", "h2", "h3", "h4", "h5", "h6"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag in self.BREAK_TAGS:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in self.BREAK_TAGS:
            self.parts.append("\n")

    def handle_data(self, data):
        self.parts.append(data)


def html_to_text(fragment):
    """Converts a ZAP HTML fragment (desc, solution, reference) into plain text."""
    if not fragment:
        return ""
    parser = _TextExtractor()
    try:
        parser.feed(str(fragment))
        parser.close()
        text = "".join(parser.parts)
    except Exception:
        text = re.sub(r"<[^>]+>", " ", str(fragment))
    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def safe_url(url):
    """Returns the URL only when it is http(s); anything else becomes '#'."""
    url = (url or "").strip()
    return url if re.match(r"^https?://", url, re.IGNORECASE) else "#"


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _as_int(value, default=0):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def extract_urls(text):
    """Returns the distinct http(s) URLs found in a block of text, in order."""
    seen, urls = set(), []
    for url in re.findall(r"https?://[^\s<>\"']+", text or ""):
        url = url.rstrip(".,);]")
        if url not in seen:
            seen.add(url)
            urls.append(url)
    return urls


def enrich_alert(a):
    """Normalises one raw ZAP alert and adds the knowledge-base metadata.

    ZAP's desc/solution/reference/otherinfo fields are HTML fragments. They are
    converted to plain text here so the report never renders scanner-supplied HTML.
    """
    risk_code = _as_int(a.get("riskcode"), 0)
    if risk_code not in RISK_LABELS:
        risk_code = 0
    risk_meta = RISK_LABELS[risk_code]

    instances = []
    for inst in _as_list(a.get("instances")):
        if not isinstance(inst, dict):
            continue
        instances.append({
            "uri": str(inst.get("uri", "") or ""),
            "method": str(inst.get("method", "GET") or "GET"),
            "param": str(inst.get("param", "") or ""),
            "attack": str(inst.get("attack", "") or ""),
            "evidence": str(inst.get("evidence", "") or ""),
        })

    alert_name = str(a.get("name") or a.get("alert") or "Unknown Issue")
    knowledge = CYBER_KNOWLEDGE.get(alert_name, {})
    default_cvss = {3: "8.5", 2: "6.0", 1: "3.5"}.get(risk_code, "2.0")
    default_cia = {
        "c": "مرتفع (High)" if risk_code == 3 else "متوسط (Medium)" if risk_code == 2 else "منخفض (Low)",
        "i": "مرتفع (High)" if risk_code == 3 else "متوسط (Medium)" if risk_code == 2 else "منخفض (Low)",
        "a": "متوسط (Medium)" if risk_code == 3 else "منخفض (Low)" if risk_code == 2 else "محدود (Minimal)",
    }
    cwe_raw = str(a.get("cweid") or knowledge.get("cwe", "")).replace("CWE-", "").strip()
    reference_text = html_to_text(a.get("reference", ""))

    return {
        "id": str(a.get("pluginid", "0") or "0"),
        "name": alert_name,
        "name_ar": knowledge.get("name_ar", alert_name),
        "owasp": knowledge.get("owasp", "OWASP General Web Security"),
        "cweid": cwe_raw if cwe_raw.isdigit() else "",
        "cvss": knowledge.get("cvss", default_cvss),
        "cvss_vector": knowledge.get("cvss_vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U"),
        "category_ar": knowledge.get("category_ar", "فحص الثغرات العامة"),
        "cia": knowledge.get("cia", default_cia),
        "riskcode": risk_code,
        "risk_en": risk_meta["en"],
        "risk_ar": risk_meta["ar"],
        "badge_class": risk_meta["badge"],
        "impact_label": risk_meta["impact"],
        "confidence": str(a.get("confidence", "2")),
        "riskdesc": str(a.get("riskdesc", "") or ""),
        "desc": html_to_text(a.get("desc", "")),
        "solution": html_to_text(a.get("solution", "")),
        "otherinfo": html_to_text(a.get("otherinfo", "")),
        "reference": reference_text,
        "reference_urls": extract_urls(reference_text),
        "wascid": str(a.get("wascid", "") or ""),
        "count": _as_int(a.get("count"), len(instances)) or len(instances),
        "instances": instances,
        "remediation_title": knowledge.get("remediation_title", "إجراءات الترقيع الأمني المعتمدة"),
        "remediation_code": knowledge.get("remediation_code", "# مراجعة وتعديل الكود المصدري وفق معايير OWASP"),
        "checklist": knowledge.get("checklist", [
            "إجراء فحص الكود المصدري (Static Code Review) للتحقق من إغلاق الموضع المصاب.",
            "إعادة تشغيل فحص OWASP ZAP والتأكد من اختفاء التنبيه تماماً.",
            "تحديث إعدادات الخوادم أو جدران الحماية (WAF) وتفعيل الحظر الاستباقي.",
        ]),
    }


def summarize_report(data):
    """Turns a parsed ZAP JSON document into the data the report template needs."""
    zap_version = str(data.get("@version", "OWASP ZAP 2.x"))
    generated_at = str(data.get("@generated", datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

    all_alerts = []
    target_urls = []
    for site in _as_list(data.get("site")):
        if not isinstance(site, dict):
            continue
        site_name = str(site.get("@name", "") or "")
        if site_name and site_name not in target_urls:
            target_urls.append(site_name)
        for a in _as_list(site.get("alerts")):
            if isinstance(a, dict):
                all_alerts.append(enrich_alert(a))

    # High -> Medium -> Low -> Info
    all_alerts.sort(key=lambda x: x["riskcode"], reverse=True)

    high_count = sum(1 for a in all_alerts if a["riskcode"] == 3)
    med_count = sum(1 for a in all_alerts if a["riskcode"] == 2)
    low_count = sum(1 for a in all_alerts if a["riskcode"] == 1)
    info_count = sum(1 for a in all_alerts if a["riskcode"] == 0)

    return {
        "zap_version": zap_version,
        "generated_at": generated_at,
        "target_url": ", ".join(target_urls) if target_urls else "",
        "target_href": safe_url(target_urls[0]) if target_urls else "#",
        "alerts": all_alerts,
        "high_count": high_count,
        "med_count": med_count,
        "low_count": low_count,
        "info_count": info_count,
        "total_alerts": len(all_alerts),
        "total_instances": sum(a["count"] for a in all_alerts),
        **assess_release(high_count, med_count, low_count),
    }


def parse_zap_json(json_path):
    """Parses an OWASP ZAP JSON report file and enriches its alerts."""
    if not os.path.exists(json_path):
        raise FileNotFoundError(f"ZAP report file not found at: {json_path}")
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("Unexpected ZAP report format: top-level JSON object expected.")
    return summarize_report(data)
