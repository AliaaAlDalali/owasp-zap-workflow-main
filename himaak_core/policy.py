# -*- coding: utf-8 -*-
"""Himaak scoring and release policy: the single source of truth.

The same rules are mirrored in the page JavaScript (assessRelease) of the
generated report and dashboard.
"""

SCORE_WEIGHTS = {"high": 25, "med": 10, "low": 3}


def compute_score(high, med, low):
    deduction = high * SCORE_WEIGHTS["high"] + med * SCORE_WEIGHTS["med"] + low * SCORE_WEIGHTS["low"]
    return max(0, min(100, 100 - deduction))


def assess_release(high, med, low):
    """Score, health status and release decision.

    Release policy:
      - blocked     : any high-risk finding, or a score below 50
      - conditional : no high-risk findings, but at least one medium (fix within 14 days)
      - approved    : only low / informational findings
    """
    score = compute_score(high, med, low)

    if score >= 90:
        grade, status_ar, status_en, status_color = "A+", "ممتاز / آمن", "Secure / Excellent", "var(--paid)"
    elif score >= 75:
        grade, status_ar, status_en, status_color = "B", "جيد / يتطلب معالجة طفيفة", "Moderate / Minor Issues", "var(--brand-gold)"
    elif score >= 50:
        grade, status_ar, status_en, status_color = "C", "متوسط / مخاطر محتملة", "Warning / Action Required", "var(--partial)"
    else:
        grade, status_ar, status_en, status_color = "F", "حرج / يتطلب تدخلاً عاجلاً", "Critical / Urgent Action Needed", "var(--unpaid)"

    if high > 0 or score < 50:
        reason_ar = ("تم رصد ثغرات عالية الخطورة تهدد سلامة النظام." if high > 0
                     else "تراكمت ملاحظات متوسطة الخطورة حتى انخفض مؤشر السلامة دون 50.")
        reason_en = ("High-risk vulnerabilities were detected." if high > 0
                     else "Accumulated medium-risk findings pushed the health score below 50.")
        release = {
            "release_status": "blocked",
            "release_title_ar": "حظر الإطلاق للإنتاج (Release Blocked)",
            "release_title_en": "Production Release Blocked (P1 Blocker)",
            "release_desc_ar": reason_ar + " يُمنع النشر للإنتاج حتى اكتمال المعالجة وإعادة الفحص.",
            "release_desc_en": reason_en + " Production release is blocked until remediation and a clean re-scan.",
            "release_pill_ar": "محظور من النشر (Blocked)",
            "release_pill_en": "RELEASE BLOCKED",
            "release_color": "var(--unpaid)",
            "release_sla_ar": "فوري قبل النشر",
            "release_sla_en": "Immediate before deploy",
        }
    elif med > 0:
        release = {
            "release_status": "conditional",
            "release_title_ar": "إطلاق مشروط (Conditional Release)",
            "release_title_en": "Conditional Release (Grace Period)",
            "release_desc_ar": "لا توجد ثغرات عالية الخطورة، ولكن يلزم جدولة معالجة الثغرات المتوسطة خلال 14 يوماً.",
            "release_desc_en": "No high-risk blockers. Medium findings must be remediated within 14 calendar days.",
            "release_pill_ar": "إطلاق مشروط (Conditional)",
            "release_pill_en": "CONDITIONAL APPROVAL",
            "release_color": "var(--partial)",
            "release_sla_ar": "14 يوماً تقويمياً",
            "release_sla_en": "14 Calendar Days",
        }
    else:
        release = {
            "release_status": "approved",
            "release_title_ar": "معتمد للإطلاق والإنتاج (Approved for Production)",
            "release_title_en": "Approved for Production",
            "release_desc_ar": "لا توجد ثغرات عالية أو متوسطة الخطورة، ولا توجد موانع للنشر.",
            "release_desc_en": "No high or medium risk findings. No release blockers.",
            "release_pill_ar": "ممتثل (Compliant)",
            "release_pill_en": "COMPLIANT",
            "release_color": "var(--paid)",
            "release_sla_ar": "مستوفٍ للمعايير",
            "release_sla_en": "Compliant",
        }

    return {"score": score, "grade": grade, "status_ar": status_ar, "status_en": status_en,
            "status_color": status_color, **release}
