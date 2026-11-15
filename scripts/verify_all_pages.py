# -*- coding: utf-8 -*-
"""
Sanity checks for the generated Himaak (حِماك) HTML pages.

Run after build_index.py / generate_report.py:  python scripts/verify_all_pages.py
Exits with code 1 if any check fails.
"""
import os
import sys
from html.parser import HTMLParser

sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Page -> checks that only apply to that kind of page.
FILES_TO_CHECK = {
    "index.html": {
        "Report Upload Dropzone": lambda c: 'id="portalDropzone"' in c,
        "Filter Empty State Card": lambda c: 'id="filterEmptyState"' in c,
        "Reports Switcher Deck": lambda c: 'id="reportsDeck"' in c,
    },
    os.path.join("docs", "sample_report.html"): {},
}

COMMON_CHECKS = {
    "Base64 Thmanyah Sans Font": lambda c: "data:font/woff2;base64," in c,
    "Base64 Logo": lambda c: "data:image/png;base64," in c,
    "Base64 Robot Icons": lambda c: "data:image/webp;base64," in c,
    "Himaak Branding": lambda c: "حِماك" in c or "حماك" in c,
    "Assistant Launcher": lambda c: 'id="asaasLauncher"' in c,
    "Assistant Panel": lambda c: 'id="asaasPanel"' in c,
    "Assistant Faces": lambda c: all(k + ":" in c for k in ("smile", "waiting", "happy", "celebrate")),
    "Security Score Gauge": lambda c: "scoreCircleFill" in c,
    "Release Decision Gate": lambda c: 'id="releaseDecisionCard"' in c,
    "Finding Inspector Modal": lambda c: 'id="findingModalBackdrop"' in c,
    "CIA Impact Matrix": lambda c: 'id="mImpactConf"' in c and 'id="mImpactInteg"' in c,
    "Remediation Code Box": lambda c: "mCustomRemediation" in c and "copyRemediationCode" in c,
    "Safe Clipboard Copy": lambda c: "safeCopy" in c and "document.execCommand" in c,
    "Safe Rendering Helpers": lambda c: all(f in c for f in ("function htmlToText", "function setPlainText",
                                                             "function buildInstanceCard", "function safeHttpUrl")),
    "No raw </script> inside embedded data": lambda c: c.lower().count("</script>") == c.lower().count("<script"),
}


class TagCounter(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tag_count = 0

    def handle_starttag(self, tag, attrs):
        self.tag_count += 1


def check_file(rel_path, extra_checks):
    full_path = os.path.join(PROJECT_ROOT, rel_path)
    print("\n==========================================")
    print(f"Checking: {rel_path}")
    if not os.path.exists(full_path):
        print(f"  ✗ FAIL: file does not exist: {full_path}")
        return False

    with open(full_path, "r", encoding="utf-8") as f:
        content = f.read()

    ok = True
    print(f"  - Size: {len(content):,} chars ({len(content.encode('utf-8')):,} bytes)")

    bad_chars = content.count("�")
    print(f"  - Unicode replacement chars: {bad_chars}")
    if bad_chars:
        print("    [!] FAILED: found corrupted characters")
        ok = False

    for name, check in {**COMMON_CHECKS, **extra_checks}.items():
        result = check(content)
        print(f"  - {name}: {'✓ PASS' if result else '✗ FAIL'}")
        ok = ok and result

    parser = TagCounter()
    try:
        parser.feed(content)
        print(f"  - HTML Parser: ✓ Clean parse ({parser.tag_count} tags)")
    except Exception as e:  # HTMLParser rarely raises, but never let it crash the run
        print(f"  - HTML Parser: ✗ FAILED ({e})")
        ok = False
    return ok


def main():
    results = [check_file(path, extra) for path, extra in FILES_TO_CHECK.items()]
    print("\n==========================================")
    if all(results):
        print(f">>> All {len(results)} pages passed. <<<")
        return 0
    print(">>> Some checks failed. <<<")
    return 1


if __name__ == "__main__":
    sys.exit(main())
