from pathlib import Path
import sys

findings = []

def add(severity, file, title, details):
    findings.append({
        "severity": severity,
        "file": file,
        "title": title,
        "details": details
    })

# Scan dispatcher files
for path in Path("dispatcher").rglob("*"):
    if path.is_file():
        text = path.read_text(errors="ignore")

        print(f"Scanning: {path}")
        print(text)

        # HIGH: broad allow
        if '/glob "*"' in text and '/type "allow"' in text:
            add(
                "HIGH",
                str(path),
                "Overly broad allow rule",
                "This rule may expose or cache unintended paths."
            )

        # MEDIUM: ignore all params
        if '/ignoreUrlParams' in text:
            add(
                "MEDIUM",
                str(path),
                "All query parameters are considered",
                "UTM, fbclid, gclid may fragment the cache and reduce cache hit ratio."
            )

print(f"Findings: {len(findings)}")

# Score
score = 0
for f in findings:
    if f["severity"] == "HIGH":
        score += 25
    else:
        score += 10

score = min(score, 100)

level = "LOW"
if score >= 25:
    level = "HIGH"

has_high = any(f["severity"] == "HIGH" for f in findings)

# Markdown report
report = [f"# AEM Dispatcher/CDN Analysis — {level} ({score}/100)", ""]

if not findings:
    report.append("No significant dispatcher risks detected. ✅")
else:
    for f in findings:
        icon = "🔴" if f["severity"] == "HIGH" else "🟠"

        report.extend([
            f"## {icon} {f['title']}",
            "",
            f"**File:** `{f['file']}`",
            f"**Severity:** {f['severity']}",
            "",
            f["details"],
            "",
            "---",
            ""
        ])

    report.append(f"### Overall Risk Score: **{score}/100 ({level})**")
    report.append("")

    if has_high:
        report.append("❌ **Merge blocked until HIGH severity findings are resolved.**")

content = "\\n".join(report)

Path("dispatcher-report.md").write_text(content, encoding="utf-8")

print("===== REPORT =====")
print(content)

if has_high:
    sys.exit(1)