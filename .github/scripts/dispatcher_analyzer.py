import re
from pathlib import Path

findings = []

# Scan dispatcher files
for path in Path("dispatcher").rglob("*"):
    if path.is_file():
        text = path.read_text(errors="ignore")
print(f"Scanning: {path}")
        # Rule 1: overly broad allow
      print(text)
if '/glob "*"' in text and '/type "allow"' in text:
    findings.append({
        "severity": "HIGH",
        "file": str(path),
        "title": "Overly broad allow rule",
        "details": "This rule may expose or cache unintended paths."
    })

# Rule 2: ignore all URL params
if '/ignoreUrlParams' in text and '/glob "*"' in text:
    findings.append({
        "severity": "MEDIUM",
        "file": str(path),
        "title": "All query parameters are considered",
        "details": "UTM, fbclid, gclid may fragment the cache and reduce cache hit ratio."
    })

# Generate markdown report
report = ["## AEM Dispatcher/CDN Analysis\\n"]

if not findings:
    report.append("No significant dispatcher risks detected. ✅")
else:
    severity_icon = {
        "HIGH": "🔴",
        "MEDIUM": "🟠",
        "LOW": "🟡"
    }

    for f in findings:
        report.append(f"### {severity_icon[f['severity']]} {f['title']}")
        report.append(f"**File:** `{f['file']}`")
        report.append(f"**Severity:** {f['severity']}`")
        report.append(f['details'])
        report.append("")

Path("dispatcher-report.md").write_text("\\n".join(report))

print("\\n".join(report))