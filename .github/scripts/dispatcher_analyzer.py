import re
from pathlib import Path
import sys

findings = []
seen = set()


def add_finding(severity, file, title, details):
    key = (severity, file, title)
    if key not in seen:
        seen.add(key)
        findings.append({
            "severity": severity,
            "file": file,
            "title": title,
            "details": details
        })


# Scan all files under dispatcher/
for path in Path("dispatcher").rglob("*"):
    if not path.is_file():
        continue

    text = path.read_text(errors="ignore")

    print(f"Scanning: {path}")

    # HIGH: overly broad allow rule
    if re.search(r'/glob\\s*"\\*"\\s*/type\\s*"allow"', text):
        add_finding(
            "HIGH",
            str(path),
            "Overly broad allow rule",
            "This rule may expose or cache unintended paths."
        )

    # MEDIUM: all query parameters considered
    if re.search(r'/ignoreUrlParams\\s*\\{[^}]*?/glob\\s*"\\*"', text, re.DOTALL):
        add_finding(
            "MEDIUM",
            str(path),
            "All query parameters are considered",
            "UTM, fbclid, gclid may fragment the cache and reduce cache hit ratio."
        )

    # MEDIUM: GraphQL endpoint changes
    if "/_cq_graphql" in text:
        add_finding(
            "MEDIUM",
            str(path),
            "GraphQL endpoint modified",
            "Verify caching, authorization, and persisted query behavior."
        )

    # HIGH: /conf exposed
    if re.search(r'/url\\s*"/conf/', text):
        add_finding(
            "HIGH",
            str(path),
            "/conf path exposed",
            "Dispatcher should not expose /conf content directly."
        )

    # HIGH: excessive cache invalidation
    if re.search(r'/statfileslevel\\s*"0"', text):
        add_finding(
            "HIGH",
            str(path),
            "statfileslevel is 0",
            "May cause excessive cache invalidation and origin load."
        )

    # MEDIUM: missing CSP header in vhost
    if path.suffix == ".vhost":
        if "Content-Security-Policy" not in text:
            add_finding(
                "MEDIUM",
                str(path),
                "CSP header not found",
                "Verify Content-Security-Policy is configured."
            )

print(f"Findings: {len(findings)}")

# Risk scoring
score = 0

for f in findings:
    if f["severity"] == "HIGH":
        score += 25
    elif f["severity"] == "MEDIUM":
        score += 10
    else:
        score += 5

score = min(score, 100)

if score < 25:
    level = "LOW"
elif score < 50:
    level = "MEDIUM"
elif score < 75:
    level = "HIGH"
else:
    level = "CRITICAL"

has_high = any(f["severity"] == "HIGH" for f in findings)

# Build markdown report
report = [
    f"# AEM Dispatcher/CDN Analysis — {level} ({score}/100)",
    ""
]

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

    report.extend([
        f"### Overall Risk Score: **{score}/100 ({level})**",
        ""
    ])

    if has_high:
        report.append("❌ **Merge blocked until HIGH severity findings are resolved.**")
    else:
        report.append("✅ Findings are informational; merge is allowed.")

# IMPORTANT: real newlines
content = "\\n".join(report)

# Write report
Path("dispatcher-report.md").write_text(content, encoding="utf-8")

print("\\n===== REPORT =====\\n")
print(content)

# Fail workflow on HIGH findings
if has_high:
    print("High severity dispatcher findings detected. Failing the workflow.")
    sys.exit(1)