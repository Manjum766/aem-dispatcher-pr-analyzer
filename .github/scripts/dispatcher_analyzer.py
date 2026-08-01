from pathlib import Path

findings = []

# Scan all files under dispatcher/
for path in Path("dispatcher").rglob("*"):
    if path.is_file():
        text = path.read_text(errors="ignore")

        print(f"Scanning: {path}")

        # HIGH: overly broad allow rule
        if '/glob "*"' in text and '/type "allow"' in text:
            findings.append({
                "severity": "HIGH",
                "file": str(path),
                "title": "Overly broad allow rule",
                "details": "This rule may expose or cache unintended paths."
            })

        # MEDIUM: ignore all URL params
        if '/ignoreUrlParams' in text and '/glob "*"' in text:
            findings.append({
                "severity": "MEDIUM",
                "file": str(path),
                "title": "All query parameters are considered",
                "details": "UTM, fbclid, gclid may fragment the cache and reduce cache hit ratio."
            })

        # MEDIUM: GraphQL endpoint
        if '/_cq_graphql' in text:
            findings.append({
                "severity": "MEDIUM",
                "file": str(path),
                "title": "GraphQL endpoint modified",
                "details": "Verify caching, authorization, and persisted query behavior."
            })

print(f"Findings: {len(findings)}")

# Risk score
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

# Generate report
report = [f"## AEM Dispatcher/CDN Analysis — {level} ({score}/100)\\n"]

if not findings:
    report.append("No significant dispatcher risks detected. ✅")
else:
    icons = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡"}

    for f in findings:
        report.append(f"### {icons[f['severity']]} {f['title']}")
        report.append(f"**File:** `{f['file']}`")
        report.append(f"**Severity:** {f['severity']}")
        report.append(f['details'])
        report.append("")

    report.append("---")
    report.append(f"**Overall Risk Score:** {score}/100 ({level})")

content = "\\n".join(report)

# Write report
Path("dispatcher-report.md").write_text(content)

print("\\n===== REPORT =====\\n")
print(content)