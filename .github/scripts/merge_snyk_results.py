"""
merge_snyk_results.py — Merges four raw Snyk JSON outputs into snyk-result.json.
Called by the snyk-scan job in dispatcher-pr-analyzer.yml.
"""

import json
import pathlib
import sys

SARIF_LEVEL_MAP = {"error": "high", "warning": "medium", "note": "low", "none": "low"}


def load(path):
    try:
        text = pathlib.Path(path).read_text()
        data = json.loads(text)
        return data[0] if isinstance(data, list) and data else (data if isinstance(data, dict) else {})
    except Exception:
        return {}


def sarif_results(data):
    return [r for run in data.get("runs", []) for r in run.get("results", [])]


def sarif_severity(result):
    raw = (result.get("level") or "warning").lower()
    return SARIF_LEVEL_MAP.get(raw, "medium")


def sarif_location(result):
    try:
        loc  = result["locations"][0]["physicalLocation"]
        path = loc["artifactLocation"]["uri"]
        line = loc.get("region", {}).get("startLine", 0)
        return f"{path}:{line}" if line else path
    except (KeyError, IndexError):
        return ""


def sarif_issues(data, source):
    return [
        {
            "id":       r.get("ruleId") or "unknown",
            "title":    (r.get("message") or {}).get("text") or "No title",
            "severity": sarif_severity(r),
            "source":   source,
            "location": sarif_location(r),
        }
        for r in sarif_results(data)
    ]


def dep_vulns(data):
    return data.get("vulnerabilities", [])


def count_sev(vulns, sev):
    return sum(1 for v in vulns if v.get("severity", "").lower() == sev)


def dep_issues(data, source):
    return [
        {
            "id":       v.get("id") or "unknown",
            "title":    v.get("title") or v.get("packageName") or "No title",
            "severity": v.get("severity", "unknown").lower(),
            "source":   source,
            "location": f"{v.get('packageName', '')}@{v.get('version', '')}",
        }
        for v in dep_vulns(data)[:20]
    ]


code    = load("snyk-code-raw.json")
maven   = load("snyk-maven-raw.json")
widgets = load("snyk-widgets-raw.json")
idl     = load("snyk-idl-raw.json")

sarif_all   = sarif_results(code)
code_high   = sum(1 for r in sarif_all if sarif_severity(r) == "high")
code_medium = sum(1 for r in sarif_all if sarif_severity(r) == "medium")
code_low    = sum(1 for r in sarif_all if sarif_severity(r) == "low")

SECRET_RULE_KEYWORDS = ("secret", "credential", "password", "hardcoded", "token", "apikey")
code_secrets = sum(
    1 for r in sarif_all
    if any(kw in (r.get("ruleId") or "").lower() for kw in SECRET_RULE_KEYWORDS)
)

all_dep      = dep_vulns(maven) + dep_vulns(widgets) + dep_vulns(idl)
dep_critical = count_sev(all_dep, "critical")
dep_high     = count_sev(all_dep, "high")
dep_medium   = count_sev(all_dep, "medium")
dep_low      = count_sev(all_dep, "low")

all_issues = (
    sarif_issues(code, "java-sast")
    + dep_issues(maven,   "maven-deps")
    + dep_issues(widgets, "ui.frontend.widgets")
    + dep_issues(idl,     "ui.frontend.idl")
)

failed = code_secrets > 0 or dep_critical > 0 or (code_high + dep_high) > 0
status = "failed" if failed else "passed"

result = {
    "status":         status,
    "secrets_found":  code_secrets,
    "sast_high":      code_high,
    "sast_medium":    code_medium,
    "critical_vulns": dep_critical,
    "high_vulns":     dep_high,
    "medium_vulns":   dep_medium,
    "low_vulns":      dep_low,
    "issues":         all_issues[:30],
}

pathlib.Path("snyk-result.json").write_text(json.dumps(result, indent=2))
print("Wrote snyk-result.json")
print(json.dumps(result, indent=2))

if failed:
    print("::error::Snyk found vulnerabilities or secrets.")
    sys.exit(1)
