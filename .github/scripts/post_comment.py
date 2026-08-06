"""
post_comment.py — Build and upsert the PR Review Agent GitHub comment.

Called by the post-comment job in dispatcher-pr-analyzer.yml.
Reads sonar-result.json, snyk-result.json, dispatcher-result.json
from the current working directory and upserts a single PR comment.

Required env vars:
  GH_TOKEN   GitHub token (GITHUB_TOKEN secret)
  REPO       owner/repo  (github.repository)
  PR         PR number   (github.event.pull_request.number or resolved)
"""

import json
import os
import sys
import textwrap
import urllib.error
import urllib.request

# Fix databases live in a separate file — no backtick fences in this script.
sys.path.insert(0, os.path.dirname(__file__))
from fix_recommendations import snyk_sast_fix, snyk_dep_fix, disp_fix

MARKER = "<!-- pr-review-agent-marker -->"
TOKEN  = os.environ["GH_TOKEN"]
REPO   = os.environ["REPO"]
PR     = os.environ["PR"]
API    = "https://api.github.com"

HEADERS = {
    "Authorization": f"token {TOKEN}",
    "Accept": "application/vnd.github+json",
    "Content-Type": "application/json",
    "X-GitHub-Api-Version": "2022-11-28",
}


def gh(method, path, body=None):
    data = json.dumps(body).encode() if body else None
    req  = urllib.request.Request(f"{API}{path}", data=data, headers=HEADERS, method=method)
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        print(f"GitHub API {method} {path} -> {e.code}: {e.read().decode()}")
        return {}


def load(path):
    try:
        return json.loads(open(path).read())
    except Exception:
        return {"status": "did_not_complete"}


sonar = load("sonar-result.json")
snyk  = load("snyk-result.json")
disp  = load("dispatcher-result.json")

# ── Summary table rows ────────────────────────────────────────────────────────

sonar_status = sonar.get("status", "did_not_complete")
sonar_badge  = {"passed": "✅ Passed", "failed": "❌ Failed"}.get(sonar_status, "⚠️ Scan did not complete")
sonar_url    = sonar.get("dashboard_url", "")
sonar_link   = f" — [Dashboard]({sonar_url})" if sonar_url else ""
sonar_detail = f"QG: {sonar.get('quality_gate_status', '?')}{sonar_link}"

snyk_status  = snyk.get("status", "did_not_complete")
snyk_badge   = {"passed": "✅ Passed", "failed": "❌ Issues found"}.get(snyk_status, "⚠️ Scan did not complete")
snyk_detail  = (
    f"SAST: {snyk.get('sast_high','?')} high, {snyk.get('sast_medium','?')} medium · "
    f"CVEs: {snyk.get('critical_vulns','?')} critical, {snyk.get('high_vulns','?')} high · "
    f"Secrets: {snyk.get('secrets_found','?')}"
)

disp_status  = disp.get("status", "did_not_complete")
disp_badge   = {"passed": "✅ Clean", "warnings": "⚠️ Warnings", "failed": "❌ Issues found"}.get(disp_status, "⚠️ Scan did not complete")
disp_detail  = (
    f"{disp.get('total_findings','?')} findings · "
    f"{disp.get('critical','?')} critical, {disp.get('high','?')} high · "
    f"score: {disp.get('score','?')}/100"
)

# ── AI agent action-required block ────────────────────────────────────────────

any_failed = any(s == "failed" for s in [sonar_status, snyk_status, disp_status])
if any_failed:
    action_items = []
    if disp_status == "failed":
        action_items.append(
            f"- **Dispatcher** — fix {disp.get('critical',0)} critical and "
            f"{disp.get('high',0)} high rule violations in your `.any` / `.vhost` files "
            f"before this can be merged (see findings below)"
        )
    if snyk_status == "failed":
        if snyk.get("secrets_found", 0) > 0:
            action_items.append(
                "- **Secrets** — remove hardcoded credentials from source code immediately; "
                "rotate any exposed values and store them in environment variables or a secrets manager"
            )
        if (snyk.get("sast_high", 0) or 0) > 0:
            action_items.append(
                f"- **SAST** — {snyk.get('sast_high',0)} high-severity code issues detected "
                f"(SQL injection, weak crypto, etc.) — see fix recommendations below"
            )
        if (snyk.get("critical_vulns", 0) or 0) + (snyk.get("high_vulns", 0) or 0) > 0:
            action_items.append(
                f"- **Dependencies** — {snyk.get('critical_vulns',0)} critical and "
                f"{snyk.get('high_vulns',0)} high CVEs in Maven dependencies — upgrade to patched versions (see below)"
            )
    if sonar_status == "failed":
        action_items.append(
            "- **SonarCloud** — Quality Gate failed; open the dashboard link above, "
            "resolve all new bugs / vulnerabilities / hotspots on this branch"
        )
    agent_summary = (
        "> [!CAUTION]\n"
        "> **🤖 AI Agent — Action Required before merge:**\n>\n"
        + "\n".join(f"> {a}" for a in action_items)
    )
else:
    agent_summary = (
        "> [!NOTE]\n"
        "> **🤖 AI Agent** — All scans passed. This PR is clear to merge from a security standpoint."
    )

# ── Snyk findings block ───────────────────────────────────────────────────────

SEV_ICON  = {"high": "🔴", "critical": "🔴", "medium": "🟠", "low": "🟡"}
DISP_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}

snyk_issues = snyk.get("issues", [])
if snyk_issues:
    sast = [i for i in snyk_issues if i.get("source") == "java-sast"]
    deps = [i for i in snyk_issues if i.get("source") != "java-sast"]
    parts = []

    if sast:
        parts.append("### SAST findings (Java source code)\n")
        for i in sast:
            loc = f" `{i['location']}`" if i.get("location") else ""
            fix_summary, fix_code = snyk_sast_fix(i.get("id", ""))
            parts.append(
                f"{SEV_ICON.get(i['severity'],'⚪')} **[{i['severity'].upper()}]** "
                f"`{i['id']}` —{loc} {i['title']}\n\n"
                f"> 💡 **Fix:** {fix_summary}\n\n"
                f"{fix_code}\n"
            )

    if deps:
        parts.append("### Dependency CVEs\n")
        seen_pkg = set()
        for i in deps:
            pkg = i.get("location", "")
            loc = f" `{pkg}`" if pkg else ""
            pkg_key = pkg.split("@")[0] if pkg else i.get("id", "")
            fix_summary, fix_code = snyk_dep_fix(pkg)
            parts.append(
                f"{SEV_ICON.get(i['severity'],'⚪')} **[{i['severity'].upper()}]** "
                f"`{i['id']}` —{loc} {i['title']}\n"
            )
            if pkg_key not in seen_pkg:
                seen_pkg.add(pkg_key)
                parts.append(f"> 💡 **Fix:** {fix_summary}\n\n{fix_code}\n")

    snyk_rows = "\n".join(parts)
else:
    snyk_rows = "✅ No issues found."

# ── Dispatcher findings block ─────────────────────────────────────────────────

disp_findings = disp.get("findings", [])
if disp_findings:
    disp_parts = []
    seen_rules = set()
    for f in disp_findings:
        rule = f.get("rule", "")
        loc  = f":{f['line']}" if f.get("line") else ""
        fix_summary, fix_code = disp_fix(rule)
        disp_parts.append(
            f"{DISP_ICON.get(f['severity'],'⚪')} **[{f['severity']}]** "
            f"`{rule}` `{f['file']}`{loc} — **{f['title']}**\n\n"
            f"> ℹ️ {f.get('details','')}\n\n"
            f"> 💡 **Fix:** {fix_summary}\n\n"
            + (fix_code if rule not in seen_rules else "> *(fix snippet shown above for this rule)*")
            + "\n"
        )
        seen_rules.add(rule)
    disp_rows = "\n---\n".join(disp_parts)
else:
    disp_rows = "✅ No issues found."

# ── Assemble comment body ─────────────────────────────────────────────────────

body = textwrap.dedent(f"""\
## 🤖 PR Review Agent

{agent_summary}

| Check | Status | Details |
|---|---|---|
| 🔍 SonarCloud | {sonar_badge} | {sonar_detail} |
| 🔒 Snyk | {snyk_badge} | {snyk_detail} |
| ⚙️ Dispatcher Rules | {disp_badge} | {disp_detail} |

<details><summary>🔒 Snyk Findings &amp; Fix Recommendations</summary>

{snyk_rows}
</details>

<details><summary>⚙️ Dispatcher Findings &amp; Fix Recommendations</summary>

{disp_rows}
</details>

{MARKER}""")

# ── Upsert ────────────────────────────────────────────────────────────────────

if not PR:
    print("No PR number — skipping comment.")
    sys.exit(0)

comments = gh("GET", f"/repos/{REPO}/issues/{PR}/comments?per_page=100")
existing = next(
    (c for c in (comments if isinstance(comments, list) else []) if MARKER in c.get("body", "")),
    None,
)

if existing:
    print(f"Updating existing comment {existing['id']}")
    gh("PATCH", f"/repos/{REPO}/issues/comments/{existing['id']}", {"body": body})
else:
    print("Creating new comment")
    gh("POST", f"/repos/{REPO}/issues/{PR}/comments", {"body": body})

print("Done.")
