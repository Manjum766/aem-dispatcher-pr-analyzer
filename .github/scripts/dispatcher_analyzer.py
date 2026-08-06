"""
AEM Dispatcher PR Analyzer
Scans dispatcher configuration files for security anti-patterns.

Rules implemented:
  DISP-001  /glob "*" /type "allow" — allow-all in a filter file           CRITICAL
  DISP-002  First rule in a filter file is not /type "deny"                 HIGH
  DISP-003  /url "/crx/*" or /url "/system/*" is allowed in filter         CRITICAL
  DISP-004  /url "/bin/*" allowed without a more specific deny below        HIGH
  DISP-005  Cache file has /glob "*" /type "allow" with no deny override    CRITICAL
  DISP-005b All query parameters considered for caching (ignoreUrlParams)   MEDIUM
  DISP-006  VHost missing Content-Security-Policy header                    MEDIUM
  DISP-007  VHost missing X-Frame-Options header                            MEDIUM
  DISP-008  /allowAuthorized "1" in cache or farm config                    HIGH
  DISP-009  Sensitive path (/crx/*, /system/*, /bin/*) cached               CRITICAL
  DISP-010  /libs/* or /conf/* served/cached without deny override          HIGH

Writes dispatcher-report.md and dispatcher-result.json to the working directory.
"""

import json
import re
import sys
from pathlib import Path

DISPATCHER_DIR = Path("dispatcher/src")

findings = []


def add(severity, rule, title, details, file_path, line=0):
    findings.append(
        {
            "severity": severity,
            "rule": rule,
            "title": title,
            "details": details,
            "file": str(file_path),
            "line": line,
        }
    )


# ── helpers ────────────────────────────────────────────────────────────────────

def lines_of(path: Path):
    """Return list of (lineno, text) tuples (1-based)."""
    try:
        return list(enumerate(path.read_text(errors="ignore").splitlines(), start=1))
    except OSError:
        return []


def first_lineno(path: Path, pattern: str) -> int:
    """Return 1-based line number of the first literal match, or 0."""
    for no, text in lines_of(path):
        if pattern in text:
            return no
    return 0


def first_lineno_re(path: Path, pattern: str) -> int:
    rx = re.compile(pattern)
    for no, text in lines_of(path):
        if rx.search(text):
            return no
    return 0


def glob_allow_lines(numbered):
    """Yield (lineno, glob_value) for every inline /glob … /type "allow" rule."""
    for no, text in numbered:
        m = re.search(r'/glob\s+"([^"]+)"', text)
        if m and '/type "allow"' in text:
            yield no, m.group(1)


# ── per-rule checks ────────────────────────────────────────────────────────────

def check_filter_file(path: Path):
    text = path.read_text(errors="ignore")
    numbered = lines_of(path)

    # DISP-001 — allow-all glob in filter
    if '/glob "*"' in text and '/type "allow"' in text:
        lineno = first_lineno(path, '/glob "*"')
        add(
            "CRITICAL", "DISP-001",
            "Allow-all glob pattern in filter",
            'A rule combining `/glob "*"` with `/type "allow"` exposes every URL through '
            "the dispatcher. Remove it and explicitly allow only required paths.",
            path, lineno,
        )

    # DISP-002 — first /type must be deny
    for _, line_text in numbered:
        m = re.search(r'/type\s+"(\w+)"', line_text)
        if m:
            if m.group(1) != "deny":
                lineno = first_lineno_re(path, r'/type\s+"')
                add(
                    "HIGH", "DISP-002",
                    "Deny-first policy not enforced",
                    'The first `/type` rule in a filter file must be `/type "deny"` to enforce '
                    "an allow-list approach. Any path not explicitly allowed will be blocked.",
                    path, lineno,
                )
            break

    # DISP-003 — /crx/* or /system/* explicitly allowed in filter
    for no, line_text in numbered:
        if re.search(r'/url\s+"/(?:crx|system)/', line_text):
            block = " ".join(t for _, t in numbered[no - 1: no + 4])
            if '/type "allow"' in block:
                add(
                    "CRITICAL", "DISP-003",
                    "Sensitive admin path accessible via dispatcher",
                    f"Line {no}: a filter rule explicitly allows `/crx/*` or `/system/*`. "
                    "These AEM admin paths must never be reachable through the dispatcher.",
                    path, no,
                )

    # DISP-004 — /bin/* allowed with no deny below
    for no, line_text in numbered:
        if re.search(r'/url\s+"/bin/', line_text):
            block = " ".join(t for _, t in numbered[no - 1: no + 4])
            if '/type "allow"' in block:
                remaining = " ".join(t for _, t in numbered[no:])
                if not re.search(r'/bin.*deny|deny.*bin', remaining):
                    add(
                        "HIGH", "DISP-004",
                        "/bin/* allowed without a specific deny below",
                        f"Line {no}: `/bin/*` is allowed but no more-specific deny rule follows. "
                        "Add a deny rule for sensitive servlets under `/bin/`.",
                        path, no,
                    )


def check_cache_file(path: Path):
    text = path.read_text(errors="ignore")
    numbered = lines_of(path)

    # DISP-008 — /allowAuthorized in cache file (same rule as farm, applies here too)
    for no, line_text in numbered:
        if '/allowAuthorized "1"' in line_text:
            add(
                "HIGH", "DISP-008",
                "Authenticated content may be cached",
                '`/allowAuthorized "1"` instructs the dispatcher to cache responses for '
                "authenticated requests. This risks serving one user's private content to another.",
                path, no,
            )

    # DISP-005 — allow-all glob in cache rules with no deny override
    has_allow_all = '/glob "*"' in text and '/type "allow"' in text
    has_deny = '/type "deny"' in text
    if has_allow_all and not has_deny:
        lineno = first_lineno(path, '/glob "*"')
        add(
            "CRITICAL", "DISP-005",
            "Cache allow-all with no deny overrides",
            'The cache rules contain `/glob "*" /type "allow"` as the only rule — every URL '
            "including admin paths will be cached. Add explicit deny overrides for "
            "`/crx/*`, `/system/*`, `/bin/*`, `/libs/*`, and `/conf/*`.",
            path, lineno,
        )

    # DISP-009 — sensitive paths explicitly cached
    SENSITIVE = {
        "crx":    ("CRITICAL", "DISP-009", "/crx/* cached — AEM repository browser exposed",
                   "Caching `/crx/*` allows unauthenticated access to the CRX repository browser "
                   "and package manager. Remove this rule entirely."),
        "system": ("CRITICAL", "DISP-009", "/system/* cached — AEM system console exposed",
                   "Caching `/system/*` exposes the Felix OSGi console and health-check endpoints. "
                   "Remove this rule entirely."),
        "bin":    ("HIGH",     "DISP-009", "/bin/* cached — Sling servlet endpoints cached",
                   "Caching `/bin/*` exposes all Sling servlet endpoints. Add a specific deny "
                   "rule or remove this allow rule."),
    }

    for no, glob_val in glob_allow_lines(numbered):
        for key, (sev, rule, title, details) in SENSITIVE.items():
            if re.match(rf"/{key}/", glob_val) or glob_val == f"/{key}/*":
                add(sev, rule, title,
                    f"Line {no}: `{glob_val}` — {details}",
                    path, no)

    # DISP-010 — /libs/* or /conf/* cached (AEM internal paths)
    for no, glob_val in glob_allow_lines(numbered):
        if re.match(r"/libs/", glob_val) or re.match(r"/conf/", glob_val):
            add(
                "HIGH", "DISP-010",
                f"{glob_val} cached — AEM internal path exposed",
                f"Line {no}: `{glob_val}` is cached. `/libs/*` and `/conf/*` contain AEM "
                "framework files and OSGi configurations that should not be publicly cached.",
                path, no,
            )

    # DISP-005b — all URL params used as cache keys
    # Only fire when /glob "*" /type "allow" appears inside the ignoreUrlParams block.
    if "/ignoreUrlParams" in text:
        # Extract just the ignoreUrlParams block content
        block_start = text.find("/ignoreUrlParams")
        brace_open  = text.find("{", block_start)
        brace_close = text.find("}", brace_open)
        block_text  = text[brace_open:brace_close] if brace_open != -1 and brace_close != -1 else ""
        if '/glob "*"' in block_text and '/type "allow"' in block_text:
            lineno = first_lineno(path, "/ignoreUrlParams")
            add(
                "MEDIUM", "DISP-005b",
                "All query parameters used as cache keys",
                "The `ignoreUrlParams` block contains `/glob \"*\" /type \"allow\"`, meaning every "
                "query parameter is included in the cache key. UTM/tracking params will fragment "
                "the cache and reduce hit rate. Explicitly ignore known tracking params.",
                path, lineno,
            )


def check_vhost_file(path: Path):
    text = path.read_text(errors="ignore")

    # DISP-006 — missing CSP header
    if not re.search(r"Content-Security-Policy", text, re.IGNORECASE):
        add(
            "MEDIUM", "DISP-006",
            "Missing Content-Security-Policy header",
            'Add `Header always set Content-Security-Policy "default-src \'self\'"` '
            "(or a suitable policy) to this VHost to prevent XSS and content injection.",
            path, 0,
        )

    # DISP-007 — missing X-Frame-Options header
    if not re.search(r"X-Frame-Options", text, re.IGNORECASE):
        add(
            "MEDIUM", "DISP-007",
            "Missing X-Frame-Options header",
            "Add `Header always set X-Frame-Options SAMEORIGIN` to prevent clickjacking attacks.",
            path, 0,
        )

    # GraphQL endpoint exposed
    if "/_cq_graphql" in text:
        add(
            "MEDIUM", "DISP-GQL",
            "GraphQL endpoint exposed via VHost",
            "Verify caching rules, authorization checks, and whether only persisted queries "
            "are allowed for `/_cq_graphql`.",
            path, first_lineno(path, "/_cq_graphql"),
        )


def check_farm_file(path: Path):
    # DISP-008 — caches authenticated content
    for no, line_text in lines_of(path):
        if '/allowAuthorized "1"' in line_text:
            add(
                "HIGH", "DISP-008",
                "Authenticated content may be cached",
                '`/allowAuthorized "1"` tells the dispatcher to cache responses for authenticated '
                "requests, risking data leakage between users.",
                path, no,
            )


# ── directory scan ─────────────────────────────────────────────────────────────

print(f"Scanning dispatcher directory: {DISPATCHER_DIR}")

filters_dir = DISPATCHER_DIR / "conf.dispatcher.d" / "filters"
cache_dirs = [
    DISPATCHER_DIR / "conf.dispatcher.d" / "cache",
    DISPATCHER_DIR / "conf.dispatcher",   # flat layout (this repo)
]
vhosts_dir = DISPATCHER_DIR / "conf.d" / "available_vhosts"
farm_dirs = [
    DISPATCHER_DIR / "conf.dispatcher.d" / "enabled_farms",
    DISPATCHER_DIR / "conf.dispatcher.d" / "available_farms",
]

if filters_dir.is_dir():
    for f in sorted(filters_dir.rglob("*.any")):
        print(f"  filter: {f}")
        check_filter_file(f)
else:
    print(f"  [skip] filters dir not found: {filters_dir}")

for d in cache_dirs:
    if d.is_dir():
        for f in sorted(d.rglob("*.any")):
            print(f"  cache:  {f}")
            check_cache_file(f)

if vhosts_dir.is_dir():
    for f in sorted(vhosts_dir.rglob("*.vhost")):
        print(f"  vhost:  {f}")
        check_vhost_file(f)
else:
    print(f"  [skip] vhosts dir not found: {vhosts_dir}")

for d in farm_dirs:
    if d.is_dir():
        for f in sorted(d.rglob("*.farm")):
            print(f"  farm:   {f}")
            check_farm_file(f)

print(f"\nTotal findings: {len(findings)}")

# ── emit GitHub Actions inline annotations ─────────────────────────────────────
# These appear as inline review comments on the PR diff in GitHub.

ANNOTATION_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "notice"}

for f in findings:
    level = ANNOTATION_LEVEL.get(f["severity"], "notice")
    loc   = f",line={f['line']}" if f["line"] else ""
    print(f"::{level} file={f['file']}{loc}::[{f['rule']}] {f['title']} — {f['details']}")

# ── risk score ─────────────────────────────────────────────────────────────────

SCORE_MAP = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 10, "LOW": 5}
raw_score = sum(SCORE_MAP.get(f["severity"], 5) for f in findings)
score = min(raw_score, 100)

if score == 0:
    level = "CLEAN"
elif score < 25:
    level = "LOW"
elif score < 50:
    level = "MEDIUM"
elif score < 75:
    level = "HIGH"
else:
    level = "CRITICAL"

# ── write dispatcher-result.json ───────────────────────────────────────────────

result = {
    "status": "failed" if any(f["severity"] in ("CRITICAL", "HIGH") for f in findings) else (
        "warnings" if findings else "passed"
    ),
    "total_findings": len(findings),
    "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
    "high":     sum(1 for f in findings if f["severity"] == "HIGH"),
    "medium":   sum(1 for f in findings if f["severity"] == "MEDIUM"),
    "low":      sum(1 for f in findings if f["severity"] == "LOW"),
    "score":    score,
    "level":    level,
    "findings": findings,
}

Path("dispatcher-result.json").write_text(json.dumps(result, indent=2))
print("Wrote dispatcher-result.json")

# ── write dispatcher-report.md ─────────────────────────────────────────────────

ICONS = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}

report_lines = [
    f"## AEM Dispatcher Security Analysis — {level} (score: {score}/100)\n",
    f"| Severity | Count |",
    f"|---|---|",
    f"| 🔴 Critical | {result['critical']} |",
    f"| 🟠 High     | {result['high']} |",
    f"| 🟡 Medium   | {result['medium']} |",
    f"| 🔵 Low      | {result['low']} |",
    "",
]

if not findings:
    report_lines.append("✅ No dispatcher security issues detected.")
else:
    for f in findings:
        icon = ICONS.get(f["severity"], "⚪")
        loc  = f" — line {f['line']}" if f["line"] else ""
        report_lines.append(f"### {icon} `{f['rule']}` · {f['title']}")
        report_lines.append(f"> **Severity:** {f['severity']}  ")
        report_lines.append(f"> **File:** `{f['file']}`{loc}  ")
        report_lines.append(f"> {f['details']}")
        report_lines.append("")

    report_lines.append("---")
    report_lines.append(
        f"**Overall Risk Score:** {score}/100 ({level})  \n"
        f"Fix all CRITICAL and HIGH issues before merging."
    )

content = "\n".join(report_lines)
Path("dispatcher-report.md").write_text(content)

print("\n===== DISPATCHER REPORT =====\n")
print(content)

# ── exit non-zero so the CI job fails on CRITICAL/HIGH ─────────────────────────
if result["status"] == "failed":
    print(
        f"\n::error::Dispatcher scan FAILED — "
        f"{result['critical']} critical, {result['high']} high findings. Merge is blocked."
    )
    sys.exit(1)
