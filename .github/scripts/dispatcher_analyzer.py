"""
AEM Dispatcher PR Analyzer
Scans dispatcher configuration files for security anti-patterns.

Rules implemented:
  DISP-001  /glob "*" + /type "allow" — allow-all pattern              CRITICAL
  DISP-002  First rule in a filter file is not /type "deny"             HIGH
  DISP-003  /url "/crx/*" or /url "/system/*" is allowed               CRITICAL
  DISP-004  /url "/bin/*" allowed without a more specific deny below    HIGH
  DISP-005  Cache file has /glob "*" /type "allow" with no deny         MEDIUM
  DISP-006  VHost missing Content-Security-Policy header                MEDIUM
  DISP-007  VHost missing X-Frame-Options header                        MEDIUM
  DISP-008  /allowAuthorized "1" in farm config                         HIGH

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
    """Return 1-based line number of the first match, or 0."""
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


# ── per-rule checks ────────────────────────────────────────────────────────────

def check_filter_file(path: Path):
    text = path.read_text(errors="ignore")
    numbered = lines_of(path)

    # DISP-001 — allow-all pattern
    if '/glob "*"' in text and '/type "allow"' in text:
        lineno = first_lineno(path, '/glob "*"')
        add(
            "CRITICAL", "DISP-001",
            "Allow-all pattern detected",
            "A rule combining `/glob \"*\"` with `/type \"allow\"` exposes or caches unintended paths.",
            path, lineno,
        )

    # DISP-002 — first rule must be deny
    for _, line_text in numbered:
        m = re.search(r'/type\s+"(\w+)"', line_text)
        if m:
            if m.group(1) != "deny":
                lineno = first_lineno_re(path, r'/type\s+"')
                add(
                    "HIGH", "DISP-002",
                    "Deny-first policy not enforced",
                    "The first `/type` rule in a filter file should be `/type \"deny\"` to enforce an allow-list approach.",
                    path, lineno,
                )
            break  # only inspect the first /type occurrence

    # DISP-003 — /crx/* or /system/* allowed
    for no, line_text in numbered:
        if re.search(r'/url\s+"/(?:crx|system)/', line_text):
            # Scan the surrounding block (up to 5 lines ahead) for /type "allow"
            block = " ".join(t for _, t in numbered[no - 1: no + 4])
            if '/type "allow"' in block:
                add(
                    "CRITICAL", "DISP-003",
                    "Sensitive admin path accessible via dispatcher",
                    f"Rule at line {no} allows access to `/crx/*` or `/system/*`. These paths must never be exposed.",
                    path, no,
                )

    # DISP-004 — /bin/* allowed without a deny below
    for no, line_text in numbered:
        if re.search(r'/url\s+"/bin/', line_text):
            block = " ".join(t for _, t in numbered[no - 1: no + 4])
            if '/type "allow"' in block:
                # Check for any deny rule for /bin after this line
                remaining = " ".join(t for _, t in numbered[no:])
                if not re.search(r'/bin.*deny|deny.*bin', remaining):
                    add(
                        "HIGH", "DISP-004",
                        "/bin/* allowed without a specific deny below",
                        f"Rule at line {no} allows `/bin/*` but no more-specific deny rule follows it.",
                        path, no,
                    )


def check_cache_file(path: Path):
    text = path.read_text(errors="ignore")

    # DISP-005 — allow-all cache with no deny override
    if '/glob "*"' in text and '/type "allow"' in text:
        if '/type "deny"' not in text:
            lineno = first_lineno(path, '/glob "*"')
            add(
                "MEDIUM", "DISP-005",
                "Cache allow-all with no deny overrides",
                "The cache rules file contains `/glob \"*\" /type \"allow\"` as the only rule. "
                "Add deny overrides for sensitive paths.",
                path, lineno,
            )

    # DISP-001 also applies to cache files (allow-all pattern)
    if '/glob "*"' in text and '/type "allow"' in text:
        lineno = first_lineno(path, '/glob "*"')
        add(
            "CRITICAL", "DISP-001",
            "Allow-all pattern detected (cache file)",
            "A rule combining `/glob \"*\"` with `/type \"allow\"` in a cache file exposes unintended paths.",
            path, lineno,
        )

    # MEDIUM: all URL params cached (existing check kept)
    if "/ignoreUrlParams" in text and '/glob "*"' in text:
        lineno = first_lineno(path, "/ignoreUrlParams")
        add(
            "MEDIUM", "DISP-005b",
            "All query parameters considered for caching",
            "UTM, fbclid, gclid params may fragment the cache and reduce cache-hit ratio.",
            path, lineno,
        )


def check_vhost_file(path: Path):
    text = path.read_text(errors="ignore")

    # DISP-006 — missing CSP header
    if not re.search(r"Content-Security-Policy", text, re.IGNORECASE):
        add(
            "MEDIUM", "DISP-006",
            "Missing Content-Security-Policy header",
            "Add `Header always set Content-Security-Policy \"...\"` to this VHost file.",
            path, 0,
        )

    # DISP-007 — missing X-Frame-Options header
    if not re.search(r"X-Frame-Options", text, re.IGNORECASE):
        add(
            "MEDIUM", "DISP-007",
            "Missing X-Frame-Options header",
            "Add `Header always set X-Frame-Options SAMEORIGIN` to this VHost file.",
            path, 0,
        )

    # MEDIUM: GraphQL endpoint (existing check kept)
    if "/_cq_graphql" in text:
        add(
            "MEDIUM", "DISP-GQL",
            "GraphQL endpoint modified",
            "Verify caching, authorization, and persisted query behavior for `/_cq_graphql`.",
            path, first_lineno(path, "/_cq_graphql"),
        )


def check_farm_file(path: Path):
    # DISP-008 — caches authenticated content
    for no, line_text in lines_of(path):
        if '/allowAuthorized "1"' in line_text:
            add(
                "HIGH", "DISP-008",
                "Authenticated content may be cached",
                "`/allowAuthorized \"1\"` tells the dispatcher to cache responses for authenticated "
                "requests, risking data leakage between users.",
                path, no,
            )


# ── directory scan ─────────────────────────────────────────────────────────────

print(f"Scanning dispatcher directory: {DISPATCHER_DIR}")

filters_dir = DISPATCHER_DIR / "conf.dispatcher.d" / "filters"
cache_dirs = [
    DISPATCHER_DIR / "conf.dispatcher.d" / "cache",
    DISPATCHER_DIR / "conf.dispatcher",   # flat layout fallback (this repo)
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

print(f"\nFindings: {len(findings)}")

# ── risk score ─────────────────────────────────────────────────────────────────

SCORE_MAP = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 10, "LOW": 5}
score = min(sum(SCORE_MAP.get(f["severity"], 5) for f in findings), 100)

if score < 25:
    level = "LOW"
elif score < 50:
    level = "MEDIUM"
elif score < 75:
    level = "HIGH"
else:
    level = "CRITICAL"

# ── write dispatcher-result.json (consumed by the comment job) ─────────────────

result = {
    "status": "failed" if any(f["severity"] in ("CRITICAL", "HIGH") for f in findings) else (
        "warnings" if findings else "passed"
    ),
    "total_findings": len(findings),
    "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
    "high":     sum(1 for f in findings if f["severity"] == "HIGH"),
    "medium":   sum(1 for f in findings if f["severity"] == "MEDIUM"),
    "score":    score,
    "level":    level,
    "findings": findings,
}

Path("dispatcher-result.json").write_text(json.dumps(result, indent=2))
print("Wrote dispatcher-result.json")

# ── write dispatcher-report.md ─────────────────────────────────────────────────

ICONS = {"CRITICAL": "🔴", "HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡"}

report_lines = [f"## AEM Dispatcher/CDN Analysis — {level} ({score}/100)\n"]

if not findings:
    report_lines.append("No significant dispatcher risks detected. ✅")
else:
    for f in findings:
        icon = ICONS.get(f["severity"], "⚪")
        loc = f" (line {f['line']})" if f["line"] else ""
        report_lines.append(f"### {icon} [{f['rule']}] {f['title']}")
        report_lines.append(f"**File:** `{f['file']}`{loc}")
        report_lines.append(f"**Severity:** {f['severity']}")
        report_lines.append(f['details'])
        report_lines.append("")

    report_lines.append("---")
    report_lines.append(f"**Overall Risk Score:** {score}/100 ({level})")

content = "\n".join(report_lines)
Path("dispatcher-report.md").write_text(content)

print("\n===== REPORT =====\n")
print(content)
