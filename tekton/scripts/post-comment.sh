#!/usr/bin/env bash
# post-comment.sh
#
# Reads the three scan result JSON files, builds a Markdown PR comment, and
# upserts it on the GitHub pull request via the GitHub REST API.
# "Upsert" = find an existing comment containing the marker and PATCH it,
# or POST a new one if no marker comment exists.
#
# Required environment variables:
#   GITHUB_TOKEN   GitHub PAT with repo scope
#   REPO_OWNER     GitHub organisation or user name
#   REPO_NAME      GitHub repository name
#   PR_NUMBER      Pull request number
#   RESULTS_DIR    Directory containing sonar-result.json, snyk-result.json,
#                  dispatcher-result.json

set -euo pipefail

: "${GITHUB_TOKEN:?GITHUB_TOKEN is required}"
: "${REPO_OWNER:?REPO_OWNER is required}"
: "${REPO_NAME:?REPO_NAME is required}"
: "${PR_NUMBER:?PR_NUMBER is required}"
: "${RESULTS_DIR:?RESULTS_DIR is required}"

MARKER="<!-- pr-review-agent-marker -->"
API_BASE="https://api.github.com"
AUTH_HEADER="Authorization: token ${GITHUB_TOKEN}"
ACCEPT_HEADER="Accept: application/vnd.github+json"

# ── Helper: read a JSON file safely ──────────────────────────────────────────
read_result() {
  local FILE="$1"
  if [ -f "$FILE" ] && jq empty "$FILE" 2>/dev/null; then
    cat "$FILE"
  else
    echo '{"status":"did_not_complete"}'
  fi
}

# ── Load results ──────────────────────────────────────────────────────────────
SONAR=$(read_result "${RESULTS_DIR}/sonar-result.json")
SNYK=$(read_result "${RESULTS_DIR}/snyk-result.json")
DISP=$(read_result "${RESULTS_DIR}/dispatcher-result.json")

# ── Build per-pillar rows ─────────────────────────────────────────────────────

# SonarQube row
SONAR_STATUS=$(echo "$SONAR" | jq -r '.status // "did_not_complete"')
SONAR_BUGS=$(echo "$SONAR" | jq -r '.bugs // "?"')
SONAR_VULNS=$(echo "$SONAR" | jq -r '.vulnerabilities // "?"')
SONAR_SMELLS=$(echo "$SONAR" | jq -r '.code_smells // "?"')
SONAR_URL=$(echo "$SONAR" | jq -r '.dashboard_url // ""')

case "$SONAR_STATUS" in
  passed)   SONAR_BADGE="✅ Passed" ;;
  failed)   SONAR_BADGE="❌ Failed" ;;
  *)        SONAR_BADGE="⚠️ Scan did not complete" ;;
esac

if [ -n "$SONAR_URL" ] && [ "$SONAR_URL" != "null" ]; then
  SONAR_DETAIL="${SONAR_BUGS} bugs, ${SONAR_VULNS} vulns, ${SONAR_SMELLS} smells — [Dashboard](${SONAR_URL})"
else
  SONAR_DETAIL="${SONAR_BUGS} bugs, ${SONAR_VULNS} vulns, ${SONAR_SMELLS} smells"
fi

# Snyk row
SNYK_STATUS=$(echo "$SNYK" | jq -r '.status // "did_not_complete"')
SNYK_SECRETS=$(echo "$SNYK" | jq -r '.secrets_found // "?"')
SNYK_CRITICAL=$(echo "$SNYK" | jq -r '.critical_vulns // "?"')
SNYK_HIGH=$(echo "$SNYK" | jq -r '.high_vulns // "?"')

case "$SNYK_STATUS" in
  passed)   SNYK_BADGE="✅ Passed" ;;
  failed)   SNYK_BADGE="❌ Issues found" ;;
  *)        SNYK_BADGE="⚠️ Scan did not complete" ;;
esac

SNYK_DETAIL="${SNYK_CRITICAL} critical, ${SNYK_HIGH} high CVEs; ${SNYK_SECRETS} secrets found"

# Dispatcher row
DISP_STATUS=$(echo "$DISP" | jq -r '.status // "did_not_complete"')
DISP_TOTAL=$(echo "$DISP" | jq -r '.total_findings // "?"')
DISP_CRITICAL=$(echo "$DISP" | jq -r '.critical // "?"')
DISP_HIGH=$(echo "$DISP" | jq -r '.high // "?"')

case "$DISP_STATUS" in
  passed)   DISP_BADGE="✅ Clean" ;;
  warnings) DISP_BADGE="⚠️ Warnings" ;;
  failed)   DISP_BADGE="❌ Issues found" ;;
  *)        DISP_BADGE="⚠️ Scan did not complete" ;;
esac

DISP_DETAIL="${DISP_TOTAL} findings (critical=${DISP_CRITICAL} high=${DISP_HIGH})"

# ── Build Snyk details block ──────────────────────────────────────────────────
SNYK_ISSUES=$(echo "$SNYK" | jq -r '
  (.issues? // [])
  | if length == 0 then "No issues found."
    else map("- **[\(.severity | ascii_upcase)]** `\(.id)` — \(.title) (\(.source))")
       | join("\n")
    end
')

# ── Build Dispatcher details block ───────────────────────────────────────────
DISP_ISSUES=$(echo "$DISP" | jq -r '
  (.findings? // [])
  | if length == 0 then "No issues found."
    else map("- **\(.severity)** `\(.rule)` \(.file):\(.line) — \(.message)")
       | join("\n")
    end
')

# ── Assemble final comment ─────────────────────────────────────────────────────
COMMENT_BODY="## 🤖 PR Review Agent

| Check | Status | Details |
|---|---|---|
| 🔍 SonarQube | ${SONAR_BADGE} | ${SONAR_DETAIL} |
| 🔒 Snyk | ${SNYK_BADGE} | ${SNYK_DETAIL} |
| ⚙️ Dispatcher Rules | ${DISP_BADGE} | ${DISP_DETAIL} |

<details><summary>Snyk Findings</summary>

${SNYK_ISSUES}
</details>

<details><summary>Dispatcher Findings</summary>

${DISP_ISSUES}
</details>

${MARKER}"

# ── Upsert: find existing marker comment ─────────────────────────────────────
echo "Fetching existing PR comments..."

EXISTING_ID=$(curl -sf \
  -H "$AUTH_HEADER" \
  -H "$ACCEPT_HEADER" \
  "${API_BASE}/repos/${REPO_OWNER}/${REPO_NAME}/issues/${PR_NUMBER}/comments?per_page=100" \
  | jq -r --arg marker "$MARKER" \
      '[.[] | select(.body | contains($marker))] | first | .id // empty')

PAYLOAD=$(jq -n --arg body "$COMMENT_BODY" '{"body": $body}')

if [ -n "$EXISTING_ID" ] && [ "$EXISTING_ID" != "null" ]; then
  echo "Updating existing comment id=${EXISTING_ID}..."
  curl -sf -X PATCH \
    -H "$AUTH_HEADER" \
    -H "$ACCEPT_HEADER" \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD" \
    "${API_BASE}/repos/${REPO_OWNER}/${REPO_NAME}/issues/comments/${EXISTING_ID}" \
    > /dev/null
  echo "Comment updated."
else
  echo "Creating new comment..."
  curl -sf -X POST \
    -H "$AUTH_HEADER" \
    -H "$ACCEPT_HEADER" \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD" \
    "${API_BASE}/repos/${REPO_OWNER}/${REPO_NAME}/issues/${PR_NUMBER}/comments" \
    > /dev/null
  echo "Comment created."
fi
