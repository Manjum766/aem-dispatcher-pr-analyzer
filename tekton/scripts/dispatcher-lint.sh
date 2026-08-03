#!/usr/bin/env bash
# dispatcher-lint.sh
#
# Statically analyses AEM Dispatcher configuration files for known security
# anti-patterns. Writes findings to ${OUTPUT_FILE} as JSON and exits 0 always
# so the Tekton Task step never aborts the pipeline.
#
# Environment variables (all optional — defaults shown):
#   DISPATCHER_DIR   Root of the dispatcher source tree  (default: dispatcher/src)
#   OUTPUT_FILE      Path to write the JSON result file  (default: /tmp/dispatcher-result.json)

set -euo pipefail

DISPATCHER_DIR="${DISPATCHER_DIR:-dispatcher/src}"
OUTPUT_FILE="${OUTPUT_FILE:-/tmp/dispatcher-result.json}"

# ── Helpers ──────────────────────────────────────────────────────────────────

# Findings are stored as newline-delimited JSON objects in a temp file;
# assembled into an array by jq at the end. This avoids shell quoting issues.
FINDINGS_TMP=$(mktemp)
trap 'rm -f "$FINDINGS_TMP"' EXIT

add_finding() {
  local FILE="$1"
  local LINE="$2"
  local SEVERITY="$3"
  local RULE="$4"
  local MESSAGE="$5"
  # Use jq to safely produce the JSON object (handles special chars in path/message)
  jq -cn \
    --arg file "$FILE" \
    --arg line "$LINE" \
    --arg severity "$SEVERITY" \
    --arg rule "$RULE" \
    --arg message "$MESSAGE" \
    '{file:$file, line:($line|tonumber), severity:$severity, rule:$rule, message:$message}' \
    >> "$FINDINGS_TMP"
}

# ── DISP-001 — allow-all pattern (/glob "*" + /type "allow" in same file) ────
check_disp001() {
  local FILE="$1"
  local TEXT
  TEXT=$(cat "$FILE")
  if echo "$TEXT" | grep -q '/glob "\*"' && echo "$TEXT" | grep -q '/type "allow"'; then
    # Find the line number of the first glob "*" + type "allow" occurrence
    local LINENO
    LINENO=$(grep -n '/glob "\*"' "$FILE" | head -1 | cut -d: -f1)
    add_finding "$FILE" "${LINENO:-0}" "CRITICAL" "DISP-001" \
      'Allow-all pattern: /glob \"*\" combined with /type \"allow\" exposes unintended paths'
  fi
}

# ── DISP-002 — first rule in filter file is not deny ─────────────────────────
check_disp002() {
  local FILE="$1"
  # Find the first /type directive in the file
  local FIRST_TYPE
  FIRST_TYPE=$(grep -m1 '/type' "$FILE" | grep -o '"[^"]*"' | tr -d '"')
  if [ -n "$FIRST_TYPE" ] && [ "$FIRST_TYPE" != "deny" ]; then
    local LINENO
    LINENO=$(grep -n '/type' "$FILE" | head -1 | cut -d: -f1)
    add_finding "$FILE" "${LINENO:-0}" "HIGH" "DISP-002" \
      'First filter rule is not /type \"deny\" — deny-first policy is not enforced'
  fi
}

# ── DISP-003 — /crx/* or /system/* allowed ───────────────────────────────────
check_disp003() {
  local FILE="$1"
  while IFS= read -r LINENO_CONTENT; do
    local LINENO
    LINENO=$(echo "$LINENO_CONTENT" | cut -d: -f1)
    local CONTENT
    CONTENT=$(echo "$LINENO_CONTENT" | cut -d: -f2-)
    # Check if the block containing this url also has type "allow"
    # We look for lines matching /url "/crx/ or /system/ and scan nearby lines
    if echo "$CONTENT" | grep -qE '/url "\/(crx|system)'; then
      local BLOCK
      BLOCK=$(awk "NR>=${LINENO} && NR<=$((LINENO+5))" "$FILE")
      if echo "$BLOCK" | grep -q '/type "allow"'; then
        add_finding "$FILE" "$LINENO" "CRITICAL" "DISP-003" \
          "Sensitive path allowed: /crx/* or /system/* is accessible via dispatcher"
      fi
    fi
  done < <(grep -n '/url' "$FILE" 2>/dev/null || true)
}

# ── DISP-004 — /bin/* allowed without a specific deny below ──────────────────
check_disp004() {
  local FILE="$1"
  while IFS= read -r LINENO_CONTENT; do
    local LINENO
    LINENO=$(echo "$LINENO_CONTENT" | cut -d: -f1)
    local CONTENT
    CONTENT=$(echo "$LINENO_CONTENT" | cut -d: -f2-)
    if echo "$CONTENT" | grep -qE '/url "/bin/'; then
      local BLOCK
      BLOCK=$(awk "NR>=${LINENO} && NR<=$((LINENO+5))" "$FILE")
      if echo "$BLOCK" | grep -q '/type "allow"'; then
        # Check if a deny rule for /bin appears after this line
        local DENY_AFTER
        DENY_AFTER=$(awk "NR>${LINENO}" "$FILE" | grep -c '/bin.*deny\|deny.*bin' || true)
        if [ "${DENY_AFTER:-0}" -eq 0 ]; then
          add_finding "$FILE" "$LINENO" "HIGH" "DISP-004" \
            '/bin/* is allowed without a more specific deny rule below it'
        fi
      fi
    fi
  done < <(grep -n '/url' "$FILE" 2>/dev/null || true)
}

# ── DISP-005 — cache rules: /glob "*" /type "allow" with no deny override ────
check_disp005() {
  local FILE="$1"
  local TEXT
  TEXT=$(cat "$FILE")
  if echo "$TEXT" | grep -q '/glob "\*"' && echo "$TEXT" | grep -q '/type "allow"'; then
    local DENY_COUNT
    DENY_COUNT=$(grep -c '/type "deny"' "$FILE" 2>/dev/null | tr -d ' \n\t' || echo 0)
    DENY_COUNT=$(( DENY_COUNT + 0 ))
    if [ "${DENY_COUNT}" -eq 0 ]; then
      local LINENO
      LINENO=$(grep -n '/glob "\*"' "$FILE" | head -1 | cut -d: -f1)
      add_finding "$FILE" "${LINENO:-0}" "MEDIUM" "DISP-005" \
        'Cache rules file has /glob "*" /type "allow" as only rule with no deny overrides — entire cache is open'
    fi
  fi
}

# ── DISP-006 — VHost missing Content-Security-Policy header ──────────────────
check_disp006() {
  local FILE="$1"
  if ! grep -qi 'Content-Security-Policy' "$FILE"; then
    add_finding "$FILE" "0" "MEDIUM" "DISP-006" \
      'VHost file is missing "Header always set Content-Security-Policy" directive'
  fi
}

# ── DISP-007 — VHost missing X-Frame-Options header ──────────────────────────
check_disp007() {
  local FILE="$1"
  if ! grep -qi 'X-Frame-Options' "$FILE"; then
    add_finding "$FILE" "0" "MEDIUM" "DISP-007" \
      'VHost file is missing X-Frame-Options header directive'
  fi
}

# ── DISP-008 — /allowAuthorized "1" in farm config ───────────────────────────
check_disp008() {
  local FILE="$1"
  local LINENO
  LINENO=$(grep -n '/allowAuthorized "1"' "$FILE" 2>/dev/null | head -1 | cut -d: -f1 || true)
  if [ -n "$LINENO" ]; then
    add_finding "$FILE" "$LINENO" "HIGH" "DISP-008" \
      '/allowAuthorized "1" detected — dispatcher will cache authenticated content, risking data leakage'
  fi
}

# ── Run checks ────────────────────────────────────────────────────────────────

echo "=== Dispatcher Lint ==="
echo "Scanning: ${DISPATCHER_DIR}"

FILTERS_DIR="${DISPATCHER_DIR}/conf.dispatcher.d/filters"
CACHE_DIR="${DISPATCHER_DIR}/conf.dispatcher.d/cache"
VHOSTS_DIR="${DISPATCHER_DIR}/conf.d/available_vhosts"

# Filter files (.any)
if [ -d "$FILTERS_DIR" ]; then
  while IFS= read -r -d '' FILE; do
    echo "  filter: $FILE"
    check_disp001 "$FILE"
    check_disp002 "$FILE"
    check_disp003 "$FILE"
    check_disp004 "$FILE"
  done < <(find "$FILTERS_DIR" -name "*.any" -print0 2>/dev/null)
else
  echo "  [skip] filters dir not found: ${FILTERS_DIR}"
fi

# Cache files (.any) — also scan conf.dispatcher/ as fallback for flat layout
CACHE_DIRS="${CACHE_DIR} ${DISPATCHER_DIR}/conf.dispatcher"
for DIR in $CACHE_DIRS; do
  if [ -d "$DIR" ]; then
    while IFS= read -r -d '' FILE; do
      echo "  cache: $FILE"
      check_disp005 "$FILE"
    done < <(find "$DIR" -name "*.any" -print0 2>/dev/null)
  fi
done

# VHost files (.vhost)
if [ -d "$VHOSTS_DIR" ]; then
  while IFS= read -r -d '' FILE; do
    echo "  vhost: $FILE"
    check_disp006 "$FILE"
    check_disp007 "$FILE"
  done < <(find "$VHOSTS_DIR" -name "*.vhost" -print0 2>/dev/null)
else
  echo "  [skip] vhosts dir not found: ${VHOSTS_DIR}"
fi

# Farm files (.farm)
FARM_DIRS="${DISPATCHER_DIR}/conf.dispatcher.d/enabled_farms ${DISPATCHER_DIR}/conf.dispatcher.d/available_farms"
for DIR in $FARM_DIRS; do
  if [ -d "$DIR" ]; then
    while IFS= read -r -d '' FILE; do
      echo "  farm: $FILE"
      check_disp008 "$FILE"
    done < <(find "$DIR" -name "*.farm" -print0 2>/dev/null)
  fi
done

# Assemble FINDINGS JSON array from the temp file
FINDINGS_JSON=$(jq -sc '.' "$FINDINGS_TMP")

# Determine counts
FINDING_COUNT=$(echo "$FINDINGS_JSON" | jq 'length')
CRITICAL_COUNT=$(echo "$FINDINGS_JSON" | jq '[.[] | select(.severity=="CRITICAL")] | length')
HIGH_COUNT=$(echo "$FINDINGS_JSON" | jq '[.[] | select(.severity=="HIGH")] | length')

if [ "$CRITICAL_COUNT" -gt 0 ] || [ "$HIGH_COUNT" -gt 0 ]; then
  STATUS="failed"
elif [ "$FINDING_COUNT" -gt 0 ]; then
  STATUS="warnings"
else
  STATUS="passed"
fi

# Write result JSON
jq -n \
  --arg status "$STATUS" \
  --argjson total "$FINDING_COUNT" \
  --argjson critical "$CRITICAL_COUNT" \
  --argjson high "$HIGH_COUNT" \
  --argjson findings "$FINDINGS_JSON" \
  '{status:$status, total_findings:$total, critical:$critical, high:$high, findings:$findings}' \
  > "${OUTPUT_FILE}"

echo ""
echo "=== Dispatcher Lint Result ==="
echo "Status: ${STATUS}  Findings: ${FINDING_COUNT}  (critical=${CRITICAL_COUNT} high=${HIGH_COUNT})"
echo "Written to: ${OUTPUT_FILE}"

# Always exit 0 — findings are reported, not blocking
exit 0
