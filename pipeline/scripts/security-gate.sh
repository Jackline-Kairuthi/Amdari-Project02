#!/usr/bin/env bash
set -e

echo "=== Security Gate Starting ==="

SCAN_DIR="$1"

if [ -z "$SCAN_DIR" ]; then
  echo "Usage: security-gate.sh <scan-output-directory>"
  exit 1
fi

if [ -z "$PR_NUMBER" ]; then
  echo "PR_NUMBER environment variable is required"
  exit 1
fi

echo "Scan directory: $SCAN_DIR"
echo "PR number: $PR_NUMBER"
echo "Environment: ${ENVIRONMENT:-unknown}"

# -------------------------------
# Exception handling
# -------------------------------
EXCEPTION_FILE=".security-exceptions/exception-${PR_NUMBER}.json"
BYPASS_EXCEPTION=false

if [ -f "$EXCEPTION_FILE" ]; then
  echo "Found exception file: $EXCEPTION_FILE"
  STATUS=$(jq -r '.status // "PENDING"' "$EXCEPTION_FILE")
  echo "Exception status: $STATUS"

  if [ "$STATUS" = "APPROVED" ]; then
    echo "⚠️ Security exception approved — bypassing DevSecOps CRITICAL findings"
    BYPASS_EXCEPTION=true
  fi
else
  echo "No exception file found for PR #$PR_NUMBER"
fi

# -------------------------------
# Data structures
# -------------------------------
DEVSECOPS_FINDINGS=()
APPSEC_FINDINGS=()
BLOCK=false
DEVSECOPS_CRITICAL_COUNT=0

# -------------------------------
# Safe JSON parser
# -------------------------------
safe_parse() {
  jq -c '
    if type=="array" then
      .[]
    elif type=="object" then
      .
    else
      empty
    end
  ' "$1" 2>/dev/null || true
}

# -------------------------------
# Process scan JSON files
# -------------------------------
for file in "$SCAN_DIR"/*.json; do
  [ -e "$file" ] || continue

  base=$(basename "$file")
  scanner="${base%%-*}"

  echo "Processing $file (scanner: $scanner)"

  while IFS= read -r finding; do
    severity=$(echo "$finding"   | jq -r '.severity // empty')
    id=$(echo "$finding"         | jq -r '.id // empty')
    file_path=$(echo "$finding"  | jq -r '.file // empty')
    line=$(echo "$finding"       | jq -r '.line // empty')

    [[ -z "$severity" ]] && continue

    if [[ "$scanner" == "secret" || "$scanner" == "image" || "$scanner" == "iac" ]]; then
      DEVSECOPS_FINDINGS+=("$severity|$scanner|$id|$file_path|$line")

      if [[ "$severity" == "CRITICAL" ]]; then
        DEVSECOPS_CRITICAL_COUNT=$((DEVSECOPS_CRITICAL_COUNT + 1))
        BLOCK=true
      fi

    elif [[ "$scanner" == "sast" ]]; then
      APPSEC_FINDINGS+=("$severity|$scanner|$id|$file_path|$line")

      if [[ "$severity" == "CRITICAL" && "$ENVIRONMENT" == "production" ]]; then
        BLOCK=true
      fi
    fi

  done < <(safe_parse "$file")

done

echo "DevSecOps CRITICAL count: $DEVSECOPS_CRITICAL_COUNT"
echo "BYPASS_EXCEPTION: $BYPASS_EXCEPTION"
echo "BLOCK (raw): $BLOCK"

# -------------------------------
# Build PR comment
# -------------------------------
COMMENT_FILE="security-gate-comment.md"

{
  echo "<!-- security-gate-comment -->"
  echo "## 🔐 Security Gate Summary"
  echo ""

  if [ "$DEVSECOPS_CRITICAL_COUNT" -gt 0 ] && [ "$BYPASS_EXCEPTION" != "true" ]; then
    echo "**❌ Merge Blocked** — CRITICAL DevSecOps findings detected (no approved exception)."
  elif [ "$DEVSECOPS_CRITICAL_COUNT" -gt 0 ] && [ "$BYPASS_EXCEPTION" = "true" ]; then
    echo "**⚠️ Merge Allowed with Exception** — CRITICAL DevSecOps findings bypassed due to approved security exception."
  elif $BLOCK; then
    echo "**❌ Merge Blocked** — Blocking findings detected."
  else
    echo "**✅ Merge Allowed** — No blocking DevSecOps findings."
  fi

  echo ""
  echo "## 🛡️ DevSecOps-Owned Findings"
  echo "| Severity | Scanner | ID | File | Line |"
  echo "|---------|---------|----|------|------|"

  if [ ${#DEVSECOPS_FINDINGS[@]} -eq 0 ]; then
    echo "| None | - | - | - | - |"
  else
    for f in "${DEVSECOPS_FINDINGS[@]}"; do
      IFS='|' read -r sev sc id fp ln <<< "$f"
      echo "| $sev | $sc-scan | $id | $fp | $ln |"
    done
  fi

  echo ""
  echo "## 🧩 AppSec-Owned Findings"
  echo "Non-blocking — escalate to AppSec via:"
  echo "**https://your-company-appsec-intake-form.example.com**"
  echo ""
  echo "| Severity | Scanner | ID | File | Line |"
  echo "|---------|---------|----|------|------|"

  if [ ${#APPSEC_FINDINGS[@]} -eq 0 ]; then
    echo "| None | - | - | - | - |"
  else
    for f in "${APPSEC_FINDINGS[@]}"; do
      IFS='|' read -r sev sc id fp ln <<< "$f"
      echo "| $sev | $sc-scan | $id | $fp | $ln |"
    done
  fi

} > "$COMMENT_FILE"

echo "Posting PR comment..."
gh pr comment "$PR_NUMBER" --body-file "$COMMENT_FILE" || true

# -------------------------------
# Final gate decision
# -------------------------------
echo "=== Evaluating Final Gate Decision ==="

if [ "$DEVSECOPS_CRITICAL_COUNT" -gt 0 ] && [ "$BYPASS_EXCEPTION" != "true" ]; then
  echo "❌ Blocking merge due to CRITICAL DevSecOps findings (no approved exception)"
  exit 1
fi

if [ "$DEVSECOPS_CRITICAL_COUNT" -gt 0 ] && [ "$BYPASS_EXCEPTION" = "true" ]; then
  echo "⚠️ CRITICAL DevSecOps findings bypassed due to approved exception"
  exit 0
fi

if $BLOCK; then
  echo "❌ Blocking merge due to blocking findings"
  exit 1
fi

echo "✅ No blocking findings — merge allowed"
exit 0
