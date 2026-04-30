#!/usr/bin/env bash
set -e

echo "=== Security Gate Starting ==="

# Folder containing scanner outputs
SCAN_DIR="$1"

if [ -z "$SCAN_DIR" ]; then
  echo "Usage: security-gate.sh <scan-output-directory>"
  exit 1
fi

# Arrays to store findings
DEVSECOPS_FINDINGS=()
APPSEC_FINDINGS=()

BLOCK=false

# Helper: read JSON safely
parse_json() {
  jq -c '.[]' "$1" 2>/dev/null || true
}

# Loop through all JSON files
for file in "$SCAN_DIR"/*.json; do
  scanner=$(basename "$file" | cut -d'-' -f1)

  echo "Processing $file (scanner: $scanner)"

  # Extract each finding
  while IFS= read -r finding; do
    severity=$(echo "$finding" | jq -r '.severity')
    id=$(echo "$finding" | jq -r '.id')
    file_path=$(echo "$finding" | jq -r '.file')
    line=$(echo "$finding" | jq -r '.line')

    # Classify by owner
    if [[ "$scanner" == "secret" || "$scanner" == "image" || "$scanner" == "iac" ]]; then
      DEVSECOPS_FINDINGS+=("$severity|$scanner|$id|$file_path|$line")

      # DevSecOps CRITICAL = block
      if [[ "$severity" == "CRITICAL" ]]; then
        BLOCK=true
      fi

    elif [[ "$scanner" == "sast" ]]; then
      APPSEC_FINDINGS+=("$severity|$scanner|$id|$file_path|$line")

      # AppSec CRITICAL blocks only in prod
      if [[ "$severity" == "CRITICAL" && "$ENVIRONMENT" == "production" ]]; then
        BLOCK=true
      fi
    fi

  done < <(parse_json "$file")

done

echo "=== Building PR Comment ==="

COMMENT_FILE="security-gate-comment.md"

{
  echo "<!-- security-gate-comment -->"
  echo "## 🔐 Security Gate Summary"

  if $BLOCK; then
    echo "**❌ Merge Blocked** — CRITICAL findings detected."
  else
    echo "**✅ Merge Allowed** — No blocking findings."
  fi

  echo ""
  echo "### DevSecOps Findings (Blocking when CRITICAL)"
  echo "| Severity | Scanner | ID | File | Line |"
  echo "|---------|---------|----|------|------|"

  for f in "${DEVSECOPS_FINDINGS[@]}"; do
    IFS='|' read -r sev sc id fp ln <<< "$f"
    echo "| $sev | $sc-scan | $id | $fp | $ln |"
  done

  echo ""
  echo "### AppSec Findings (Non-blocking)"
  echo "| Severity | Scanner | ID | File | Line |"
  echo "|---------|---------|----|------|------|"

  for f in "${APPSEC_FINDINGS[@]}"; do
    IFS='|' read -r sev sc id fp ln <<< "$f"
    echo "| $sev | $sc-scan | $id | $fp | $ln |"
  done

} > "$COMMENT_FILE"

echo "=== Posting PR Comment ==="

# Post or update PR comment
gh pr comment "$PR_NUMBER" --body-file "$COMMENT_FILE" || true

echo "=== Security Gate Finished ==="

# Exit based on BLOCK flag
if $BLOCK; then
  exit 1
else
  exit 0
fi
