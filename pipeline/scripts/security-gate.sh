#!/usr/bin/env bash
set -e

echo "=== Security Gate Starting ==="

SCAN_DIR="$1"

if [ -z "$SCAN_DIR" ]; then
  echo "Usage: security-gate.sh <scan-output-directory>"
  exit 1
fi

DEVSECOPS_FINDINGS=()
APPSEC_FINDINGS=()
BLOCK=false

# SAFE JSON PARSER
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

for file in "$SCAN_DIR"/*.json; do
  scanner=$(basename "$file" | cut -d'-' -f1)

  echo "Processing $file (scanner: $scanner)"

  while IFS= read -r finding; do
    severity=$(echo "$finding" | jq -r '.severity // empty')
    id=$(echo "$finding" | jq -r '.id // empty')
    file_path=$(echo "$finding" | jq -r '.file // empty')
    line=$(echo "$finding" | jq -r '.line // empty')

    # Skip entries with no severity
    [[ -z "$severity" ]] && continue

    # DevSecOps-owned scanners
    if [[ "$scanner" == "secret" || "$scanner" == "image" || "$scanner" == "iac" ]]; then
      DEVSECOPS_FINDINGS+=("$severity|$scanner|$id|$file_path|$line")

      if [[ "$severity" == "CRITICAL" ]]; then
        BLOCK=true
      fi

    # AppSec-owned scanner
    elif [[ "$scanner" == "sast" ]]; then
      APPSEC_FINDINGS+=("$severity|$scanner|$id|$file_path|$line")

      if [[ "$severity" == "CRITICAL" && "$ENVIRONMENT" == "production" ]]; then
        BLOCK=true
      fi
    fi

  done < <(safe_parse "$file")

done

echo "=== Building PR Comment ==="

COMMENT_FILE="security-gate-comment.md"

{
  echo "<!-- security-gate-comment -->"
  echo "## 🔐 Security Gate Summary"

  if $BLOCK; then
    echo "**❌ Merge Blocked** — CRITICAL DevSecOps findings detected."
  else
    echo "**✅ Merge Allowed** — No blocking DevSecOps findings."
  fi

  echo ""
  echo "## 🛡️ DevSecOps-Owned Findings"
  echo "Blocking when **CRITICAL** (Secrets, Image Scan, IaC Scan)"
  echo ""
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
  echo "Non-blocking — escalate to AppSec via the intake form:"
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

echo "=== Posting PR Comment ==="
gh pr comment "$PR_NUMBER" --body-file "$COMMENT_FILE" || true

echo "=== Security Gate Finished ==="

if $BLOCK; then
  exit 1
else
  exit 0
fi

