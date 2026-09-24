#!/usr/bin/env bash
# scripts/file_threat_issue.sh
# Automates the creation and updating of GitHub Issue alerts for CRITICAL packages
# with full package details, offending code snippets, and full PKGBUILD contents.

set -euo pipefail

REPO_ROOT="${1:-.}"
TARGET_REPO="${2:-rebizzz/aur-sentry}"
ADVISORIES_JSON="$REPO_ROOT/advisories.json"

if [ ! -f "$ADVISORIES_JSON" ]; then
    echo "[!] No advisories.json found at $ADVISORIES_JSON"
    exit 0
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "[!] jq is required but not installed"
    exit 1
fi

if ! command -v gh >/dev/null 2>&1; then
    echo "[!] gh is required but not installed"
    exit 1
fi

TOTAL=$(jq '.advisories | length' "$ADVISORIES_JSON")
echo "[*] Processing $TOTAL advisories from $ADVISORIES_JSON..."

TMP_DIR="$(mktemp -d /tmp/aur_threat_issues_XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT

for i in $(seq 0 $((TOTAL - 1))); do
    SEV=$(jq -r ".advisories[$i].highest_severity" "$ADVISORIES_JSON")
    if [ "$SEV" != "CRITICAL" ]; then
        continue
    fi

    PKG=$(jq -r ".advisories[$i].package" "$ADVISORIES_JSON")
    VER=$(jq -r ".advisories[$i].version" "$ADVISORIES_JSON")
    MAINT=$(jq -r ".advisories[$i].maintainer" "$ADVISORIES_JSON")
    URL=$(jq -r ".advisories[$i].aur_url" "$ADVISORIES_JSON")
    DETECTED=$(jq -r ".advisories[$i].detected_at" "$ADVISORIES_JSON")

    echo "[+] Processing CRITICAL threat package: $PKG (v$VER)"

    # Fetch live PKGBUILD from AUR cgit
    PKGBUILD_FILE="$TMP_DIR/PKGBUILD_$PKG"
    if ! curl -fsSL "https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h=$PKG" -o "$PKGBUILD_FILE" 2>/dev/null; then
        echo "# PKGBUILD unavailable or removed from AUR" > "$PKGBUILD_FILE"
    fi

    # Build findings markdown table
    FINDINGS_TABLE=$(jq -r ".advisories[$i].findings[] | \"| \`\" + .rule_id + \"\` | \`[\" + .severity + \"]\` | \" + .description + \" | \" + (.line_number|tostring) + \" | \`\" + (.matched_text | gsub(\"\\n\"; \" \") | .[0:80]) + \"\` |\"" "$ADVISORIES_JSON")

    # Build code snippet highlights
    SNIPPETS_FILE="$TMP_DIR/snippets_$PKG.txt"
    jq -r ".advisories[$i].findings[] | \"# Line \" + (.line_number|tostring) + \" — \" + .rule_id + \" (\" + .severity + \"):\n\" + .matched_text + \"\n\"" "$ADVISORIES_JSON" > "$SNIPPETS_FILE"

    BODY_FILE="$TMP_DIR/body_$PKG.md"
    cat << EOF > "$BODY_FILE"
# 🚨 [CRITICAL THREAT] Active Supply-Chain Alert for \`$PKG\`

AUR-Sentry Autopilot detected a **CRITICAL** severity supply-chain threat in Arch User Repository (AUR) package **\`$PKG\`**.

### 📋 Package Details
- **Package:** \`$PKG\`
- **Version:** \`$VER\`
- **Maintainer:** \`$MAINT\`
- **Severity:** \`[CRITICAL]\`
- **AUR Page:** [$PKG on AUR]($URL)
- **Detected At:** \`$DETECTED\`

### 🔍 Threat Findings
| Rule ID | Severity | Description | Line | Matched Code |
| :--- | :--- | :--- | :--- | :--- |
$FINDINGS_TABLE

### 🛑 Offending Code Snippet(s)
\`\`\`bash
$(cat "$SNIPPETS_FILE")
\`\`\`

<details>
<summary><b>📦 View Full Package PKGBUILD</b></summary>

\`\`\`bash
$(cat "$PKGBUILD_FILE")
\`\`\`
</details>

### 🛠️ Verification
You can verify this package code dynamically using \`aur-sentry\` or \`safeaur\`:
\`\`\`bash
aur-sentry scan-pkg $PKG
safeaur check $PKG
\`\`\`

*Reported automatically by [AUR-Sentry](https://github.com/rebizzz/aur-sentry) Autopilot Threat Radar.*
EOF

    ISSUE_TITLE="[CRITICAL THREAT] Active supply-chain alert for $PKG"
    EXISTING_ISSUE=$(gh issue list --repo "$TARGET_REPO" --state open --search "$PKG" --json number,title --jq ".[] | select(.title | contains(\"$PKG\")) | .number" | head -n 1 || true)

    if [ -n "$EXISTING_ISSUE" ]; then
        echo "    Updating existing issue #$EXISTING_ISSUE in $TARGET_REPO with full code and findings..."
        gh issue edit "$EXISTING_ISSUE" --repo "$TARGET_REPO" --body-file "$BODY_FILE"
    else
        echo "    Creating new security issue for $PKG in $TARGET_REPO with full code and findings..."
        gh issue create --repo "$TARGET_REPO" --title "$ISSUE_TITLE" --body-file "$BODY_FILE"
    fi
done

echo "[✓] Finished processing all threat issues."
