#!/usr/bin/env bash
# scripts/file_dynamic_threat_issue.sh
#
# Notification layer for the dynamic sandbox pipeline (ARCHITECTURE.md):
# "Notifications (GitHub issue only for SUSPICIOUS/MALICIOUS)". Reads one
# attestation JSON produced by `aur-sentry attest` and, if its verdict is
# SUSPICIOUS or MALICIOUS, files or updates a GitHub issue with the evidence.
# VERIFIED/INCONCLUSIVE/etc. attestations are silent — the registry is the
# primary output, issues are only for things a human should look at.
#
# Usage: file_dynamic_threat_issue.sh <attestation.json> [target-repo]

set -euo pipefail

ATTESTATION_FILE="${1:?path to attestation JSON required}"
TARGET_REPO="${2:-rebizzz/aur-sentry}"

if ! command -v jq >/dev/null 2>&1; then
    echo "[!] jq is required but not installed"
    exit 1
fi
if ! command -v gh >/dev/null 2>&1; then
    echo "[!] gh is required but not installed"
    exit 1
fi
if [ ! -f "$ATTESTATION_FILE" ]; then
    echo "[!] no attestation file at $ATTESTATION_FILE"
    exit 0
fi

VERDICT=$(jq -r '.verdict // "UNKNOWN"' "$ATTESTATION_FILE")
case "$VERDICT" in
    SUSPICIOUS|MALICIOUS) ;;
    *)
        echo "[*] verdict is $VERDICT — no issue needed"
        exit 0
        ;;
esac

PKG=$(jq -r '.package.name // "unknown"' "$ATTESTATION_FILE")
VER=$(jq -r '.package.version // "unknown"' "$ATTESTATION_FILE")
ARCH=$(jq -r '.package.arch // "unknown"' "$ATTESTATION_FILE")
COMMIT=$(jq -r '.source.aur_commit // "unknown"' "$ATTESTATION_FILE")
ANALYZED_AT=$(jq -r '.analyzed_at // "unknown"' "$ATTESTATION_FILE")

echo "[+] $VERDICT attestation for $PKG@$VER — filing/updating GitHub issue"

FINDINGS_TABLE=$(jq -r '
  (.static_findings // [])
  | .[]
  | "| `" + (.behavior // "unknown") + "` | `[" + (.severity // "unknown") + "]` | " + (.description // "") + " | " + (.file // "-") + " |"
' "$ATTESTATION_FILE")
[ -z "$FINDINGS_TABLE" ] && FINDINGS_TABLE="| _(no discrete findings — see raw attestation)_ | | | |"

TMP_DIR="$(mktemp -d /tmp/aur_dynamic_threat_issue_XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT
BODY_FILE="$TMP_DIR/body.md"

ICON="⚠️"
[ "$VERDICT" = "MALICIOUS" ] && ICON="🚨"

cat <<EOF > "$BODY_FILE"
# $ICON [$VERDICT] Dynamic sandbox verdict for \`$PKG\`

AUR-Sentry's disposable dynamic sandbox built and inspected \`$PKG\` and produced a **$VERDICT** verdict.

### Package Details
- **Package:** \`$PKG\`
- **Version:** \`$VER\`
- **Arch:** \`$ARCH\`
- **AUR commit:** \`$COMMIT\`
- **Analyzed at:** \`$ANALYZED_AT\`

### Findings
| Behavior | Severity | Description | File |
| :--- | :--- | :--- | :--- |
$FINDINGS_TABLE

### Full evidence
The complete attestation (static findings, dynamic telemetry, package/ELF analysis,
reproducibility, external intelligence) is published and cryptographically signed:
- Registry: https://rebizzz.github.io/aur-sentry/package.html?name=$PKG
- Raw attestation: https://raw.githubusercontent.com/$TARGET_REPO/main/data/attestations/$PKG/$VER.json
- Verify independently: \`scripts/verify_attestation.sh $PKG $VER\`

### Check before installing
\`\`\`bash
aur-sentry check $PKG
safeaur check $PKG
\`\`\`

*Reported automatically by [AUR-Sentry](https://github.com/$TARGET_REPO) Dynamic Sandbox.*
EOF

ISSUE_TITLE="[$VERDICT] Dynamic sandbox alert for $PKG"
EXISTING_ISSUE=$(gh issue list --repo "$TARGET_REPO" --state open --search "$PKG" --json number,title \
    --jq ".[] | select(.title | contains(\"$PKG\")) | .number" | head -n 1 || true)

if [ -n "$EXISTING_ISSUE" ]; then
    echo "    Updating existing issue #$EXISTING_ISSUE in $TARGET_REPO"
    gh issue edit "$EXISTING_ISSUE" --repo "$TARGET_REPO" --body-file "$BODY_FILE"
else
    echo "    Creating new issue for $PKG in $TARGET_REPO"
    gh issue create --repo "$TARGET_REPO" --title "$ISSUE_TITLE" --body-file "$BODY_FILE" \
        --label "security" 2>/dev/null || \
    gh issue create --repo "$TARGET_REPO" --title "$ISSUE_TITLE" --body-file "$BODY_FILE"
fi
