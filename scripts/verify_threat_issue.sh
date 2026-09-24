#!/usr/bin/env bash
# scripts/verify_threat_issue.sh
# Dynamically verifies a package from AUR using aur-sentry and posts a verification comment to the GitHub Issue.

set -euo pipefail

PKG="${1:?Package name required}"
ISSUE_NUMBER="${2:-}"
REPO="${3:-rebizzz/aur-sentry}"

echo "=== AUR-Sentry Dynamic Threat Verification ==="
echo "Target package: $PKG"
echo "Target repo:    $REPO"
if [ -n "$ISSUE_NUMBER" ]; then
    echo "Issue number:   #$ISSUE_NUMBER"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

# Locate aur-sentry binary
AUR_BIN=""
if [ -x "$REPO_ROOT/target/release/aur-sentry" ]; then
    AUR_BIN="$REPO_ROOT/target/release/aur-sentry"
elif [ -x "$REPO_ROOT/target/debug/aur-sentry" ]; then
    AUR_BIN="$REPO_ROOT/target/debug/aur-sentry"
elif command -v aur-sentry >/dev/null 2>&1; then
    AUR_BIN="$(command -v aur-sentry)"
else
    echo "Building aur-sentry in release mode..."
    cargo build --release --manifest-path "$REPO_ROOT/Cargo.toml"
    AUR_BIN="$REPO_ROOT/target/release/aur-sentry"
fi

echo "Using scanner: $AUR_BIN"

TMP_DIR="$(mktemp -d /tmp/verify_pkg_XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "Fetching live PKGBUILD for $PKG from AUR..."
curl -fsSL "https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h=$PKG" -o "$TMP_DIR/PKGBUILD" 2>/dev/null || true

set +e
"$AUR_BIN" scan-pkg "$PKG" > "$TMP_DIR/scan_output.txt" 2>&1
SCAN_EXIT=$?
set -e

echo "Scanner exit code: $SCAN_EXIT"
cat "$TMP_DIR/scan_output.txt"

if [ "$SCAN_EXIT" -eq 2 ]; then
    VERDICT="❌ **CONFIRMED THREAT**"
    BADGE="https://img.shields.io/badge/AUR--Sentry-CONFIRMED_THREAT-critical"
elif [ "$SCAN_EXIT" -eq 0 ]; then
    VERDICT="✅ **VERIFIED CLEAN**"
    BADGE="https://img.shields.io/badge/AUR--Sentry-CLEAN-success"
else
    VERDICT="⚠️ **UNRESOLVED / TAKEN DOWN**"
    BADGE="https://img.shields.io/badge/AUR--Sentry-INCONCLUSIVE-yellow"
fi

REPORT_FILE="$TMP_DIR/report.md"
CLEAN_LOG="$TMP_DIR/scan_output_clean.txt"
sed -E 's/\x1b\[[0-9;]*[mK]//g' "$TMP_DIR/scan_output.txt" > "$CLEAN_LOG"

cat << EOF > "$REPORT_FILE"
### 🛡️ Automated Verification Report by GitHub Actions

![$VERDICT]($BADGE)

GitHub Actions dynamically audited the live AUR package sources for **\`$PKG\`**.

| Attribute | Details |
| :--- | :--- |
| **Target Package** | \`$PKG\` |
| **Scanner Verdict** | $VERDICT (Exit code: \`$SCAN_EXIT\`) |
| **Live Upstream Source** | [AUR cgit PKGBUILD](https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h=$PKG) |
| **Execution Environment** | Ubuntu + StepSecurity Harden-Runner |

<details>
<summary><b>🔍 View aur-sentry Scanner Output</b></summary>

\`\`\`
$(tail -n 60 "$CLEAN_LOG")
\`\`\`
</details>

*Dynamically verified by GitHub Actions runner.*
EOF

if [ -n "$ISSUE_NUMBER" ] && command -v gh >/dev/null 2>&1; then
    echo "Commenting verification report on $REPO#$ISSUE_NUMBER..."
    gh issue comment "$ISSUE_NUMBER" --repo "$REPO" --body-file "$REPORT_FILE"
    if [ "$SCAN_EXIT" -eq 2 ]; then
        gh label create "security-threat" --repo "$REPO" --color "d73a4a" --description "Active verified supply-chain security threat" 2>/dev/null || true
        gh issue edit "$ISSUE_NUMBER" --repo "$REPO" --add-label "security-threat" || true
    fi
    echo "[✓] Commented on issue #$ISSUE_NUMBER successfully."
fi

echo "Verification complete: exit code $SCAN_EXIT"
exit 0
