#!/usr/bin/env bash
# scripts/open_scan_pr.sh
#
# Opens a scratch "scan PR" for one AUR package and dispatches the dynamic
# scan workflow on it (see ARCHITECTURE.md "PR-based scan flow"):
#
#   1. snapshot the package from the AUR (scripts/fetch_aur_snapshot.sh)
#   2. branch scan/<pkg>-<aurcommit7> from origin/main in a temporary detached
#      git worktree (the caller's working tree and branches are never touched)
#   3. commit scans/<pkg>/{PKGBUILD,.SRCINFO,*.install,...,request.json}
#   4. push, open a PR labelled `scan`
#   5. gh workflow run scan.yml --ref <branch> -f package=<pkg> -f pr=<n>
#
# scan.yml then analyzes the snapshot, commits the signed attestation to
# main, comments the verdict on the PR and closes it.
#
# Idempotent: if an open PR for the branch already exists, it only
# re-dispatches the workflow. Dry-run (prints actions only) when neither
# GH_TOKEN nor GITHUB_TOKEN is set.
#
# Usage: scripts/open_scan_pr.sh <package> [reason...]
# Env:   GH_TOKEN/GITHUB_TOKEN, GITHUB_REPOSITORY (default: derived from origin)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"

PKG="${1:?usage: open_scan_pr.sh <package> [reason...]}"
shift
REASONS=("$@")
[ "${#REASONS[@]}" -gt 0 ] || REASONS=("MANUAL")

if ! printf '%s' "$PKG" | grep -Eq '^[A-Za-z0-9@_+][A-Za-z0-9@._+-]{0,127}$'; then
  echo "error: invalid package name '$PKG'" >&2
  exit 1
fi

TOKEN="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
DRY_RUN=false
[ -n "$TOKEN" ] || DRY_RUN=true

TARGET_REPO="${GITHUB_REPOSITORY:-}"
if [ -z "$TARGET_REPO" ]; then
  origin_url="$(git -C "$REPO_ROOT" remote get-url origin 2>/dev/null || true)"
  TARGET_REPO="$(printf '%s' "$origin_url" | sed -E 's#^(https://[^/]+/|git@[^:]+:)##; s#\.git$##')"
fi
[ -n "$TARGET_REPO" ] || TARGET_REPO="rebizzz/aur-sentry"

REASONS_TEXT="$(printf '%s, ' "${REASONS[@]}")"
REASONS_TEXT="${REASONS_TEXT%, }"

# ── Dry run: resolve the AUR commit cheaply (no clone) and print the plan ──
if [ "$DRY_RUN" = true ]; then
  sha="$(timeout 15 git ls-remote "https://aur.archlinux.org/${PKG}.git" HEAD 2>/dev/null | awk '{print $1}' | head -n1 || true)"
  branch="scan/${PKG}-${sha:0:7}"
  [ -n "$sha" ] || branch="scan/${PKG}-<aur-head>"
  echo "     [dry-run] no GH_TOKEN/GITHUB_TOKEN: would snapshot ${PKG} @ ${sha:-<unresolved>}"
  echo "     [dry-run] would push ${branch} (scans/${PKG}/) and open PR 'scan: ${PKG} @ ${sha:0:7}' on ${TARGET_REPO} [reasons: ${REASONS_TEXT}]"
  echo "     [dry-run] would run: gh workflow run scan.yml --ref ${branch} -f package=${PKG} -f pr=<n>"
  exit 0
fi

export GH_TOKEN="$TOKEN"
command -v gh >/dev/null 2>&1 || { echo "error: gh CLI is required" >&2; exit 1; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/aur_scan_pr_XXXXXX")"
WORKTREE="$WORK/worktree"
cleanup() {
  git -C "$REPO_ROOT" worktree remove --force "$WORKTREE" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# ── 1. AUR snapshot ─────────────────────────────────────────────────────
SNAP="$WORK/snapshot"
SHA="$(bash "$SCRIPT_DIR/fetch_aur_snapshot.sh" "$PKG" "$SNAP")"
SHA7="${SHA:0:7}"
BRANCH="scan/${PKG}-${SHA7}"
echo "[*] ${PKG}: AUR HEAD ${SHA} -> branch ${BRANCH}"

dispatch() {
  local pr="$1"
  echo "[*] dispatching scan.yml on ${BRANCH} (pr #${pr})"
  gh workflow run scan.yml --repo "$TARGET_REPO" --ref "$BRANCH" \
    -f package="$PKG" -f pr="$pr"
}

# ── Idempotency: an open PR for this exact snapshot just gets re-dispatched ─
EXISTING_PR="$(gh pr list --repo "$TARGET_REPO" --head "$BRANCH" --state open \
  --json number --jq '.[0].number // empty' 2>/dev/null || true)"
if [ -n "$EXISTING_PR" ]; then
  echo "[*] PR #${EXISTING_PR} already open for ${BRANCH}"
  dispatch "$EXISTING_PR"
  exit 0
fi

# ── 2-3. Branch + snapshot commit in a throwaway worktree ─────────────────
git -C "$REPO_ROOT" fetch --quiet origin main
# Detached worktree: no local branch is created in the caller's repo; the
# commit is pushed straight to refs/heads/$BRANCH on the remote.
git -C "$REPO_ROOT" worktree add --quiet --detach "$WORKTREE" origin/main

DEST="$WORKTREE/scans/$PKG"
rm -rf "$DEST"
mkdir -p "$DEST"
cp -- "$SNAP"/* "$DEST/" 2>/dev/null || true
[ -f "$SNAP/.SRCINFO" ] && cp -- "$SNAP/.SRCINFO" "$DEST/.SRCINFO"

jq -n \
  --arg package "$PKG" \
  --arg aur_commit "$SHA" \
  --arg requested_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --args '{package: $package, aur_commit: $aur_commit, reasons: $ARGS.positional, requested_at: $requested_at}' \
  "${REASONS[@]}" > "$DEST/request.json"

git -C "$WORKTREE" add -- "scans/$PKG"
BOT_NAME="${BOT_NAME:-aur-sentry[bot]}"
BOT_EMAIL="${BOT_EMAIL:-333591084+aur-sentry[bot]@users.noreply.github.com}"
git -C "$WORKTREE" \
  -c user.name="$BOT_NAME" -c user.email="$BOT_EMAIL" \
  commit --quiet --no-verify -m "scan: ${PKG} @ ${SHA7}" -m "AUR commit ${SHA}. Reasons: ${REASONS_TEXT}"

# ── 4. Push + PR ────────────────────────────────────────────────────────
git -C "$WORKTREE" push --quiet --force origin "HEAD:refs/heads/${BRANCH}"

gh label create scan --repo "$TARGET_REPO" --color 5319e7 \
  --description "Automated AUR-Sentry dynamic scan (auto-closed)" --force >/dev/null 2>&1 || true

BODY_FILE="$WORK/body.md"
cat > "$BODY_FILE" <<EOF
Automated dynamic scan of AUR package \`${PKG}\` at AUR commit [\`${SHA7}\`](https://aur.archlinux.org/cgit/aur.git/commit/?h=${PKG}&id=${SHA}).

**Triage reasons:** ${REASONS_TEXT}

This PR only carries a snapshot of the package (\`scans/${PKG}/\`) so the scan runs against exactly this code. It is **never merged**. What happens next:

1. \`scan.yml\` builds and installs the package in disposable containers (no write token, evidence streamed to the host).
2. A separate trusted job computes the verdict, signs the attestation with Sigstore and commits it to \`main\` under \`data/attestations/${PKG}/\`.
3. SUSPICIOUS / MALICIOUS verdicts are also added to \`advisories.json\`.
4. The verdict is posted here as a commit status and a comment, then this PR is closed and its branch deleted.

Registry: https://rebizzz.github.io/aur-sentry/package.html?name=${PKG}
EOF

PR_URL="$(gh pr create --repo "$TARGET_REPO" --base main --head "$BRANCH" --label scan \
  --title "scan: ${PKG} @ ${SHA7}" --body-file "$BODY_FILE")"
PR_NUM="${PR_URL##*/}"
echo "[+] opened ${PR_URL}"

# ── 5. Dispatch the scan on the PR branch ────────────────────────────────
dispatch "$PR_NUM"
