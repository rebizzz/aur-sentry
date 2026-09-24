#!/usr/bin/env bash
# scripts/triage_dispatch.sh
#
# Phase 2 triage scheduler (see ARCHITECTURE.md "Triage" stage). Runs after
# the cheap static autopilot pass and decides which AUR packages are worth
# escalating to the expensive per-package dynamic sandbox
# (.github/workflows/dynamic-sandbox.yml, repository_dispatch type
# "sentry-scan"). Static analysis already covers every changed package every
# cycle; this script exists purely to keep dynamic sandbox fan-out bounded so
# a single autopilot run can never blow through Actions concurrency/minutes.
#
# Escalation signals (any one is enough):
#   NEW               package has never been seen by this script before
#   MAINTAINER_CHANGED maintainer differs from the last-seen snapshot
#   COMMIT_CHANGED     AUR git HEAD commit differs from the last-seen snapshot
#                       (covers PKGBUILD-changed and .install-changed, since
#                       both live in the same AUR git commit)
#   STALE              AUR HEAD commit no longer matches the commit recorded
#                       in the package's latest data/attestations/<pkg>/*.json
#   HIGH_RISK          this autopilot run's advisories.json flags the package
#                       CRITICAL or HIGH severity
#
# State: data/<STATE_FILE> (default data/aur-state.json), a small JSON object
# committed to the repo, mapping package name -> last-seen {commit,
# maintainer, version, last_modified, last_checked}. This is the "last seen
# state per package" substitute for external storage (see ARCHITECTURE.md's
# free-tier control-plane DB row).
#
# Usage:
#   scripts/triage_dispatch.sh <repo_root> <target_repo> [window_hours] [max_dispatch] [candidate_limit]
#
# Env overrides (all optional): AUR_SENTRY_WINDOW_HOURS, AUR_SENTRY_MAX_DISPATCH,
# AUR_SENTRY_CANDIDATE_LIMIT, GH_TOKEN (required to actually dispatch; if
# unset the script still updates state and prints what it WOULD dispatch).
#
# Designed to degrade gracefully: network failures, a missing metadata dump,
# or missing tools cause the script to skip triage (exit 0) rather than fail
# the autopilot workflow — the static scan / advisories PR must never be
# blocked by triage.

set -uo pipefail

REPO_ROOT="${1:-.}"
TARGET_REPO="${2:-${GITHUB_REPOSITORY:-}}"
WINDOW_HOURS="${3:-${AUR_SENTRY_WINDOW_HOURS:-4}}"
MAX_DISPATCH="${4:-${AUR_SENTRY_MAX_DISPATCH:-20}}"
CANDIDATE_LIMIT="${5:-${AUR_SENTRY_CANDIDATE_LIMIT:-150}}"

AUR_META_DUMP="https://aur.archlinux.org/packages-meta-ext-v1.json.gz"
STATE_FILE="$REPO_ROOT/data/aur-state.json"
ADVISORIES_JSON="$REPO_ROOT/advisories.json"
ATTESTATIONS_DIR="$REPO_ROOT/data/attestations"

echo "[*] triage: window=${WINDOW_HOURS}h max_dispatch=${MAX_DISPATCH} candidate_limit=${CANDIDATE_LIMIT} repo=${TARGET_REPO:-<unknown>}"

if ! command -v jq >/dev/null 2>&1; then
    echo "[!] triage: jq not found, skipping triage (non-fatal)"
    exit 0
fi
if ! command -v curl >/dev/null 2>&1; then
    echo "[!] triage: curl not found, skipping triage (non-fatal)"
    exit 0
fi

mkdir -p "$REPO_ROOT/data"
[ -f "$STATE_FILE" ] || echo '{}' > "$STATE_FILE"
if ! jq -e . "$STATE_FILE" >/dev/null 2>&1; then
    echo "[!] triage: $STATE_FILE is not valid JSON, resetting to {}"
    echo '{}' > "$STATE_FILE"
fi

TMP_DIR="$(mktemp -d /tmp/aur_triage_XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT

DUMP_GZ="$TMP_DIR/meta.json.gz"
DUMP_JSON="$TMP_DIR/meta.json"

echo "[*] triage: downloading AUR metadata dump..."
if ! curl -fsSL --max-time 180 "$AUR_META_DUMP" -o "$DUMP_GZ"; then
    echo "[!] triage: failed to download metadata dump, skipping triage this run (non-fatal)"
    exit 0
fi
if ! gunzip -c "$DUMP_GZ" > "$DUMP_JSON" 2>/dev/null; then
    echo "[!] triage: failed to decompress metadata dump, skipping triage this run (non-fatal)"
    exit 0
fi

CUTOFF=$(( $(date -u +%s) - WINDOW_HOURS * 3600 ))

CANDIDATES_FILE="$TMP_DIR/candidates.jsonl"

# Packages modified within the window, newest first, bounded to CANDIDATE_LIMIT.
# Note: $DUMP_JSON is already a top-level JSON array (the metadata dump), so
# no -s/slurp here — that would wrap it in an extra array.
jq -c --argjson cutoff "$CUTOFF" '
  [ .[] | select((.LastModified // 0) >= $cutoff) |
    {name: .Name, base: (.PackageBase // .Name), version: (.Version // ""),
     maintainer: (.Maintainer // "orphan"), last_modified: (.LastModified // 0),
     first_submitted: (.FirstSubmitted // 0)} ] |
  sort_by(-(.last_modified // 0))
' "$DUMP_JSON" > "$TMP_DIR/candidates_array.json"
JQ_STATUS=$?
if [ "$JQ_STATUS" -ne 0 ]; then
    echo "[!] triage: metadata dump failed to parse (jq exit $JQ_STATUS), skipping triage this run (non-fatal)"
    exit 0
fi
jq -c '.[]' "$TMP_DIR/candidates_array.json" | head -n "$CANDIDATE_LIMIT" > "$CANDIDATES_FILE"

NUM_CANDIDATES=$(wc -l < "$CANDIDATES_FILE" | tr -d ' ')
echo "[*] triage: ${NUM_CANDIDATES} candidate package(s) modified in the last ${WINDOW_HOURS}h (bounded to ${CANDIDATE_LIMIT})"

# High-risk lookup: package -> highest_severity, from this run's advisories.json
declare -A HIGH_RISK=()
if [ -f "$ADVISORIES_JSON" ] && jq -e . "$ADVISORIES_JSON" >/dev/null 2>&1; then
    while IFS=$'\t' read -r pkg sev; do
        [ -n "$pkg" ] || continue
        HIGH_RISK["$pkg"]="$sev"
    done < <(jq -r '.advisories[]? | select(.highest_severity=="CRITICAL" or .highest_severity=="HIGH") | [.package, .highest_severity] | @tsv' "$ADVISORIES_JSON" 2>/dev/null)
fi

NEW_STATE="$TMP_DIR/new_state.json"
cp "$STATE_FILE" "$NEW_STATE"

ESCALATE_FILE="$TMP_DIR/escalate.tsv" # priority \t package \t reason
: > "$ESCALATE_FILE"

now_iso() { date -u +%Y-%m-%dT%H:%M:%SZ; }

while IFS= read -r row; do
    [ -n "$row" ] || continue
    name=$(jq -r '.name' <<<"$row")
    base=$(jq -r '.base' <<<"$row")
    version=$(jq -r '.version' <<<"$row")
    maintainer=$(jq -r '.maintainer' <<<"$row")
    last_modified=$(jq -r '.last_modified' <<<"$row")
    first_submitted=$(jq -r '.first_submitted' <<<"$row")

    if [ -z "$name" ] || [ "$name" = "null" ]; then
        continue
    fi

    prev=$(jq -c --arg n "$name" '.[$n] // empty' "$STATE_FILE" 2>/dev/null || echo "")

    # Resolve current AUR git commit cheaply (no clone). ls-remote can print
    # more than one matching line for HEAD; only the first ref's sha matters.
    commit=""
    if out=$(timeout 10 git ls-remote "https://aur.archlinux.org/${base}.git" HEAD 2>/dev/null); then
        commit=$(awk '{print $1}' <<<"$out" | head -n1)
    fi

    reason=""
    if [ -z "$prev" ]; then
        reason="NEW"
    else
        prev_maintainer=$(jq -r '.maintainer // ""' <<<"$prev")
        prev_commit=$(jq -r '.commit // ""' <<<"$prev")
        if [ -n "$maintainer" ] && [ "$maintainer" != "$prev_maintainer" ]; then
            reason="MAINTAINER_CHANGED"
        elif [ -n "$commit" ] && [ -n "$prev_commit" ] && [ "$commit" != "$prev_commit" ]; then
            reason="COMMIT_CHANGED"
        fi
    fi

    # STALE: latest attestation's recorded commit no longer matches AUR HEAD.
    if [ -z "$reason" ] && [ -n "$commit" ] && [ -d "$ATTESTATIONS_DIR/$name" ]; then
        latest_attestation=$(find "$ATTESTATIONS_DIR/$name" -maxdepth 1 -name '*.json' 2>/dev/null | sort -V | tail -n1 || true)
        if [ -n "$latest_attestation" ] && [ -f "$latest_attestation" ]; then
            att_commit=$(jq -r '.source.aur_commit // ""' "$latest_attestation" 2>/dev/null || echo "")
            if [ -n "$att_commit" ] && [ "$att_commit" != "$commit" ]; then
                reason="STALE"
            fi
        fi
    fi

    if [ -z "$reason" ] && [ -n "${HIGH_RISK[$name]:-}" ]; then
        reason="HIGH_RISK(${HIGH_RISK[$name]})"
    fi

    if [ -n "$reason" ]; then
        case "$reason" in
            HIGH_RISK*) prio=0 ;;
            STALE) prio=1 ;;
            NEW) prio=2 ;;
            MAINTAINER_CHANGED) prio=3 ;;
            COMMIT_CHANGED) prio=4 ;;
            *) prio=9 ;;
        esac
        printf '%s\t%s\t%s\n' "$prio" "$name" "$reason" >> "$ESCALATE_FILE"
    fi

    # Update state snapshot regardless of escalation, so drift is detectable next run.
    entry=$(jq -n \
        --arg commit "$commit" \
        --arg maintainer "$maintainer" \
        --arg version "$version" \
        --argjson last_modified "${last_modified:-0}" \
        --argjson first_submitted "${first_submitted:-0}" \
        --arg checked "$(now_iso)" \
        '{commit: $commit, maintainer: $maintainer, version: $version,
          last_modified: $last_modified, first_submitted: $first_submitted,
          last_checked: $checked}')
    jq --arg n "$name" --argjson e "$entry" '.[$n] = $e' "$NEW_STATE" > "$NEW_STATE.tmp" && mv "$NEW_STATE.tmp" "$NEW_STATE"
done < "$CANDIDATES_FILE"

cp "$NEW_STATE" "$STATE_FILE"

TOTAL_ESCALATE=$(wc -l < "$ESCALATE_FILE" | tr -d ' ')
echo "[*] triage: ${TOTAL_ESCALATE} package(s) meet escalation criteria before capping"

DISPATCHED=0
if [ "$TOTAL_ESCALATE" -gt 0 ]; then
    sort -n "$ESCALATE_FILE" | head -n "$MAX_DISPATCH" | while IFS=$'\t' read -r prio pkg reason; do
        [ -n "$pkg" ] || continue
        echo "  -> dispatching sentry-scan for '$pkg' (${reason})"
        if [ -z "${GH_TOKEN:-}" ] && [ -z "${GITHUB_TOKEN:-}" ]; then
            echo "     [dry-run] no GH_TOKEN/GITHUB_TOKEN available, not actually dispatching"
            continue
        fi
        if [ -z "$TARGET_REPO" ]; then
            echo "     [!] no target repo resolved (pass as arg2 or set GITHUB_REPOSITORY), skipping"
            continue
        fi
        payload=$(jq -n --arg pkg "$pkg" '{event_type: "sentry-scan", client_payload: {package: $pkg}}')
        if command -v gh >/dev/null 2>&1; then
            if ! echo "$payload" | gh api "repos/${TARGET_REPO}/dispatches" --input - >/dev/null 2>"$TMP_DIR/gh_err.log"; then
                echo "     [!] dispatch failed for '$pkg': $(cat "$TMP_DIR/gh_err.log" 2>/dev/null)"
            fi
        else
            token="${GH_TOKEN:-$GITHUB_TOKEN}"
            if ! curl -fsSL -X POST \
                -H "Authorization: token ${token}" \
                -H "Accept: application/vnd.github+json" \
                "https://api.github.com/repos/${TARGET_REPO}/dispatches" \
                -d "$payload" >/dev/null 2>"$TMP_DIR/curl_err.log"; then
                echo "     [!] dispatch failed for '$pkg': $(cat "$TMP_DIR/curl_err.log" 2>/dev/null)"
            fi
        fi
    done
    DISPATCHED=$(( TOTAL_ESCALATE < MAX_DISPATCH ? TOTAL_ESCALATE : MAX_DISPATCH ))
fi

if [ "$TOTAL_ESCALATE" -gt "$MAX_DISPATCH" ]; then
    echo "[*] triage: capped at ${MAX_DISPATCH} dispatch(es) this run (${TOTAL_ESCALATE} qualified); remainder will be re-evaluated (and re-escalate if still drifted) next cycle"
fi

echo "[*] triage: complete. up to ${DISPATCHED} dynamic-sandbox dispatch(es) fired, state file updated at ${STATE_FILE#"$REPO_ROOT/"}"
exit 0
