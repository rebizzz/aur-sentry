#!/usr/bin/env bash
# scripts/finalize_scan.sh
#
# TRUSTED half of .github/workflows/scan.yml (the `finalize` job). Runs on a
# fresh runner checked out at main, with write permissions, and treats the
# `raw-evidence` artifact from the untrusted `sandbox` job as data only.
#
# Usage: scripts/finalize_scan.sh <attest|commit|report>
#
#   attest  validate the artifact, recompute static findings from the
#           snapshot committed on the scan branch, run `aur-sentry attest`
#           (the verdict is computed HERE), cosign sign-blob, stage the
#           result (+ an advisory entry for SUSPICIOUS/MALICIOUS) in $STAGE
#   commit  commit data/attestations/<pkg>/<ver>.json{,.sig,.cert} (and the
#           advisories.json upsert) to main; fetch/reset/re-apply/push, up
#           to 5 attempts
#   report  commit status on the PR head sha, verdict comment, close PR +
#           delete branch
#
# Env: PKG (required), PR (optional), EVIDENCE (downloaded artifact dir),
#      STAGE (scratch dir), AUR_SENTRY_BIN, SANDBOX_RESULT, RUN_URL,
#      GITHUB_REPOSITORY, GITHUB_SHA, GITHUB_REF_NAME, GITHUB_OUTPUT, GH_TOKEN

set -uo pipefail

CMD="${1:?usage: finalize_scan.sh <attest|commit|report>}"
PKG="${PKG:?PKG required}"
PR="${PR:-}"
EVIDENCE="${EVIDENCE:-${RUNNER_TEMP:-/tmp}/raw-evidence}"
STAGE="${STAGE:-${RUNNER_TEMP:-/tmp}/finalize}"
AUR_SENTRY_BIN="${AUR_SENTRY_BIN:-./target/release/aur-sentry}"
REPO="${GITHUB_REPOSITORY:-rebizzz/aur-sentry}"
RUN_URL="${RUN_URL:-}"
RESULT="$STAGE/result.json"
REGISTRY_URL="https://rebizzz.github.io/aur-sentry/package.html?name=${PKG}"

if ! printf '%s' "$PKG" | grep -Eq '^[A-Za-z0-9@_+][A-Za-z0-9@._+-]{0,127}$'; then
  echo "::error::invalid package name"
  exit 1
fi
if [ -n "$PR" ] && ! printf '%s' "$PR" | grep -Eq '^[0-9]{1,9}$'; then
  echo "::error::invalid PR number"
  exit 1
fi
mkdir -p "$STAGE"

set_output() {
  [ -n "${GITHUB_OUTPUT:-}" ] && printf '%s=%s\n' "$1" "$2" >> "$GITHUB_OUTPUT"
  return 0
}

write_result() {
  # write_result <verdict> <attested> [version] [file_ver] [aur_commit] [source_origin]
  jq -n --arg verdict "$1" --argjson attested "$2" --arg version "${3:-}" \
    --arg file_ver "${4:-}" --arg aur_commit "${5:-}" --arg source_origin "${6:-}" \
    '{verdict:$verdict, attested:$attested, version:$version, file_ver:$file_ver,
      aur_commit:$aur_commit, source_origin:$source_origin}' > "$RESULT"
  set_output verdict "$1"
  set_output attested "$2"
  set_output file_ver "${4:-}"
}

# ── attest ─────────────────────────────────────────────────────────────
cmd_attest() {
  write_result ANALYSIS_FAILED false
  local meta="$EVIDENCE/meta.json"
  if ! jq -e 'type == "object"' "$meta" >/dev/null 2>&1; then
    echo "::warning::no usable meta.json in the raw-evidence artifact (sandbox result: ${SANDBOX_RESULT:-unknown}) — nothing to attest"
    return 0
  fi

  # Identity comes from the workflow input, never from the artifact.
  local meta_pkg
  meta_pkg="$(jq -r '.package // ""' "$meta")"
  if [ "$meta_pkg" != "$PKG" ]; then
    echo "::error::artifact meta.json is for a different package — refusing to attest"
    return 0
  fi

  local version file_ver arch makepkg_exit strace repro install_ran
  version="$(jq -r '.version // "unknown"' "$meta")"
  if ! printf '%s' "$version" | grep -Eq '^[A-Za-z0-9._+~:-]{1,128}$'; then
    version="unknown"
  fi
  # Filename-safe version: [A-Za-z0-9._+~-] only, no leading dot.
  file_ver="$(printf '%s' "$version" | tr -c 'A-Za-z0-9._+~-' '_')"
  while [ "${file_ver#.}" != "$file_ver" ]; do file_ver="_${file_ver#.}"; done
  [ -n "$file_ver" ] || file_ver="unknown"

  arch="$(jq -r '.arch // "x86_64"' "$meta")"
  case "$arch" in x86_64|any|aarch64|i686) ;; *) arch="x86_64" ;; esac
  makepkg_exit="$(jq -r '.makepkg_exit | if type == "number" then floor | tostring else "" end' "$meta")"
  strace="$(jq -r '.strace_available == true' "$meta")"
  repro="$(jq -r '.reproducibility_status // "NOT_ATTEMPTED"' "$meta")"
  case "$repro" in NOT_ATTEMPTED|REPRODUCED|DIVERGED|FAILED|UNSUPPORTED) ;; *) repro="NOT_ATTEMPTED" ;; esac
  install_ran="$(jq -r '.install_phase_ran == true' "$meta")"

  # Source snapshot: prefer the copy committed on the scan branch (the
  # dispatch ref, $GITHUB_SHA) over the artifact's copy.
  local src="$STAGE/source" source_origin aur_commit="" path name
  rm -rf "$src"
  mkdir -p "$src"
  [ -n "${GITHUB_SHA:-}" ] && { git fetch --quiet --no-tags origin "$GITHUB_SHA" 2>/dev/null || true; }
  if [ -n "${GITHUB_SHA:-}" ] && git cat-file -e "$GITHUB_SHA:scans/$PKG/PKGBUILD" 2>/dev/null; then
    source_origin="scan-branch"
    git show "$GITHUB_SHA:scans/$PKG/PKGBUILD" > "$src/PKGBUILD"
    while IFS= read -r -d '' path; do
      name="${path##*/}"
      case "$name" in *.install) ;; *) continue ;; esac
      printf '%s' "$name" | grep -Eq '^[A-Za-z0-9@_+][A-Za-z0-9@._+-]*$' || continue
      git show "$GITHUB_SHA:$path" > "$src/$name"
    done < <(git ls-tree -z --name-only "$GITHUB_SHA" "scans/$PKG/")
    aur_commit="$(git show "$GITHUB_SHA:scans/$PKG/request.json" 2>/dev/null | jq -r '.aur_commit // ""' 2>/dev/null || true)"
  else
    source_origin="artifact"
    for path in "$EVIDENCE/source/PKGBUILD" "$EVIDENCE"/source/*.install; do
      if [ ! -f "$path" ] || [ -L "$path" ]; then continue; fi
      cp -- "$path" "$src/"
    done
    aur_commit="$(jq -r '.aur_commit // ""' "$meta")"
  fi
  printf '%s' "$aur_commit" | grep -Eq '^[0-9a-f]{40}$' || aur_commit=""
  if [ ! -f "$src/PKGBUILD" ]; then
    echo "::error::no PKGBUILD available to attest"
    return 0
  fi
  echo "source: $source_origin, version: $version (file: $file_ver), aur commit: ${aur_commit:-unknown}"

  # Static findings recomputed here from the trusted snapshot.
  local static_dir="$STAGE/static" f out
  local -a jsons=()
  rm -rf "$static_dir"
  mkdir -p "$static_dir"
  for f in "$src"/PKGBUILD "$src"/*.install; do
    [ -f "$f" ] || continue
    out="$static_dir/${f##*/}.json"
    "$AUR_SENTRY_BIN" scan-file "$f" --json > "$out" 2>/dev/null
    jq -e 'type == "object" and has("findings")' "$out" >/dev/null 2>&1 && jsons+=("$out")
  done
  if [ "${#jsons[@]}" -gt 0 ]; then
    jq -s . "${jsons[@]}" > "$STAGE/static_findings.json"
  else
    echo '[]' > "$STAGE/static_findings.json"
  fi

  local att_dir="$STAGE/attestation" output
  rm -rf "$att_dir"
  mkdir -p "$att_dir"
  output="$att_dir/$file_ver.json"

  local -a args=(
    "$PKG"
    --version "$version"
    --arch "$arch"
    --aur-commit "$aur_commit"
    --pkgbuild "$src/PKGBUILD"
    --static-findings "$STAGE/static_findings.json"
    --reproducibility-status "$repro"
    --output "$output"
  )
  [ -f "$EVIDENCE/telemetry.log" ] && args+=(--telemetry "$EVIDENCE/telemetry.log")
  [ "$strace" = true ] && args+=(--strace-available)
  [ -n "$makepkg_exit" ] && args+=(--makepkg-exit "$makepkg_exit")
  for f in "$src"/*.install; do
    [ -f "$f" ] || continue
    args+=(--install-file "$f")
    break
  done
  if [ "$install_ran" = true ] && [ -f "$EVIDENCE/install_telemetry.log" ]; then
    args+=(--install-telemetry "$EVIDENCE/install_telemetry.log")
  fi
  jq -e 'type == "object"' "$EVIDENCE/package_analysis.json" >/dev/null 2>&1 \
    && args+=(--package-analysis "$EVIDENCE/package_analysis.json")
  jq -e 'type == "array"' "$EVIDENCE/external_intel.json" >/dev/null 2>&1 \
    && args+=(--external-intel "$EVIDENCE/external_intel.json")

  # Non-VERIFIED verdicts exit non-zero by design; the JSON is what matters.
  "$AUR_SENTRY_BIN" attest "${args[@]}" || true
  if ! jq -e '.verdict' "$output" >/dev/null 2>&1; then
    echo "::error::aur-sentry attest produced no attestation"
    return 0
  fi
  local verdict
  verdict="$(jq -r '.verdict' "$output")"
  echo "verdict: $verdict"

  if command -v cosign >/dev/null 2>&1; then
    cosign sign-blob --yes \
      --output-signature "$output.sig" \
      --output-certificate "$output.cert" \
      "$output" || echo "::warning::cosign signing failed — committing unsigned attestation"
  else
    echo "::warning::cosign not installed — committing unsigned attestation"
  fi

  case "$verdict" in
    SUSPICIOUS|MALICIOUS) stage_advisory "$verdict" "$version" "$output" ;;
    *) rm -f "$STAGE/advisory.json" ;;
  esac

  write_result "$verdict" true "$version" "$file_ver" "$aur_commit" "$source_origin"
}

# Minimal advisories.json entry, same shape as the autopilot's entries
# (package, version, maintainer, highest_severity, detected_at, findings,
# aur_url). advisories.xml / ADVISORIES.md have no standalone generator, so
# they are refreshed by the next autopilot run.
stage_advisory() {
  local verdict="$1" version="$2" attestation="$3" severity maintainer
  severity="HIGH"
  [ "$verdict" = MALICIOUS ] && severity="CRITICAL"
  maintainer="$(curl -fsS -m 10 "https://aur.archlinux.org/rpc/v5/info?arg%5B%5D=${PKG}" 2>/dev/null \
    | jq -r '.results[0].Maintainer // "unknown"' 2>/dev/null || true)"
  [ -n "$maintainer" ] || maintainer="unknown"
  jq -n \
    --arg package "$PKG" --arg version "$version" --arg maintainer "$maintainer" \
    --arg severity "$severity" --arg verdict "$verdict" \
    --arg detected_at "$(date -u +%Y-%m-%dT%H:%M:%S+00:00)" \
    --slurpfile static "$STAGE/static_findings.json" \
    --slurpfile att "$attestation" \
    '($static[0] // [] | map(.findings // []) | add // []) as $f
     | {
        package: $package,
        version: $version,
        maintainer: $maintainer,
        highest_severity: $severity,
        detected_at: $detected_at,
        findings: (if ($f | length) > 0 then $f else [{
          rule_id: ("DYNAMIC_SANDBOX_" + $verdict),
          severity: $severity,
          description: ("dynamic sandbox verdict " + $verdict + " (see signed attestation, evidence hash " + (($att[0].evidence_hash // "") | .[0:16]) + ")"),
          line_number: 0,
          matched_text: ""
        }] end),
        aur_url: ("https://aur.archlinux.org/packages/" + $package)
      }' > "$STAGE/advisory.json"
}

# ── commit ─────────────────────────────────────────────────────────────
apply_changes() {
  local dest="data/attestations/$PKG"
  mkdir -p "$dest"
  cp -- "$STAGE"/attestation/* "$dest/"
  git add -- "$dest"
  if [ -f "$STAGE/advisory.json" ]; then
    [ -f advisories.json ] && jq -e '.advisories | type == "array"' advisories.json >/dev/null 2>&1 \
      || echo '{"version":"1.0","updated_at":"","total_flagged":0,"advisories":[]}' > advisories.json
    jq --slurpfile e "$STAGE/advisory.json" '
      def rank: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}[.highest_severity] // 4;
      .advisories = ([.advisories[] | select(.package != $e[0].package)] + $e
                     | sort_by(.detected_at) | reverse | sort_by(rank))
      | .total_flagged = (.advisories | length)
      | .updated_at = $e[0].detected_at' advisories.json > advisories.json.tmp \
      && mv advisories.json.tmp advisories.json
    git add advisories.json
  fi
}

cmd_commit() {
  set_output committed false
  if [ "$(jq -r '.attested' "$RESULT" 2>/dev/null)" != true ]; then
    echo "nothing attested — no commit"
    return 0
  fi
  local verdict version attempt
  verdict="$(jq -r '.verdict' "$RESULT")"
  version="$(jq -r '.version' "$RESULT")"
  git config user.name "aur-sentry-bot"
  git config user.email "bot@users.noreply.github.com"

  for attempt in 1 2 3 4 5; do
    git fetch --quiet origin main
    git checkout --quiet --force -B finalize-scan origin/main
    apply_changes
    if git diff --cached --quiet; then
      echo "attestation already identical on main — nothing to commit"
      return 0
    fi
    git commit --quiet -m "chore(scan): ${verdict} attestation for ${PKG} ${version}" \
      -m "Run: ${RUN_URL}"
    if git push --quiet origin HEAD:main; then
      echo "pushed attestation to main (attempt $attempt)"
      set_output committed true
      return 0
    fi
    echo "::warning::push attempt $attempt failed, retrying on a fresh main"
    sleep $((attempt * 5 + RANDOM % 5))
  done
  echo "::error::could not push attestation to main after 5 attempts"
  return 1
}

# ── report ─────────────────────────────────────────────────────────────
cmd_report() {
  if [ -z "$PR" ]; then
    echo "manual run without a scan PR — nothing to report"
    return 0
  fi
  local pr_json head_ref head_sha pr_state
  if ! pr_json="$(gh pr view "$PR" --repo "$REPO" --json headRefName,headRefOid,state)"; then
    echo "::error::cannot read PR #$PR"
    return 1
  fi
  head_ref="$(jq -r '.headRefName' <<<"$pr_json")"
  head_sha="$(jq -r '.headRefOid' <<<"$pr_json")"
  pr_state="$(jq -r '.state' <<<"$pr_json")"
  # Only ever touch the scan PR this run was dispatched for.
  if [ "$head_ref" != "${GITHUB_REF_NAME:-}" ] || [ "${head_ref#scan/}" = "$head_ref" ]; then
    echo "::error::PR #$PR head '$head_ref' does not match this run's scan branch '${GITHUB_REF_NAME:-}' — not touching it"
    return 1
  fi

  local verdict attested file_ver state desc
  verdict="$(jq -r '.verdict // "ANALYSIS_FAILED"' "$RESULT" 2>/dev/null || echo ANALYSIS_FAILED)"
  attested="$(jq -r '.attested // false' "$RESULT" 2>/dev/null || echo false)"
  file_ver="$(jq -r '.file_ver // ""' "$RESULT" 2>/dev/null || true)"
  case "$verdict" in
    VERIFIED) state=success ;;
    SUSPICIOUS|MALICIOUS) state=failure ;;
    *) state=error ;;
  esac
  desc="verdict: $verdict"
  [ "$attested" = true ] || desc="analysis failed — no attestation (sandbox: ${SANDBOX_RESULT:-unknown})"

  gh api --silent -X POST "repos/$REPO/statuses/$head_sha" \
    -f state="$state" -f context="aur-sentry/scan" \
    -f description="${desc:0:140}" -f target_url="$RUN_URL" \
    || echo "::warning::could not set commit status"

  local body="$STAGE/comment.md"
  if [ "$attested" = true ]; then
    local att="$STAGE/attestation/$file_ver.json"
    {
      echo "## AUR-Sentry scan: \`$PKG\` — **$verdict**"
      echo
      jq -r --arg url "$REGISTRY_URL" '
        "| | |", "|---|---|",
        "| Verdict | **\(.verdict)** |",
        "| Version | `\(.package.version)` |",
        "| AUR commit | `\(.source.aur_commit // "unknown")` |",
        "| Reproducibility | \(.reproducibility // "NOT_ATTEMPTED") |",
        "| Dynamic telemetry | \(if .dynamic_evidence.collected then "collected" else "unavailable" end) — \(.dynamic_evidence.processes // [] | length) process, \(.dynamic_evidence.network // [] | length) network, \(.dynamic_evidence.filesystem // [] | length) filesystem event(s) |",
        "| Package analysis | \(if .package_analysis.available then "\(.package_analysis.file_count) files, \(.package_analysis.elf_object_count) ELF, \(.package_analysis.setuid_files) setuid, \(.package_analysis.world_writable_files) world-writable" else "unavailable" end) |",
        "| Findings by behavior | \((.static_findings // []) | if length == 0 then "none" else (group_by(.behavior) | map("`\(.[0].behavior // "UNKNOWN")`: \(length)") | join(", ")) end) |",
        "| Registry | \($url) |"
      ' "$att"
      echo
      echo "Signed attestation: [\`data/attestations/$PKG/$file_ver.json\`](https://github.com/$REPO/blob/main/data/attestations/$PKG/$file_ver.json). Verify it yourself:"
      echo
      echo '```sh'
      echo "scripts/verify_attestation.sh $PKG $file_ver"
      echo '```'
      case "$verdict" in
        SUSPICIOUS|MALICIOUS) echo; echo "This package was added to \`advisories.json\`." ;;
      esac
    } > "$body"
  else
    {
      echo "## AUR-Sentry scan: \`$PKG\` — **ANALYSIS_FAILED**"
      echo
      echo "The sandbox job finished with \`${SANDBOX_RESULT:-unknown}\` and produced no usable evidence, so no attestation was committed. The package will be re-triaged on a later autopilot cycle."
    } > "$body"
  fi
  {
    echo
    echo "[Workflow run]($RUN_URL) · This PR only carried the package snapshot and is closed automatically."
  } >> "$body"

  gh pr comment "$PR" --repo "$REPO" --body-file "$body" || echo "::warning::could not comment on PR #$PR"
  if [ "$pr_state" = OPEN ]; then
    gh pr close "$PR" --repo "$REPO" --delete-branch || echo "::warning::could not close PR #$PR"
  fi
}

case "$CMD" in
  attest) cmd_attest ;;
  commit) cmd_commit ;;
  report) cmd_report ;;
  *) echo "unknown command '$CMD'" >&2; exit 2 ;;
esac
