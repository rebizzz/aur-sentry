#!/usr/bin/env bash
# sandbox/host_analyze.sh — HOST-side analysis, run by sandbox/run.sh after
# the containers have exited. Everything here reads container OUTPUT (built
# packages, source snapshot) as untrusted data; nothing here executes it.
#
#   - static scan (aur-sentry scan-file --json) -> static_findings.json
#   - reproducibility diff of the two independent builds
#   - package-content & ELF analysis (bsdtar listing + file/readelf)
#   - OSV.dev external-intelligence query
#   - meta.json: identity + run facts for the trusted finalize job
#
# No verdict is computed here — `aur-sentry attest` runs in the finalize job.
#
# Required env (exported by run.sh): PKG SRC_DIR EVIDENCE_DIR WORK
#   MAKEPKG_EXIT STRACE_OK INSTALL_PHASE_RAN AUR_SENTRY_BIN
# Optional env: PKG_FILE INSTALL_EXIT AUR_COMMIT
# Host tools: jq curl file readelf (binutils) bsdtar (libarchive-tools) sha256sum

set -uo pipefail

: "${PKG:?}" "${SRC_DIR:?}" "${EVIDENCE_DIR:?}" "${WORK:?}" "${AUR_SENTRY_BIN:?}"
MAKEPKG_EXIT="${MAKEPKG_EXIT:-}"
STRACE_OK="${STRACE_OK:-false}"
INSTALL_PHASE_RAN="${INSTALL_PHASE_RAN:-false}"
INSTALL_EXIT="${INSTALL_EXIT:-}"
PKG_FILE="${PKG_FILE:-}"
REPRO_DIR="$EVIDENCE_DIR/reproducibility"
mkdir -p "$REPRO_DIR"

# ── Source copy (for the artifact) + version metadata. .SRCINFO is read as
#    data (canonical, never executes the PKGBUILD). ───────────────────────
SOURCE_OUT="$EVIDENCE_DIR/source"
mkdir -p "$SOURCE_OUT"
for f in "$SRC_DIR"/PKGBUILD "$SRC_DIR"/*.install; do
  if [ ! -f "$f" ] || [ -L "$f" ]; then continue; fi
  cp -- "$f" "$SOURCE_OUT/"
done
# upload-artifact skips dotfiles, so .SRCINFO travels as SRCINFO.
if [ -f "$SRC_DIR/.SRCINFO" ] && [ ! -L "$SRC_DIR/.SRCINFO" ]; then
  cp -- "$SRC_DIR/.SRCINFO" "$SOURCE_OUT/SRCINFO"
fi

PKGVER=""
PKGREL=""
if [ -f "$SRC_DIR/.SRCINFO" ]; then
  PKGVER="$(awk -F'= ?' '/^\tpkgver = /{print $2; exit}' "$SRC_DIR/.SRCINFO")"
  PKGREL="$(awk -F'= ?' '/^\tpkgrel = /{print $2; exit}' "$SRC_DIR/.SRCINFO")"
fi
if [ -z "$PKGVER" ]; then
  PKGVER="$(awk -F= '/^pkgver=/{print $2; exit}' "$SRC_DIR/PKGBUILD" | tr -d '"'"'"'')"
fi
[ -z "$PKGVER" ] && PKGVER="unknown"
[ -z "$PKGREL" ] && PKGREL="1"
VERSION="${PKGVER}-${PKGREL}"

AUR_COMMIT="${AUR_COMMIT:-}"
if [ -z "$AUR_COMMIT" ] && [ -f "$SRC_DIR/request.json" ]; then
  AUR_COMMIT="$(jq -r '.aur_commit // ""' "$SRC_DIR/request.json" 2>/dev/null || true)"
fi
echo "Resolved version: $VERSION (aur commit ${AUR_COMMIT:-unknown})"

INSTALL_FILE=""
for f in "$SOURCE_OUT"/*.install; do
  [ -f "$f" ] || continue
  INSTALL_FILE="source/${f##*/}"
  break
done

# ── Static analysis (--json, merged with jq -s) ─────────────────────────
echo "--- Running static analyzer ---"
STATIC_DIR="$EVIDENCE_DIR/static"
mkdir -p "$STATIC_DIR"
: > "$EVIDENCE_DIR/static_scan.log"
STATIC_JSONS=()
for f in "$SOURCE_OUT"/PKGBUILD "$SOURCE_OUT"/*.install; do
  [ -f "$f" ] || continue
  out="$STATIC_DIR/${f##*/}.json"
  "$AUR_SENTRY_BIN" scan-file "$f" --json >"$out" 2>>"$EVIDENCE_DIR/static_scan.log"
  if jq -e 'type == "object" and has("findings")' "$out" >/dev/null 2>&1; then
    STATIC_JSONS+=("$out")
  else
    echo "::warning::scan-file --json produced no valid JSON for ${f##*/}"
  fi
  # Human-readable copy for the evidence bundle (ANSI stripped).
  "$AUR_SENTRY_BIN" scan-file "$f" 2>&1 | sed -E 's/\x1b\[[0-9;]*[mK]//g' >> "$EVIDENCE_DIR/static_scan.log"
done
if [ "${#STATIC_JSONS[@]}" -gt 0 ]; then
  jq -s . "${STATIC_JSONS[@]}" > "$EVIDENCE_DIR/static_findings.json"
else
  echo '[]' > "$EVIDENCE_DIR/static_findings.json"
fi
echo "Static findings: $(jq '[.[].findings | length] | add // 0' "$EVIDENCE_DIR/static_findings.json")"

# ── Reproducibility diff (file list + per-file sha256 of each build) ─────
echo "--- Reproducibility comparison ---"
repro_collect() {
  local n="$1" dir="$WORK/repro-$1" code f
  code="$(cat "$REPRO_DIR/exit-$n.txt" 2>/dev/null || echo 1)"
  [ "$code" = 0 ] || return 1
  find "$dir" -maxdepth 1 -type f -name '*.pkg.tar.*' -printf '%f\n' 2>/dev/null | sort > "$REPRO_DIR/filelist-$n.txt"
  : > "$REPRO_DIR/hashes-$n.txt"
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    sha256sum "$dir/$f" | awk '{print $1}' >> "$REPRO_DIR/hashes-$n.txt"
  done < "$REPRO_DIR/filelist-$n.txt"
  [ -s "$REPRO_DIR/filelist-$n.txt" ]
}
REPRO_STATUS="NOT_ATTEMPTED"
if [ -f "$REPRO_DIR/exit-1.txt" ] || [ -f "$REPRO_DIR/exit-2.txt" ]; then
  if repro_collect 1 && repro_collect 2; then
    if diff -q "$REPRO_DIR/filelist-1.txt" "$REPRO_DIR/filelist-2.txt" >/dev/null 2>&1 \
      && diff -q "$REPRO_DIR/hashes-1.txt" "$REPRO_DIR/hashes-2.txt" >/dev/null 2>&1; then
      REPRO_STATUS="REPRODUCED"
    else
      REPRO_STATUS="DIVERGED"
    fi
  else
    REPRO_STATUS="UNSUPPORTED"
    echo "::warning::reproducibility comparison did not complete for both independent builds (commonly --nodeps blocking a network-fetched dependency) — marking UNSUPPORTED rather than failing the attestation"
  fi
fi
echo "Reproducibility status: $REPRO_STATUS"

# ── Package-content & ELF analysis over the real built package. Mode bits
#    come from the archive LISTING (a non-root extract would drop setuid);
#    content checks run on a scratch extract outside the evidence dir. ────
echo "--- Package-content & ELF analysis ---"
PKG_ANALYSIS_JSON="$EVIDENCE_DIR/package_analysis.json"
PKG_ANALYSIS_AVAILABLE=false
SETUID_LIST="$EVIDENCE_DIR/setuid_files.txt"
WW_LIST="$EVIDENCE_DIR/world_writable_files.txt"
ELF_OBJECTS_JSONL="$EVIDENCE_DIR/elf_objects.jsonl"
PKG_META_RE='^[.](PKGINFO|MTREE|BUILDINFO|INSTALL|CHANGELOG)$'

if [ -n "$PKG_FILE" ] && [ -f "$PKG_FILE" ] && command -v bsdtar >/dev/null 2>&1; then
  echo "Analyzing package: ${PKG_FILE##*/}"
  EXTRACT_DIR="$WORK/pkg-extract"
  rm -rf "$EXTRACT_DIR"
  mkdir -p "$EXTRACT_DIR"
  if bsdtar -tvf "$PKG_FILE" > "$WORK/pkg_listing.txt" 2>"$EVIDENCE_DIR/pkg_extract.log" \
    && bsdtar -xf "$PKG_FILE" -C "$EXTRACT_DIR" >>"$EVIDENCE_DIR/pkg_extract.log" 2>&1; then
    chmod -R u+rwX "$EXTRACT_DIR" 2>/dev/null || true

    # Regular-file entries only (package metadata like .PKGINFO excluded);
    # name = everything after bsdtar's 8 metadata columns.
    FILE_COUNT="$(awk -v ww="$WW_LIST" -v su="$SETUID_LIST" -v meta="$PKG_META_RE" '
      BEGIN { n = 0; printf "" > ww; printf "" > su }
      substr($1, 1, 1) == "-" {
        mode = $1; name = $0
        for (i = 1; i <= 8; i++) sub(/^[ \t]*[^ \t]+/, "", name)
        sub(/^[ \t]+/, "", name)
        if (name ~ meta) next
        n++
        u = substr(mode, 4, 1); g = substr(mode, 7, 1)
        if (u == "s" || u == "S" || g == "s" || g == "S") print name > su
        if (substr(mode, 9, 1) == "w") print name > ww
      }
      END { print n }' "$WORK/pkg_listing.txt")"

    : > "$ELF_OBJECTS_JSONL"
    ELF_COUNT=0
    while IFS= read -r -d '' f; do
      rel="${f#"$EXTRACT_DIR"/}"
      [[ "$rel" =~ $PKG_META_RE ]] && continue
      FOUT="$(file -b "$f" 2>/dev/null)"
      case "$FOUT" in
        *ELF*)
          ELF_COUNT=$((ELF_COUNT + 1))
          ARCH="$(readelf -h "$f" 2>/dev/null | awk -F': *' '/Machine:/{print $2; exit}')"
          [ -n "$ARCH" ] || ARCH="unknown"
          STRIPPED=false
          case "$FOUT" in *"not stripped"*) STRIPPED=false ;; *stripped*) STRIPPED=true ;; esac
          PIE=false
          case "$FOUT" in *"pie executable"*|*"shared object"*) PIE=true ;; esac
          jq -n -c --arg path "$rel" --arg arch "$ARCH" \
            --argjson stripped "$STRIPPED" --argjson pie "$PIE" \
            '{path:$path, arch:$arch, stripped:$stripped, pie:$pie}' >> "$ELF_OBJECTS_JSONL"
          ;;
      esac
    done < <(find "$EXTRACT_DIR" -type f -print0)

    jq -n \
      --argjson file_count "$FILE_COUNT" \
      --argjson elf_object_count "$ELF_COUNT" \
      --slurpfile elf_objects "$ELF_OBJECTS_JSONL" \
      --argjson setuid_files "$(wc -l < "$SETUID_LIST")" \
      --argjson world_writable_files "$(wc -l < "$WW_LIST")" \
      --rawfile setuid_raw "$SETUID_LIST" \
      --rawfile ww_raw "$WW_LIST" \
      '{
        available: true,
        file_count: $file_count,
        elf_object_count: $elf_object_count,
        elf_objects: $elf_objects,
        setuid_files: $setuid_files,
        world_writable_files: $world_writable_files,
        setuid_paths: ($setuid_raw | split("\n") | map(select(length > 0))),
        world_writable_paths: ($ww_raw | split("\n") | map(select(length > 0)))
      }' > "$PKG_ANALYSIS_JSON"
    PKG_ANALYSIS_AVAILABLE=true
    rm -rf "$EXTRACT_DIR"
  else
    echo "::warning::failed to read '${PKG_FILE##*/}' for package-content analysis"
  fi
elif [ -n "$PKG_FILE" ]; then
  echo "::warning::bsdtar not available on the host — skipping package-content analysis" \
    | tee -a "$EVIDENCE_DIR/pkg_extract.log"
else
  echo "::warning::no built package available for package-content analysis (reproducibility status: $REPRO_STATUS)"
fi
if [ "$PKG_ANALYSIS_AVAILABLE" != true ]; then
  jq -n '{available:false, file_count:0, elf_object_count:0, elf_objects:[], setuid_files:0, world_writable_files:0, setuid_paths:[], world_writable_paths:[]}' \
    > "$PKG_ANALYSIS_JSON"
fi
echo "Package analysis available: $PKG_ANALYSIS_AVAILABLE"

# ── External intelligence — OSV.dev. Evidence only, never verdict-deciding.
#    OSV has no Arch/AUR ecosystem, so we try (a) depends/makedepends names
#    against PyPI/npm/crates.io (name-collision guess, low-yield) and (b) a
#    github.com upstream url as a Go module path (an exact identity match).
#    For most AUR packages the honest result is `[]`. ─────────────────────
echo "--- External intelligence (OSV.dev) ---"
EXTERNAL_INTEL_JSON="$EVIDENCE_DIR/external_intel.json"
OSV_QUERIES_JSON="$EVIDENCE_DIR/osv_queries.json"
OSV_ECOSYSTEMS='["PyPI","npm","crates.io"]'

DEP_NAMES="$(awk -F'= ?' '/^\t(make)?depends(_[A-Za-z0-9_]+)? = /{print $2}' "$SRC_DIR/.SRCINFO" 2>/dev/null \
  | sed -E 's/[<>=].*$//' | sed '/^$/d' | sort -u | head -n 25)"

PKG_URL="$(grep -m1 '^url=' "$SRC_DIR/PKGBUILD" 2>/dev/null | sed -E 's/^url=//' | tr -d '"'"'"'\r')"
GO_MODULE=""
case "$PKG_URL" in
  *github.com/*)
    GO_MODULE="$(printf '%s' "$PKG_URL" | sed -E 's#^https?://##; s#/$##; s#\.git$##')"
    ;;
esac

{
  if [ -n "$DEP_NAMES" ]; then
    printf '%s\n' "$DEP_NAMES" | jq -R -c --argjson ecosystems "$OSV_ECOSYSTEMS" \
      'select(length > 0) as $n | $ecosystems[] | {package: {name: $n, ecosystem: .}}'
  fi
  if [ -n "$GO_MODULE" ]; then
    jq -n -c --arg m "$GO_MODULE" '{package: {name: $m, ecosystem: "Go"}}'
  fi
} | jq -s '{queries: .}' > "$OSV_QUERIES_JSON"

OSV_QUERY_COUNT="$(jq '.queries | length' "$OSV_QUERIES_JSON")"
: > "$EVIDENCE_DIR/osv_entries.jsonl"
if [ "$OSV_QUERY_COUNT" -gt 0 ]; then
  echo "Querying OSV.dev for $OSV_QUERY_COUNT candidate identit(y/ies)"
  OSV_RESPONSE_JSON="$EVIDENCE_DIR/osv_response.json"
  if curl -fsS -m 30 -X POST -H 'Content-Type: application/json' \
    --data @"$OSV_QUERIES_JSON" https://api.osv.dev/v1/querybatch \
    -o "$OSV_RESPONSE_JSON" 2>"$EVIDENCE_DIR/osv_query.err"; then
    HIT_IDS="$(jq -r '[.results[]?.vulns[]?.id] | unique | .[:10][]' "$OSV_RESPONSE_JSON" 2>/dev/null)"
    if [ -n "$HIT_IDS" ]; then
      while IFS= read -r vid; do
        [ -z "$vid" ] && continue
        safe_vid="$(printf '%s' "$vid" | tr -c 'A-Za-z0-9._-' '_')"
        vuln_json="$EVIDENCE_DIR/osv_vuln_$safe_vid.json"
        if curl -fsS -m 15 "https://api.osv.dev/v1/vulns/$safe_vid" \
          -o "$vuln_json" 2>>"$EVIDENCE_DIR/osv_query.err"; then
          jq -c --arg id "$vid" '{
            source: "osv.dev",
            summary: (((.summary // .details // "known vulnerability") | .[0:300]) + " (" + $id + ")"),
            url: ("https://osv.dev/vulnerability/" + $id)
          }' "$vuln_json" >> "$EVIDENCE_DIR/osv_entries.jsonl"
        fi
      done <<< "$HIT_IDS"
    fi
  else
    echo "::warning::OSV.dev query failed — continuing without external intelligence"
  fi
else
  echo "no OSV-queryable identities found for this package (expected for most AUR packages)"
fi
jq -s '.' "$EVIDENCE_DIR/osv_entries.jsonl" > "$EXTERNAL_INTEL_JSON"
echo "External intelligence entries: $(jq 'length' "$EXTERNAL_INTEL_JSON")"

# ── meta.json — run facts for the trusted finalize job. Finalize re-checks
#    `package` against its own input and never trusts it for paths. ───────
jq -n \
  --arg package "$PKG" \
  --arg version "$VERSION" \
  --arg arch x86_64 \
  --arg aur_commit "$AUR_COMMIT" \
  --arg makepkg_exit "$MAKEPKG_EXIT" \
  --argjson strace_available "$([ "$STRACE_OK" = true ] && echo true || echo false)" \
  --arg reproducibility_status "$REPRO_STATUS" \
  --argjson install_phase_ran "$([ "$INSTALL_PHASE_RAN" = true ] && echo true || echo false)" \
  --arg install_exit "$INSTALL_EXIT" \
  --arg install_file "$INSTALL_FILE" \
  '{
    package: $package,
    version: $version,
    arch: $arch,
    aur_commit: $aur_commit,
    makepkg_exit: ($makepkg_exit | tonumber? // null),
    strace_available: $strace_available,
    reproducibility_status: $reproducibility_status,
    install_phase_ran: $install_phase_ran,
    install_exit: ($install_exit | tonumber? // null),
    pkgbuild: "source/PKGBUILD",
    install_file: (if $install_file == "" then null else $install_file end),
    static_findings: "static_findings.json"
  }' > "$EVIDENCE_DIR/meta.json"

echo "=== Sandbox evidence complete: $EVIDENCE_DIR ==="
cat "$EVIDENCE_DIR/meta.json"
exit 0
