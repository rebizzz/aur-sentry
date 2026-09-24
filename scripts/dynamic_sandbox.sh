#!/usr/bin/env bash
# scripts/dynamic_sandbox.sh
#
# Runs INSIDE a disposable `archlinux:base-devel` container (see
# .github/workflows/dynamic-sandbox.yml). One invocation = one disposable
# analysis lab for exactly one AUR package. Plants canary secrets, fetches the
# package, runs the static analyzer, builds it under `strace` telemetry, and
# assembles an Attestation JSON. Never touches AWS/paid infra — GitHub-hosted
# runner + free Docker Hub image only.
#
# Usage: dynamic_sandbox.sh <package-name>

set -uo pipefail

PKG="${1:?package name required}"
REPO_ROOT="/workspace"
EVIDENCE_DIR="$REPO_ROOT/sandbox-evidence/$PKG"
ATTEST_DIR="$REPO_ROOT/data/attestations/$PKG"

mkdir -p "$EVIDENCE_DIR" "$ATTEST_DIR"

echo "=== AUR-Sentry Disposable Dynamic Sandbox ==="
echo "Package: $PKG"
echo "Evidence dir: $EVIDENCE_DIR"

# ── 1. Prepare the Arch build environment ───────────────────────────────
echo "--- Installing sandbox dependencies ---"
pacman -Syu --noconfirm --needed
pacman -S --noconfirm --needed git rust strace jq python sudo namcap file binutils \
  >"$EVIDENCE_DIR/pacman.log" 2>&1

# ── 2. Build aur-sentry (trusted, our own code — done before canaries/AUR
#       fetch so it doesn't pollute the untrusted-package telemetry) ───────
echo "--- Building aur-sentry ---"
cargo build --release --manifest-path "$REPO_ROOT/Cargo.toml" \
  >"$EVIDENCE_DIR/cargo_build.log" 2>&1
AUR_BIN="$REPO_ROOT/target/release/aur-sentry"
if [ ! -x "$AUR_BIN" ]; then
  echo "::error::failed to build aur-sentry binary" | tee -a "$EVIDENCE_DIR/fatal.log"
  cat "$EVIDENCE_DIR/cargo_build.log"
  exit 1
fi

# ── 3. Create the unprivileged build user (makepkg refuses to run as root) ─
echo "--- Creating unprivileged build user ---"
useradd -m -s /bin/bash builder
echo 'builder ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/builder
chown -R builder:builder "$REPO_ROOT"

# ── 4. Plant canary secrets — obviously fake, clearly labeled. The whole
#       point is to see if a malicious PKGBUILD/.install reads or exfiltrates
#       these during prepare()/pkgver()/build()/package() (build phase) or
#       pre_install/post_install/pre_upgrade/post_upgrade/pre_remove/
#       post_remove (install phase, see section 9d below — same canary
#       content, planted fresh in whatever home directory that phase uses,
#       via this one shared function so the fake-key content lives in
#       exactly one place). ─────────────────────────────────────────────────
plant_canaries() {
  # $1 = home directory to plant into, $2 = owning user (chown target)
  home_dir="$1"
  owner="$2"
  install -d -m 700 "$home_dir/.ssh" "$home_dir/.aws"
  cat > "$home_dir/.ssh/id_fake" <<'EOF'
-----BEGIN OPENSSH PRIVATE KEY-----
CANARY-DO-NOT-USE-THIS-IS-A-FAKE-DECOY-KEY-PLANTED-BY-AUR-SENTRY
CANARY-IF-THIS-VALUE-LEAVES-THE-SANDBOX-THE-PACKAGE-IS-EXFILTRATING-SECRETS
-----END OPENSSH PRIVATE KEY-----
EOF
  cat > "$home_dir/.aws/credentials" <<'EOF'
# CANARY — fake AWS credentials planted by AUR-Sentry's disposable sandbox.
[default]
aws_access_key_id = CANARY_AKIAFAKEFAKEFAKEFAKE
aws_secret_access_key = CANARY_FAKESECRETFAKESECRETFAKESECRETFAKEFAKE
EOF
  chown -R "$owner:$owner" "$home_dir/.ssh" "$home_dir/.aws"
  chmod 600 "$home_dir/.ssh/id_fake" "$home_dir/.aws/credentials"
}

echo "--- Planting canary secrets (build phase) ---"
BUILDER_HOME=/home/builder
plant_canaries "$BUILDER_HOME" builder

CANARY_GITHUB_TOKEN="CANARY_ghp_0000000000000000000000000000FAKE00"
CANARY_AWS_SECRET="CANARY_FAKESECRETFAKESECRETFAKESECRETFAKEFAKE"

# ── 5. Fetch the AUR package source (git clone; no CLI `fetch` subcommand
#       exists in src/main.rs today, so we clone directly like
#       scripts/verify_threat_issue.sh does). ───────────────────────────────
echo "--- Fetching AUR package source ---"
SRC_DIR="$BUILDER_HOME/pkg-src"
FETCH_OK=true
# shellcheck disable=SC2024 # redirect intentionally stays root-owned; only the clone itself drops to builder
sudo -u builder bash -c 'git clone --depth 1 "https://aur.archlinux.org/$1.git" "$2"' \
  _ "$PKG" "$SRC_DIR" >"$EVIDENCE_DIR/fetch.log" 2>&1
if [ ! -f "$SRC_DIR/PKGBUILD" ]; then
  FETCH_OK=false
  echo "::warning::could not fetch a PKGBUILD for '$PKG' — package may not exist or AUR is unreachable"
fi

AUR_COMMIT=""
if [ "$FETCH_OK" = true ]; then
  AUR_COMMIT="$(sudo -u builder git -C "$SRC_DIR" rev-parse HEAD 2>/dev/null || true)"
fi

if [ "$FETCH_OK" != true ]; then
  echo "--- Assembling ANALYSIS_FAILED attestation (fetch failed) ---"
  python3 "$REPO_ROOT/scripts/build_attestation.py" \
    --package "$PKG" \
    --version "unknown" \
    --analysis-failed \
    --note "could not fetch PKGBUILD for '$PKG' from aur.archlinux.org" \
    --output "$ATTEST_DIR/analysis-failed-$(date -u +%Y%m%dT%H%M%SZ).json"
  exit 0
fi

# ── 6. Version metadata — read .SRCINFO (canonical, doesn't require
#       executing the PKGBUILD) rather than sourcing the PKGBUILD itself. ──
PKGVER="unknown"
PKGREL="1"
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
echo "Resolved version: $VERSION (aur commit $AUR_COMMIT)"

# ── 7. Static analysis — run the existing scanner against PKGBUILD/.install
#       BEFORE any dynamic execution. ───────────────────────────────────────
echo "--- Running static analyzer ---"
: > "$EVIDENCE_DIR/static_scan_raw.log"
"$AUR_BIN" scan-file "$SRC_DIR/PKGBUILD" >>"$EVIDENCE_DIR/static_scan_raw.log" 2>&1
for f in "$SRC_DIR"/*.install; do
  [ -e "$f" ] || continue
  "$AUR_BIN" scan-file "$f" >>"$EVIDENCE_DIR/static_scan_raw.log" 2>&1
done
# strip ANSI colour codes (same pattern as scripts/verify_threat_issue.sh)
sed -E 's/\x1b\[[0-9;]*[mK]//g' "$EVIDENCE_DIR/static_scan_raw.log" > "$EVIDENCE_DIR/static_scan.log"

# ── 8. Check strace usability before relying on it — GH-hosted containers
#       sometimes restrict ptrace. Fall back gracefully rather than failing
#       the whole job. ───────────────────────────────────────────────────
echo "--- Checking strace availability ---"
STRACE_OK=true
if ! strace -f -e trace=network,file true >"$EVIDENCE_DIR/strace_check.log" 2>&1; then
  STRACE_OK=false
  echo "::warning::strace is not usable in this runner/container (ptrace likely restricted) — continuing without dynamic telemetry"
  echo "strace unavailable in this environment; dynamic telemetry was not collected for this run." \
    > "$EVIDENCE_DIR/telemetry.unavailable.note"
fi

# ── 9. Build under telemetry. --nodeps avoids pulling arbitrary dependency
#       trees (keeps the job fast/free); --nobuild still executes
#       prepare()/pkgver() where most malicious PKGBUILD payloads live,
#       PKGBUILD is always sourced regardless. ──────────────────────────────
echo "--- Running makepkg (telemetry: $STRACE_OK) ---"
chown -R builder:builder "$SRC_DIR"
# shellcheck disable=SC2016 # single quotes are intentional: $1/$2/$3 expand inside the sudo sub-shell, not here
MAKEPKG_CMD='cd "$1" && GITHUB_TOKEN="$2" AWS_SECRET_ACCESS_KEY="$3" makepkg --noconfirm --nobuild --nodeps --skippgpcheck'
: > "$EVIDENCE_DIR/telemetry.log"
if [ "$STRACE_OK" = true ]; then
  # shellcheck disable=SC2024 # redirect intentionally stays root-owned; only makepkg itself drops to builder
  sudo -u builder strace -f -e trace=network,file -o "$EVIDENCE_DIR/telemetry.log" -- \
    bash -c "$MAKEPKG_CMD" _ "$SRC_DIR" "$CANARY_GITHUB_TOKEN" "$CANARY_AWS_SECRET" \
    >"$EVIDENCE_DIR/makepkg.log" 2>&1
else
  # shellcheck disable=SC2024 # redirect intentionally stays root-owned; only makepkg itself drops to builder
  sudo -u builder bash -c "$MAKEPKG_CMD" _ "$SRC_DIR" "$CANARY_GITHUB_TOKEN" "$CANARY_AWS_SECRET" \
    >"$EVIDENCE_DIR/makepkg.log" 2>&1
fi
MAKEPKG_EXIT=$?
echo "makepkg exit code: $MAKEPKG_EXIT" >> "$EVIDENCE_DIR/makepkg.log"

# ── 9b. Reproducibility check (Phase 3, ARCHITECTURE.md) — run makepkg a
#        SECOND time, independently: a fresh clone of the same AUR source
#        into a fresh directory, then a REAL build (no --nobuild, since you
#        can't diff build *outputs* without an actual output) and diff the
#        produced package file list + per-file sha256 against a first,
#        equally independent build. Both builds still use --nodeps
#        --skippgpcheck to stay fast/free; when a package needs
#        network-fetched deps that --nodeps blocks, the build itself fails
#        and the comparison degrades to UNSUPPORTED rather than failing the
#        whole attestation. This is evidence only — it must never feed the
#        verdict (see verdict_from_findings in src/attestation.rs). ────────
echo "--- Reproducibility check (second independent build) ---"
REPRO_STATUS="NOT_ATTEMPTED"
REPRO_DIR="$EVIDENCE_DIR/reproducibility"
mkdir -p "$REPRO_DIR"

repro_build() {
  # $1 = build slot number (1 or 2). Clones fresh and builds for real
  # (no --nobuild) in its own directory so the two runs never share state.
  n="$1"
  dir="$BUILDER_HOME/pkg-src-repro-$n"
  # shellcheck disable=SC2024 # redirect intentionally stays root-owned; only the clone itself drops to builder
  if ! sudo -u builder bash -c 'git clone --depth 1 "https://aur.archlinux.org/$1.git" "$2"' \
    _ "$PKG" "$dir" >"$REPRO_DIR/clone-$n.log" 2>&1; then
    return 1
  fi
  [ -f "$dir/PKGBUILD" ] || return 1
  chown -R builder:builder "$dir"
  # shellcheck disable=SC2016 # single quotes intentional: $1 expands inside the sudo sub-shell, not here
  # shellcheck disable=SC2024 # redirect intentionally stays root-owned; only makepkg itself drops to builder
  if ! sudo -u builder bash -c 'cd "$1" && makepkg --noconfirm --nodeps --skippgpcheck' \
    _ "$dir" >"$REPRO_DIR/makepkg-$n.log" 2>&1; then
    return 1
  fi
  find "$dir" -maxdepth 1 -name '*.pkg.tar.*' -printf '%f\n' 2>/dev/null | sort > "$REPRO_DIR/filelist-$n.txt"
  : > "$REPRO_DIR/hashes-$n.txt"
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    sha256sum "$dir/$f" | awk '{print $1}' >> "$REPRO_DIR/hashes-$n.txt"
  done < "$REPRO_DIR/filelist-$n.txt"
  [ -s "$REPRO_DIR/filelist-$n.txt" ]
}

if repro_build 1 && repro_build 2; then
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
echo "Reproducibility status: $REPRO_STATUS"

# ── 9c. Package-content & ELF analysis (ARCHITECTURE.md sections 12-13) —
#        reuse one of the two real *.pkg.tar.* files the reproducibility
#        step above already built (no third build). Extracted with
#        bsdtar/tar (both ship with archlinux:base-devel via libarchive),
#        then a pragmatic, cheap pass: total file count, ELF count via
#        `file`, per-ELF arch/stripped/PIE via `file`+`readelf -h`, and
#        setuid/setgid/world-writable file detection via `find -perm`. No
#        symbol/import analysis or entropy scoring — kept deliberately
#        lightweight for a free-tier GitHub Actions runner. Degrades to
#        "unavailable" (not a failure) if no package file exists, e.g. both
#        reproducibility builds failed (REPRO_STATUS=UNSUPPORTED). ─────────
echo "--- Package-content & ELF analysis ---"
PKG_ANALYSIS_JSON="$EVIDENCE_DIR/package_analysis.json"
PKG_ANALYSIS_AVAILABLE=false

PKG_FILE=""
for n in 1 2; do
  [ -n "$PKG_FILE" ] && break
  flist="$REPRO_DIR/filelist-$n.txt"
  [ -s "$flist" ] || continue
  candidate="$BUILDER_HOME/pkg-src-repro-$n/$(head -n1 "$flist")"
  [ -f "$candidate" ] && PKG_FILE="$candidate"
done

if [ -n "$PKG_FILE" ]; then
  echo "Analyzing package: $PKG_FILE"
  EXTRACT_DIR="$EVIDENCE_DIR/pkg-extract"
  rm -rf "$EXTRACT_DIR"
  mkdir -p "$EXTRACT_DIR"
  EXTRACT_OK=false
  if command -v bsdtar >/dev/null 2>&1; then
    bsdtar -xf "$PKG_FILE" -C "$EXTRACT_DIR" >"$EVIDENCE_DIR/pkg_extract.log" 2>&1 && EXTRACT_OK=true
  elif command -v tar >/dev/null 2>&1; then
    tar -xf "$PKG_FILE" -C "$EXTRACT_DIR" >"$EVIDENCE_DIR/pkg_extract.log" 2>&1 && EXTRACT_OK=true
  else
    echo "::warning::neither bsdtar nor tar is available — skipping package-content analysis" \
      | tee -a "$EVIDENCE_DIR/pkg_extract.log"
  fi

  if [ "$EXTRACT_OK" = true ]; then
    FILE_COUNT="$(find "$EXTRACT_DIR" -type f | wc -l)"

    SETUID_LIST="$EVIDENCE_DIR/setuid_files.txt"
    WW_LIST="$EVIDENCE_DIR/world_writable_files.txt"
    find "$EXTRACT_DIR" \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null \
      | sed "s|^$EXTRACT_DIR/||" > "$SETUID_LIST"
    find "$EXTRACT_DIR" -perm -0002 -type f 2>/dev/null \
      | sed "s|^$EXTRACT_DIR/||" > "$WW_LIST"

    ELF_OBJECTS_JSONL="$EVIDENCE_DIR/elf_objects.jsonl"
    : > "$ELF_OBJECTS_JSONL"
    ELF_COUNT=0
    while IFS= read -r -d '' f; do
      FOUT="$(file -b "$f" 2>/dev/null)"
      case "$FOUT" in
        *ELF*)
          ELF_COUNT=$((ELF_COUNT + 1))
          rel="${f#"$EXTRACT_DIR"/}"
          ARCH="unknown"
          if command -v readelf >/dev/null 2>&1; then
            ARCH="$(readelf -h "$f" 2>/dev/null | awk -F': *' '/Machine:/{print $2; exit}')"
            [ -n "$ARCH" ] || ARCH="unknown"
          fi
          STRIPPED=false
          case "$FOUT" in *"not stripped"*) STRIPPED=false ;; *stripped*) STRIPPED=true ;; esac
          PIE=false
          case "$FOUT" in *"pie executable"*|*"shared object"*) PIE=true ;; esac
          jq -n --arg path "$rel" --arg arch "$ARCH" \
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
  else
    echo "::warning::failed to extract '$PKG_FILE' for package-content analysis"
  fi
else
  echo "::warning::no built package available for package-content analysis (reproducibility status: $REPRO_STATUS)"
fi

if [ "$PKG_ANALYSIS_AVAILABLE" != true ]; then
  jq -n '{available:false, file_count:0, elf_object_count:0, elf_objects:[], setuid_files:0, world_writable_files:0, setuid_paths:[], world_writable_paths:[]}' \
    > "$PKG_ANALYSIS_JSON"
fi
echo "Package analysis available: $PKG_ANALYSIS_AVAILABLE"

# ── 9d. Install-phase dynamic sandbox pass — the gap called out in
#        ARCHITECTURE.md's "Known gaps" / section 11: "PKGBUILD build
#        behavior and package installation behavior are not necessarily the
#        same thing." Everything above observes `makepkg` (prepare/build/
#        package); this step actually runs `pacman -U` on one of the real
#        *.pkg.tar.* files the reproducibility step already built (no third
#        build — reuses $PKG_FILE from the package-content analysis above),
#        so `.install` hooks (pre_install/post_install/pre_upgrade/
#        post_upgrade) execute for real under the same strace telemetry
#        categories as the build phase. `pacman -U` needs root (unlike
#        makepkg, which refuses to run as root), so unlike every other step
#        in this script this one runs directly as root rather than dropping
#        to the unprivileged `builder` user — that's fine, the container is
#        disposable either way. Canary secrets are planted fresh into /root
#        (same fake content as the build phase, via plant_canaries) since
#        `.install` scripts can probe for credentials too. Also runs
#        `pacman -R` afterward, under the same telemetry, to observe
#        pre_remove/post_remove — cheap given the container is disposable
#        regardless. Degrades to "skipped" (not a failure) when no built
#        package file exists, e.g. both reproducibility builds failed. ─────
echo "--- Install-phase dynamic sandbox pass ---"
INSTALL_TELEMETRY_LOG="$EVIDENCE_DIR/install_telemetry.log"
: > "$INSTALL_TELEMETRY_LOG"
INSTALL_PHASE_RAN=false
PACMAN_INSTALL_EXIT=""

if [ -n "$PKG_FILE" ] && [ -f "$PKG_FILE" ]; then
  echo "--- Planting canary secrets (install phase) ---"
  plant_canaries /root root

  echo "Installing built package: $PKG_FILE"
  # shellcheck disable=SC2016 # single quotes intentional: $1/$2/$3 expand inside the bash -c sub-shell, not here
  INSTALL_CMD='GITHUB_TOKEN="$2" AWS_SECRET_ACCESS_KEY="$3" pacman -U --noconfirm "$1"'
  if [ "$STRACE_OK" = true ]; then
    strace -f -e trace=network,file -o "$INSTALL_TELEMETRY_LOG" -- \
      bash -c "$INSTALL_CMD" _ "$PKG_FILE" "$CANARY_GITHUB_TOKEN" "$CANARY_AWS_SECRET" \
      >"$EVIDENCE_DIR/pacman_install.log" 2>&1
  else
    bash -c "$INSTALL_CMD" _ "$PKG_FILE" "$CANARY_GITHUB_TOKEN" "$CANARY_AWS_SECRET" \
      >"$EVIDENCE_DIR/pacman_install.log" 2>&1
  fi
  PACMAN_INSTALL_EXIT=$?
  echo "pacman -U exit code: $PACMAN_INSTALL_EXIT" >> "$EVIDENCE_DIR/pacman_install.log"
  INSTALL_PHASE_RAN=true

  if [ "$PACMAN_INSTALL_EXIT" -eq 0 ]; then
    INSTALLED_PKGNAME="$(pacman -Qp "$PKG_FILE" 2>/dev/null | awk '{print $1}')"
    if [ -n "$INSTALLED_PKGNAME" ]; then
      echo "--- Removal-phase telemetry (pacman -R): $INSTALLED_PKGNAME ---"
      REMOVE_TELEMETRY_LOG="$EVIDENCE_DIR/install_telemetry_remove.log"
      # shellcheck disable=SC2016 # single quotes intentional: $1 expands inside the bash -c sub-shell, not here
      REMOVE_CMD='pacman -R --noconfirm "$1"'
      if [ "$STRACE_OK" = true ]; then
        strace -f -e trace=network,file -o "$REMOVE_TELEMETRY_LOG" -- \
          bash -c "$REMOVE_CMD" _ "$INSTALLED_PKGNAME" \
          >"$EVIDENCE_DIR/pacman_remove.log" 2>&1
      else
        bash -c "$REMOVE_CMD" _ "$INSTALLED_PKGNAME" \
          >"$EVIDENCE_DIR/pacman_remove.log" 2>&1
      fi
      echo "pacman -R exit code: $?" >> "$EVIDENCE_DIR/pacman_remove.log"
      # Fold removal-phase telemetry into the same install_telemetry.log so
      # `aur-sentry attest --install-telemetry` sees both pre_remove/
      # post_remove and pre_install/post_install in one pass.
      if [ -f "$REMOVE_TELEMETRY_LOG" ]; then
        cat "$REMOVE_TELEMETRY_LOG" >> "$INSTALL_TELEMETRY_LOG"
        rm -f "$REMOVE_TELEMETRY_LOG"
      fi
    else
      echo "::warning::could not determine installed package name from '$PKG_FILE' — skipping pacman -R removal-phase telemetry"
    fi
  else
    echo "::warning::pacman -U exited $PACMAN_INSTALL_EXIT — skipping removal-phase telemetry"
  fi
else
  echo "::warning::no built package available for install-phase sandbox pass (reproducibility status: $REPRO_STATUS) — skipping"
fi
echo "Install-phase pass ran: $INSTALL_PHASE_RAN"

# ── 9e. External intelligence — OSV.dev vulnerability correlation. Purely
#        evidence, never verdict-deciding (see ARCHITECTURE.md's "external
#        intelligence" note and src/attest.rs's `parse_external_intelligence`
#        doc comment). OSV.dev has NO "Arch"/"AUR" ecosystem (verified
#        against the OSV schema docs before writing this), so there is no
#        honest way to query it for an AUR package's own dependency graph in
#        general. What's genuinely queryable, cheaply and for free:
#          - each depends()/makedepends() name from .SRCINFO (version
#            constraints stripped), tried against OSV's PyPI/npm/crates.io
#            ecosystems in case the same name happens to also be a package
#            there — a name-collision guess, low-yield but occasionally real
#          - if PKGBUILD's url= is a github.com repo, its Go-module form
#            (github.com/owner/repo) tried against OSV's Go ecosystem — this
#            one is an EXACT identity match, not a guess, because Go module
#            names are literally their GitHub path, so this is the most
#            reliable signal this step produces (and only fires for
#            Go-based AUR packages)
#        Realistic expectation: for most AUR packages (shell scripts, C/C++
#        tools with system-library deps, etc.) this whole step will find
#        nothing, and external_intel.json will be `[]`. That's an honest
#        result, not a bug. ───────────────────────────────────────────────
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
    # Batch results only carry vuln IDs — fetch full advisories (capped, so
    # a package with many hits can't turn this into an unbounded loop) for
    # a human-readable summary/url per match.
    HIT_IDS="$(jq -r '[.results[]?.vulns[]?.id] | unique | .[:10][]' \
      "$OSV_RESPONSE_JSON" 2>/dev/null)"
    if [ -n "$HIT_IDS" ]; then
      while IFS= read -r vid; do
        [ -z "$vid" ] && continue
        vuln_json="$EVIDENCE_DIR/osv_vuln_$vid.json"
        if curl -fsS -m 15 "https://api.osv.dev/v1/vulns/$vid" \
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

# ── 10. Assemble the attestation. Prefer the real CLI (`aur-sentry attest`)
#        once src/attestation.rs lands; otherwise use the standalone Python
#        fallback assembler so this workflow stays runnable today.
#        TODO(attestation.rs): once `aur-sentry attest` exists, drop the
#        Python fallback branch below and always use the native CLI path.
echo "--- Assembling attestation ---"
OUTPUT_JSON="$ATTEST_DIR/$VERSION.json"
if "$AUR_BIN" attest --help >/dev/null 2>&1; then
  echo "Using native 'aur-sentry attest' CLI"
  ATTEST_ARGS=(
    "$PKG"
    --version "$VERSION"
    --arch x86_64
    --aur-commit "$AUR_COMMIT"
    --pkgbuild "$SRC_DIR/PKGBUILD"
    --static-findings "$EVIDENCE_DIR/static_scan.log"
    --telemetry "$EVIDENCE_DIR/telemetry.log"
    --package-analysis "$PKG_ANALYSIS_JSON"
    --external-intel "$EXTERNAL_INTEL_JSON"
    --makepkg-exit "$MAKEPKG_EXIT"
    --reproducibility-status "$REPRO_STATUS"
    --output "$OUTPUT_JSON"
  )
  [ "$STRACE_OK" = true ] && ATTEST_ARGS+=(--strace-available)
  for f in "$SRC_DIR"/*.install; do
    [ -e "$f" ] || continue
    ATTEST_ARGS+=(--install-file "$f")
    break
  done
  # Install-phase evidence (section 9d above) — omitted entirely when that
  # pass didn't run (no built package file), matching --install-file's
  # "only pass what actually exists" pattern rather than pointing at an
  # empty file.
  [ "$INSTALL_PHASE_RAN" = true ] && ATTEST_ARGS+=(--install-telemetry "$INSTALL_TELEMETRY_LOG")
  "$AUR_BIN" attest "${ATTEST_ARGS[@]}"
else
  echo "'aur-sentry attest' not available yet — using Python fallback assembler"
  python3 "$REPO_ROOT/scripts/build_attestation.py" \
    --package "$PKG" \
    --version "$VERSION" \
    --arch x86_64 \
    --aur-commit "$AUR_COMMIT" \
    --pkgbuild "$SRC_DIR/PKGBUILD" \
    --install-glob "$SRC_DIR"/*.install \
    --static-log "$EVIDENCE_DIR/static_scan.log" \
    --telemetry-log "$EVIDENCE_DIR/telemetry.log" \
    --strace-available "$STRACE_OK" \
    --makepkg-exit "$MAKEPKG_EXIT" \
    --reproducibility-status "$REPRO_STATUS" \
    --output "$OUTPUT_JSON"
fi

echo "=== Sandbox complete: $OUTPUT_JSON ==="
cat "$OUTPUT_JSON" 2>/dev/null || true
exit 0
