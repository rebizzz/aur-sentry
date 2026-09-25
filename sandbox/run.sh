#!/usr/bin/env bash
# sandbox/run.sh — HOST-side orchestrator for one package's dynamic analysis.
# Called by the untrusted `sandbox` job in .github/workflows/scan.yml (which
# holds only a read-only token) and usable locally for smoke tests.
#
# Usage: sandbox/run.sh <package> <src_dir> <evidence_dir>
#
#   <src_dir>       the package snapshot (scans/<pkg>/): PKGBUILD, .SRCINFO,
#                   *.install, request.json. Mounted READ-ONLY into the build
#                   containers; nothing else from the repo is ever mounted.
#   <evidence_dir>  host-only directory the evidence is written to. No
#                   container can see it: container stdout/stderr are
#                   redirected into files here by this script.
#
# Env (all optional):
#   AUR_SENTRY_BIN     aur-sentry binary for host_analyze.sh (default: target/release/aur-sentry)
#   AUR_COMMIT         AUR commit of the snapshot (default: from request.json)
#   SANDBOX_IMAGE      image tag to build/use (default aur-sentry-sandbox:local)
#   SANDBOX_WORK       scratch dir for built packages (default: mktemp under $RUNNER_TEMP)
#   SANDBOX_TIMEOUT    per-container timeout, `timeout` syntax (default 15m)
#
# Container layout (the whole point of the redesign):
#   build (trace)  -v <src>:/src:ro                         stdout>makepkg.log  stderr>telemetry.log
#   build (repro)  -v <src>:/src:ro -v <work>/repro-N:/out  stdout+stderr>reproducibility/makepkg-N.log
#   install        -v <work>/install-pkg:/pkg:ro            stdout>pacman_install.log  stderr>install_telemetry.log
# All with --cap-add SYS_PTRACE (root strace traces the unprivileged
# tracee), --security-opt no-new-privileges and a pids limit.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

PKG="${1:?package name required}"
SRC_DIR="${2:?source snapshot dir required}"
EVIDENCE_DIR="${3:?evidence dir required}"

if ! printf '%s' "$PKG" | grep -Eq '^[A-Za-z0-9@_+][A-Za-z0-9@._+-]{0,127}$'; then
  echo "::error::invalid package name '$PKG'"
  exit 1
fi
if [ ! -f "$SRC_DIR/PKGBUILD" ] || [ -L "$SRC_DIR/PKGBUILD" ]; then
  echo "::error::no regular PKGBUILD in $SRC_DIR"
  exit 1
fi

SRC_DIR="$(cd "$SRC_DIR" && pwd)"
mkdir -p "$EVIDENCE_DIR"
EVIDENCE_DIR="$(cd "$EVIDENCE_DIR" && pwd)"
IMAGE="${SANDBOX_IMAGE:-aur-sentry-sandbox:local}"
TIMEOUT="${SANDBOX_TIMEOUT:-15m}"
WORK="${SANDBOX_WORK:-$(mktemp -d "${RUNNER_TEMP:-/tmp}/aur-sentry-sandbox.XXXXXX")}"
mkdir -p "$WORK"
REPRO_DIR="$EVIDENCE_DIR/reproducibility"
mkdir -p "$REPRO_DIR"

echo "=== AUR-Sentry disposable dynamic sandbox ==="
echo "Package: $PKG"
echo "Source snapshot (read-only in containers): $SRC_DIR"
echo "Evidence dir (host-only): $EVIDENCE_DIR"
echo "Scratch dir: $WORK"

# ── 1. Build the sandbox image (pacman -Syu + strace/git + builder user) ──
echo "--- Building sandbox image $IMAGE ---"
if ! docker build --pull -t "$IMAGE" -f "$SCRIPT_DIR/Containerfile" "$SCRIPT_DIR" \
  >"$EVIDENCE_DIR/pacman.log" 2>&1; then
  echo "::error::failed to build sandbox image" | tee -a "$EVIDENCE_DIR/fatal.log"
  tail -n 50 "$EVIDENCE_DIR/pacman.log"
  exit 1
fi

# ── 2. ptrace probe — run before any untrusted code, so the package cannot
#       influence whether telemetry is considered available. ─────────────
echo "--- Checking strace availability ---"
STRACE_OK=false
if docker run --rm --cap-add SYS_PTRACE "$IMAGE" \
  strace -f -e trace=network,file,process -o /dev/null true \
  >"$EVIDENCE_DIR/strace_check.log" 2>&1; then
  STRACE_OK=true
else
  echo "::warning::strace is not usable in this runner/container (ptrace likely restricted) — continuing without dynamic telemetry"
  echo "strace unavailable in this environment; dynamic telemetry was not collected for this run." \
    > "$EVIDENCE_DIR/telemetry.unavailable.note"
fi
SANDBOX_STRACE=0
[ "$STRACE_OK" = true ] && SANDBOX_STRACE=1

# sandbox_run <label> <stdout_file> <stderr_file> [docker run args...]
# One disposable container. Its stdout/stderr go straight into host files;
# the container has no path to either file.
sandbox_run() {
  local label="$1" out="$2" err="$3" name rc
  shift 3
  name="aur-sentry-sbx-$$-$label"
  timeout "$TIMEOUT" docker run --name "$name" \
    --cap-add SYS_PTRACE \
    --security-opt no-new-privileges \
    --pids-limit 4096 \
    -e SANDBOX_STRACE="$SANDBOX_STRACE" \
    "$@" >"$out" 2>"$err"
  rc=$?
  docker rm -f "$name" >/dev/null 2>&1
  [ "$rc" -eq 124 ] && echo "::warning::container '$label' timed out after $TIMEOUT"
  return "$rc"
}

# ── 3. Build under telemetry (container A). --nobuild still executes
#       prepare()/pkgver() and fetches sources; the PKGBUILD is always
#       sourced. strace output streams to this host's telemetry.log. ──────
echo "--- Running makepkg --nobuild (telemetry: $STRACE_OK) ---"
sandbox_run trace "$EVIDENCE_DIR/makepkg.log" "$EVIDENCE_DIR/telemetry.log" \
  -v "$SRC_DIR:/src:ro" \
  "$IMAGE" bash /opt/aur-sentry-sandbox/build.sh trace
MAKEPKG_EXIT=$?
echo "makepkg exit code: $MAKEPKG_EXIT" >> "$EVIDENCE_DIR/makepkg.log"
echo "makepkg exit code: $MAKEPKG_EXIT"

# ── 4. Reproducibility: two independent real builds, each in its own fresh
#       container writing only to its own scratch dir. Evidence only — it
#       never feeds the verdict. ───────────────────────────────────────────
echo "--- Reproducibility check (two independent builds) ---"
for n in 1 2; do
  mkdir -p "$WORK/repro-$n"
  sandbox_run "repro$n" "$REPRO_DIR/makepkg-$n.log" "$REPRO_DIR/makepkg-$n.stderr.log" \
    -v "$SRC_DIR:/src:ro" -v "$WORK/repro-$n:/out" \
    "$IMAGE" bash /opt/aur-sentry-sandbox/build.sh repro
  echo "$?" > "$REPRO_DIR/exit-$n.txt"
done

# Package reused by the install pass and the package/ELF analysis (no third build).
PKG_FILE=""
for n in 1 2; do
  [ -n "$PKG_FILE" ] && break
  first="$(find "$WORK/repro-$n" -maxdepth 1 -type f -name '*.pkg.tar.*' -printf '%f\n' 2>/dev/null | sort | head -n1)"
  [ -n "$first" ] && PKG_FILE="$WORK/repro-$n/$first"
done

# ── 5. Install phase (container B): fresh container, root pacman -U / -R,
#       strace streamed to install_telemetry.log the same way. ─────────────
echo "--- Install-phase dynamic sandbox pass ---"
INSTALL_PHASE_RAN=false
INSTALL_EXIT=""
if [ -n "$PKG_FILE" ]; then
  rm -rf "$WORK/install-pkg"
  mkdir -p "$WORK/install-pkg"
  cp -- "$PKG_FILE" "$WORK/install-pkg/"
  sandbox_run install "$WORK/install-stdout.log" "$EVIDENCE_DIR/install_telemetry.log" \
    -v "$WORK/install-pkg:/pkg:ro" \
    "$IMAGE" bash /opt/aur-sentry-sandbox/install.sh
  INSTALL_EXIT=$?
  INSTALL_PHASE_RAN=true
  # Split the combined stdout at the removal marker (informational logs only).
  awk -v inst="$EVIDENCE_DIR/pacman_install.log" -v rem="$EVIDENCE_DIR/pacman_remove.log" '
    !seen && $0 == "=== AUR-SENTRY-REMOVE-PHASE ===" { seen = 1; next }
    { print > (seen ? rem : inst) }' "$WORK/install-stdout.log"
  echo "pacman -U exit code: $INSTALL_EXIT" >> "$EVIDENCE_DIR/pacman_install.log"
else
  echo "::warning::no built package available for install-phase sandbox pass — skipping"
fi
echo "Install-phase pass ran: $INSTALL_PHASE_RAN"

# ── 6. Host-side analysis: static scan, repro diff, package/ELF, OSV, meta ─
export PKG SRC_DIR EVIDENCE_DIR WORK PKG_FILE MAKEPKG_EXIT STRACE_OK INSTALL_PHASE_RAN INSTALL_EXIT
export AUR_SENTRY_BIN="${AUR_SENTRY_BIN:-$REPO_ROOT/target/release/aur-sentry}"
bash "$SCRIPT_DIR/host_analyze.sh"
