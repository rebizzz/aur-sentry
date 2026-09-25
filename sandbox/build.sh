#!/usr/bin/env bash
# sandbox/build.sh — runs INSIDE a disposable sandbox container (image built
# from sandbox/Containerfile). Orchestrated from the host by sandbox/run.sh.
#
# Usage (inside the container):
#   build.sh trace   # makepkg --nobuild under strace (prepare()/pkgver() and
#                    # source fetching, where most PKGBUILD payloads live).
#                    # stdout -> host makepkg.log, fd 3/stderr -> host telemetry.log
#   build.sh repro   # one real makepkg build (no strace) for the
#                    # reproducibility comparison; built *.pkg.tar.* files are
#                    # copied (by root, after makepkg exits) into /out
#
# Mounts (set up by the host, nothing else is visible):
#   /src  read-only  scans/<pkg>/ snapshot (PKGBUILD, .SRCINFO, *.install, ...)
#   /out  writable   repro mode only: scratch dir for the built package
#
# Exit status = makepkg's exit status (the host records it; nothing printed
# by the package can change it).
#
# Env: SANDBOX_STRACE=1|0 (decided by the host's ptrace probe).

set -uo pipefail

# shellcheck source=sandbox/lib.sh
. /opt/aur-sentry-sandbox/lib.sh
evidence_channel_init

MODE="${1:?mode required: trace|repro}"
BUILDER_HOME=/home/builder
BUILD_DIR="$BUILDER_HOME/build"

log "AUR-Sentry sandbox build ($MODE), strace=${SANDBOX_STRACE:-0}"

if [ ! -f /src/PKGBUILD ]; then
  echo "::error::no PKGBUILD in /src"
  exit 1
fi

# Container-local copy; /src stays read-only and untouched.
copy_source /src "$BUILD_DIR" builder

log "Planting canary secrets (build phase)"
plant_canaries "$BUILDER_HOME" builder

# --nodeps avoids pulling arbitrary dependency trees (keeps the job fast and
# free). Packages whose build needs a dependency that --nodeps blocks fail
# the build, which degrades to BUILD_FAILED / UNSUPPORTED on the host side.
case "$MODE" in
  trace)
    log "Running makepkg --nobuild (telemetry: ${SANDBOX_STRACE:-0})"
    run_traced builder env -C "$BUILD_DIR" \
      HOME="$BUILDER_HOME" USER=builder LOGNAME=builder \
      GITHUB_TOKEN="$CANARY_GITHUB_TOKEN" AWS_SECRET_ACCESS_KEY="$CANARY_AWS_SECRET" \
      makepkg --noconfirm --nobuild --nodeps --skippgpcheck
    rc=$?
    log "makepkg exit code: $rc"
    exit "$rc"
    ;;
  repro)
    log "Running full makepkg build (reproducibility slot)"
    SANDBOX_STRACE=0 run_traced builder env -C "$BUILD_DIR" \
      HOME="$BUILDER_HOME" USER=builder LOGNAME=builder \
      makepkg --noconfirm --nodeps --skippgpcheck
    rc=$?
    log "makepkg exit code: $rc"
    if [ "$rc" -eq 0 ] && [ -d /out ]; then
      # Copied by root after makepkg has exited; regular files only.
      find "$BUILD_DIR" -maxdepth 1 -type f -name '*.pkg.tar.*' \
        -exec cp --no-dereference -t /out {} +
    fi
    exit "$rc"
    ;;
  *)
    echo "::error::unknown mode '$MODE'"
    exit 1
    ;;
esac
