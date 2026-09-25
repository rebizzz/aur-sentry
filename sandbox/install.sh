#!/usr/bin/env bash
# sandbox/install.sh — runs INSIDE a fresh disposable sandbox container,
# separate from the build containers. Orchestrated by sandbox/run.sh.
#
# Install-phase dynamic pass: `pacman -U` on the package a reproducibility
# build produced, so .install hooks (pre_install/post_install/...) execute for
# real under strace, then `pacman -R` to observe pre_remove/post_remove.
# pacman needs root, so the hooks run as root — but in a container that has
# never held anything worth stealing, and strace streams to the host-captured
# stderr, so root in here can add lines to the telemetry but never retract
# them.
#
# Mounts: /pkg read-only, containing exactly one *.pkg.tar.* file.
# stdout -> host pacman_install.log (removal output follows a marker line
#           and is split into pacman_remove.log by the host)
# fd 3/stderr -> host install_telemetry.log (install + removal, one stream)
# Exit status = pacman -U's exit status.

set -uo pipefail

# shellcheck source=sandbox/lib.sh
. /opt/aur-sentry-sandbox/lib.sh
evidence_channel_init

PKG_FILE=""
for f in /pkg/*.pkg.tar.*; do
  if [ ! -f "$f" ] || [ -L "$f" ]; then continue; fi
  PKG_FILE="$f"
  break
done
if [ -z "$PKG_FILE" ]; then
  echo "::error::no package file mounted at /pkg"
  exit 1
fi

log "Planting canary secrets (install phase)"
plant_canaries /root root

log "Installing built package: ${PKG_FILE##*/} (telemetry: ${SANDBOX_STRACE:-0})"
run_traced root env \
  GITHUB_TOKEN="$CANARY_GITHUB_TOKEN" AWS_SECRET_ACCESS_KEY="$CANARY_AWS_SECRET" \
  pacman -U --noconfirm "$PKG_FILE"
INSTALL_EXIT=$?
log "pacman -U exit code: $INSTALL_EXIT"

if [ "$INSTALL_EXIT" -eq 0 ]; then
  INSTALLED_PKGNAME="$(pacman -Qp "$PKG_FILE" 2>/dev/null | awk '{print $1}')"
  if [ -n "$INSTALLED_PKGNAME" ]; then
    echo "=== AUR-SENTRY-REMOVE-PHASE ==="
    log "Removal-phase telemetry (pacman -R): $INSTALLED_PKGNAME"
    run_traced root pacman -R --noconfirm "$INSTALLED_PKGNAME"
    log "pacman -R exit code: $?"
  else
    warn "could not determine installed package name — skipping pacman -R removal-phase telemetry"
  fi
else
  warn "pacman -U exited $INSTALL_EXIT — skipping removal-phase telemetry"
fi

exit "$INSTALL_EXIT"
