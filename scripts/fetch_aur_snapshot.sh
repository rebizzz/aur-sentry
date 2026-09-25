#!/usr/bin/env bash
# scripts/fetch_aur_snapshot.sh
#
# Fetches one AUR package's git repo (shallow) and copies its top-level
# regular files (PKGBUILD, .SRCINFO, *.install, and any local source files
# the PKGBUILD's source=() references, like patches) into <dest_dir>.
# Symlinks, subdirectories and .git are never copied. Nothing is executed.
# Prints the AUR HEAD commit sha on stdout.
#
# Used by scripts/open_scan_pr.sh (to build the scan PR snapshot) and by
# .github/workflows/scan.yml for manual runs that have no scan PR.
#
# Usage: scripts/fetch_aur_snapshot.sh <package> <dest_dir>

set -euo pipefail

PKG="${1:?package name required}"
DEST="${2:?destination dir required}"
MAX_FILE_BYTES=$((5 * 1024 * 1024))

if ! printf '%s' "$PKG" | grep -Eq '^[A-Za-z0-9@_+][A-Za-z0-9@._+-]{0,127}$'; then
  echo "error: invalid package name '$PKG'" >&2
  exit 1
fi

TMP="$(mktemp -d "${TMPDIR:-/tmp}/aur_snapshot_XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

if ! GIT_TERMINAL_PROMPT=0 git clone --quiet --depth 1 --no-tags \
  "https://aur.archlinux.org/${PKG}.git" "$TMP/aur" >&2; then
  echo "error: git clone of AUR package '$PKG' failed" >&2
  exit 1
fi
if [ ! -f "$TMP/aur/PKGBUILD" ] || [ -L "$TMP/aur/PKGBUILD" ]; then
  echo "error: AUR package '$PKG' has no regular PKGBUILD (package may not exist)" >&2
  exit 1
fi

SHA="$(git -C "$TMP/aur" rev-parse HEAD)"

mkdir -p "$DEST"
for f in "$TMP/aur"/* "$TMP/aur"/.SRCINFO; do
  [ -f "$f" ] && [ ! -L "$f" ] || continue
  name="${f##*/}"
  case "$name" in request.json) continue ;; esac
  if [ "$(stat -c %s "$f")" -gt "$MAX_FILE_BYTES" ]; then
    echo "warning: skipping oversized file '$name'" >&2
    continue
  fi
  cp -- "$f" "$DEST/$name"
done

printf '%s\n' "$SHA"
