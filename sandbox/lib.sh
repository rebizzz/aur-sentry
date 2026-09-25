#!/usr/bin/env bash
# sandbox/lib.sh — shared helpers for the in-container sandbox scripts
# (sandbox/build.sh, sandbox/install.sh). Baked into the sandbox image at
# /opt/aur-sentry-sandbox/ by sandbox/Containerfile; never sourced on the host.
#
# Evidence channel contract (see ARCHITECTURE.md "Append-only evidence"):
#   fd 1 (container stdout) -> host file, human-readable log (makepkg.log, ...)
#   fd 3                    -> the ORIGINAL container stderr, which the host
#                              captures as telemetry.log / install_telemetry.log.
#                              Only strace writes here. Scripts call
#                              `evidence_channel_init` first, which moves
#                              fd 2 onto stdout so nothing else leaks into it.
# The traced command closes every fd > 2 before exec'ing, so the package
# under analysis never holds a handle to the telemetry stream: strace lines
# already written to the pipe cannot be retracted from inside the container.

# shellcheck disable=SC2034 # consumed by the scripts that source this file
CANARY_GITHUB_TOKEN="CANARY_ghp_0000000000000000000000000000FAKE00"
# shellcheck disable=SC2034
CANARY_AWS_SECRET="CANARY_FAKESECRETFAKESECRETFAKESECRETFAKEFAKE"

TRACE_SYSCALLS="network,file,process"

log() { printf '=== %s\n' "$*"; }
warn() { printf '::warning::%s\n' "$*"; }

# Save the container's stderr as fd 3 (telemetry channel) and fold fd 2 into
# stdout for everything else this script runs.
evidence_channel_init() {
  exec 3>&2 2>&1
}

# plant_canaries <home_dir> <owner>
# Obviously fake, clearly labeled decoy secrets. If a PKGBUILD or .install
# script reads or exfiltrates these, the strace telemetry shows it.
plant_canaries() {
  local home_dir="$1" owner="$2"
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

# run_traced <user> <cmd> [args...]
#
# The one place that decides "strace or plain". With SANDBOX_STRACE=1, strace
# runs as ROOT and drops only the tracee to <user> (`-u`), so the traced code
# can neither kill strace nor touch its output. strace writes to fd 3 (the
# host-captured stderr). Without strace (ptrace unavailable), the command
# still runs as <user>, just without telemetry — same graceful degradation
# as before. Returns the command's exit status (strace propagates it).
run_traced() {
  local user="$1"
  shift
  # Inner wrapper, runs before any untrusted code: fold stderr into stdout
  # and close every inherited fd above 2 (including any handle on fd 3).
  # shellcheck disable=SC2016 # expanded by the inner bash, not here
  local -a wrap=(bash -c '
    exec 2>&1
    for fd in /proc/$$/fd/*; do
      fd="${fd##*/}"
      case "$fd" in ""|*[!0-9]*) continue ;; esac
      [ "$fd" -gt 2 ] && eval "exec $fd>&-"
    done
    exec "$@"' aur-sentry-traced)

  if [ "${SANDBOX_STRACE:-0}" = 1 ]; then
    local -a as_user=()
    [ "$user" = root ] || as_user=(-u "$user")
    strace -f "${as_user[@]}" -e "trace=$TRACE_SYSCALLS" -o /proc/self/fd/3 -- "${wrap[@]}" "$@"
  elif [ "$user" = root ]; then
    "${wrap[@]}" "$@" 3>&-
  else
    runuser -u "$user" -- "${wrap[@]}" "$@" 3>&-
  fi
}

# copy_source <src_dir> <dest_dir> <owner>
# Copies the read-only package snapshot into a container-local build dir.
# Regular files only (no symlinks, no subdirectories) — the AUR itself
# forbids subdirectories, and a symlinked PKGBUILD must never be followed.
copy_source() {
  local src="$1" dest="$2" owner="$3" f
  install -d -o "$owner" -g "$owner" "$dest"
  for f in "$src"/* "$src"/.SRCINFO; do
    [ -f "$f" ] && [ ! -L "$f" ] || continue
    case "${f##*/}" in request.json) continue ;; esac
    cp --no-dereference -- "$f" "$dest/"
  done
  chown -R "$owner:$owner" "$dest"
}
