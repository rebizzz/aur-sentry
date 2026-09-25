#!/usr/bin/env bash
# scripts/verify_attestation.sh
#
# Independently verifies a published AUR-Sentry attestation's Sigstore
# signature. Attestations are signed keylessly by the trusted `finalize` job
# of .github/workflows/scan.yml using `cosign sign-blob --yes` with GitHub
# Actions OIDC — no stored secrets, no paid KMS. This script fetches the
# three published files (<version>.json, <version>.json.sig,
# <version>.json.cert) from the registry's raw GitHub content and runs the
# matching `cosign verify-blob` command, confirming the JSON was signed by
# *this* repo's scan workflow and not by anyone else.
#
# Accepted signer identities (the certificate records the workflow file and
# the ref it ran on):
#   .github/workflows/scan.yml@refs/heads/scan/<pkg>-<commit7>  (scan PR runs)
#   .github/workflows/scan.yml@refs/heads/main                  (manual runs)
#   .github/workflows/dynamic-sandbox.yml@refs/heads/main       (attestations
#     signed before the PR-based pipeline replaced that workflow)
#
# Usage:
#   scripts/verify_attestation.sh <package> <version>
#   scripts/verify_attestation.sh curl 8.10.1-1
#
# Requires: cosign (https://docs.sigstore.dev/cosign/installation/), curl.

set -uo pipefail

REPO="rebizzz/aur-sentry"
RAW_BASE="https://raw.githubusercontent.com/$REPO/main"
CERT_IDENTITY_REGEXP="^https://github\\.com/${REPO}/\\.github/workflows/(scan\\.yml@refs/heads/(main|scan/[A-Za-z0-9@._+-]+)|dynamic-sandbox\\.yml@refs/heads/main)\$"
CERT_OIDC_ISSUER="https://token.actions.githubusercontent.com"

PKG="${1:-}"
VERSION="${2:-}"

if [ -z "$PKG" ] || [ -z "$VERSION" ]; then
  echo "usage: $0 <package> <version>" >&2
  echo "example: $0 curl 8.10.1-1" >&2
  exit 1
fi

if ! command -v cosign >/dev/null 2>&1; then
  echo "error: cosign is not installed. See https://docs.sigstore.dev/cosign/installation/" >&2
  exit 1
fi

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

JSON_PATH="data/attestations/$PKG/$VERSION.json"
JSON_URL="$RAW_BASE/$JSON_PATH"
SIG_URL="$JSON_URL.sig"
CERT_URL="$JSON_URL.cert"

JSON_FILE="$WORKDIR/$VERSION.json"
SIG_FILE="$WORKDIR/$VERSION.json.sig"
CERT_FILE="$WORKDIR/$VERSION.json.cert"

echo "fetching $JSON_URL"
if ! curl -fsSL "$JSON_URL" -o "$JSON_FILE"; then
  echo "error: could not fetch attestation JSON ($JSON_URL) — check package/version" >&2
  exit 1
fi

echo "fetching $SIG_URL"
if ! curl -fsSL "$SIG_URL" -o "$SIG_FILE"; then
  echo "error: could not fetch signature ($SIG_URL) — this attestation may predate signing, or signing failed" >&2
  exit 1
fi

echo "fetching $CERT_URL"
if ! curl -fsSL "$CERT_URL" -o "$CERT_FILE"; then
  echo "error: could not fetch certificate ($CERT_URL) — this attestation may predate signing, or signing failed" >&2
  exit 1
fi

echo "verifying with cosign (Sigstore public-good instance)..."
cosign verify-blob \
  --certificate "$CERT_FILE" \
  --signature "$SIG_FILE" \
  --certificate-identity-regexp "$CERT_IDENTITY_REGEXP" \
  --certificate-oidc-issuer "$CERT_OIDC_ISSUER" \
  "$JSON_FILE"

STATUS=$?
if [ "$STATUS" -eq 0 ]; then
  echo "OK: $PKG $VERSION attestation is signed by the $REPO scan workflow"
else
  echo "FAILED: signature did not verify — do not trust this attestation" >&2
fi
exit "$STATUS"
