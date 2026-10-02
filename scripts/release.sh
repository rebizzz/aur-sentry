#!/usr/bin/env bash
# scripts/release.sh — Automated release tagger and validation for aur-sentry
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
    VERSION=$(grep '^version = ' "$REPO_ROOT/Cargo.toml" | head -n1 | cut -d'"' -f2)
fi

TAG="v${VERSION#v}"

echo "=========================================================="
echo " AUR-Sentry Release Pipeline"
echo " Target Version: ${VERSION}"
echo " Tag:            ${TAG}"
echo "=========================================================="

cd "$REPO_ROOT"

echo "[1/4] Running test suite..."
cargo test --all-targets

echo "[2/4] Running clippy linter..."
cargo clippy --all-targets -- -D warnings

echo "[3/4] Verifying generated/ and git status..."
if git status --porcelain | grep -v '^?? generated/' | grep -v '^?? .agents/' | grep -q '^??'; then
    echo "⚠️  Untracked non-ignored files detected outside generated/:"
    git status --short
fi

echo "[4/4] Creating git tag ${TAG}..."
if git rev-parse "$TAG" >/dev/null 2>&1; then
    echo "Tag ${TAG} already exists locally."
else
    git tag -a "$TAG" -m "Release ${TAG} — Multi-source dependency intelligence & container sandboxing"
    echo "✓ Tag ${TAG} created."
fi

echo ""
echo "Release ${TAG} prepared successfully!"
echo "To publish, run:"
echo "  git push origin main --tags"
