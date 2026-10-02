mod common;

use aur_sentry::attest::{AttestInputs, build_attestation};
use aur_sentry::attestation::{
    Attestation, DynamicEvidence, Finding as AttFinding, PackageAnalysis, PackageIdentity,
    ReproducibilityStatus, Severity as AttSeverity, SourceIdentity, Verdict, verdict_from_findings,
};
use aur_sentry::findings::{Behavior, FileFindings, Finding};
use aur_sentry::report::{
    Advisory, load_advisories, remove_advisory, update_advisories_markdown, update_readme_table,
    write_advisories,
};
use common::*;

// =========================================================================
// 1. Full Pipeline: Scan -> Attest -> Verdict -> Hash Verification
// =========================================================================

#[test]
fn test_pipeline_clean_pkgbuild_to_verified_attestation() {
    let sandbox = TestSandbox::new("tier3_pipeline_clean");
    let pkgbuild = sandbox.write_file("PKGBUILD", BENIGN_MINIMAL_PKGBUILD);

    // Step 1: Scan via CLI with --json
    let scan_output = run_aur_sentry(&["scan-file", pkgbuild.to_str().unwrap(), "--json"]);
    assert_eq!(scan_output.code(), Some(0));

    let file_findings: FileFindings = serde_json::from_str(&scan_output.stdout).unwrap();
    assert_eq!(file_findings.file, "PKGBUILD");
    assert!(file_findings.findings.is_empty());

    let static_findings_path =
        sandbox.write_file("static.json", &format!("[{}]", scan_output.stdout));
    let out_attestation = sandbox.path().join("attestation.json");

    // Step 2: Attest via CLI
    let attest_output = run_aur_sentry(&[
        "attest",
        "simple-tool",
        "--version",
        "1.2.3-1",
        "--pkgbuild",
        pkgbuild.to_str().unwrap(),
        "--static-findings",
        static_findings_path.to_str().unwrap(),
        "--output",
        out_attestation.to_str().unwrap(),
    ]);
    assert_eq!(attest_output.code(), Some(0));

    // Step 3: Verify Attestation JSON
    let att_content = std::fs::read_to_string(&out_attestation).unwrap();
    let att: Attestation = serde_json::from_str(&att_content).unwrap();

    assert_eq!(att.package.name, "simple-tool");
    assert_eq!(att.package.version, "1.2.3-1");
    assert_eq!(att.verdict, Verdict::Verified);
    assert!(!att.evidence_hash.is_empty());
    assert_eq!(att.evidence_hash, att.compute_evidence_hash());
}

#[test]
fn test_pipeline_threat_pkgbuild_to_malicious_attestation() {
    let sandbox = TestSandbox::new("tier3_pipeline_threat");
    let pkgbuild = sandbox.write_file("PKGBUILD", MALICIOUS_DISCORD_STEALER);

    // Step 1: Scan via CLI with --json
    let scan_output = run_aur_sentry(&["scan-file", pkgbuild.to_str().unwrap(), "--json"]);
    assert_eq!(scan_output.code(), Some(2));

    let file_findings: FileFindings = serde_json::from_str(&scan_output.stdout).unwrap();
    assert!(!file_findings.findings.is_empty());

    let static_findings_path =
        sandbox.write_file("static.json", &format!("[{}]", scan_output.stdout));
    let out_attestation = sandbox.path().join("attestation.json");

    // Step 2: Attest via CLI
    let attest_output = run_aur_sentry(&[
        "attest",
        "discord-theme-dark",
        "--version",
        "1.0.0-1",
        "--pkgbuild",
        pkgbuild.to_str().unwrap(),
        "--static-findings",
        static_findings_path.to_str().unwrap(),
        "--output",
        out_attestation.to_str().unwrap(),
    ]);
    assert_eq!(attest_output.code(), Some(2)); // Non-verified exit code is 2

    // Step 3: Verify Attestation JSON
    let att_content = std::fs::read_to_string(&out_attestation).unwrap();
    let att: Attestation = serde_json::from_str(&att_content).unwrap();

    assert_eq!(att.verdict, Verdict::Malicious);
    assert!(!att.static_findings.is_empty());
    assert_eq!(att.evidence_hash, att.compute_evidence_hash());
}

#[test]
fn test_pipeline_suspicious_pkgbuild_to_suspicious_attestation() {
    let sandbox = TestSandbox::new("tier3_pipeline_suspicious");
    let pkgbuild_content = r#"
pkgname=dd-writer
pkgver=1.0.0
package() {
    dd if=source.img of=/dev/sdb bs=1M
}
"#;
    let pkgbuild = sandbox.write_file("PKGBUILD", pkgbuild_content);

    let scan_output = run_aur_sentry(&["scan-file", pkgbuild.to_str().unwrap(), "--json"]);
    assert_eq!(scan_output.code(), Some(2));

    let static_findings_path =
        sandbox.write_file("static.json", &format!("[{}]", scan_output.stdout));
    let out_attestation = sandbox.path().join("attestation.json");

    let attest_output = run_aur_sentry(&[
        "attest",
        "dd-writer",
        "--version",
        "1.0.0-1",
        "--pkgbuild",
        pkgbuild.to_str().unwrap(),
        "--static-findings",
        static_findings_path.to_str().unwrap(),
        "--output",
        out_attestation.to_str().unwrap(),
    ]);
    assert_eq!(attest_output.code(), Some(2));

    let att_content = std::fs::read_to_string(&out_attestation).unwrap();
    let att: Attestation = serde_json::from_str(&att_content).unwrap();
    assert_eq!(att.verdict, Verdict::Suspicious);
}

#[test]
fn test_pipeline_build_failed_exit_code_fallback() {
    let sandbox = TestSandbox::new("tier3_build_failed");
    let pkgbuild = sandbox.write_file("PKGBUILD", BENIGN_MINIMAL_PKGBUILD);
    let static_findings = sandbox.write_file("static.json", "[]");
    let out_attestation = sandbox.path().join("attestation.json");

    let output = run_aur_sentry(&[
        "attest",
        "failed-pkg",
        "--version",
        "1.0.0-1",
        "--pkgbuild",
        pkgbuild.to_str().unwrap(),
        "--static-findings",
        static_findings.to_str().unwrap(),
        "--makepkg-exit",
        "2",
        "--output",
        out_attestation.to_str().unwrap(),
    ]);
    assert_eq!(output.code(), Some(2));

    let att_content = std::fs::read_to_string(&out_attestation).unwrap();
    let att: Attestation = serde_json::from_str(&att_content).unwrap();
    assert_eq!(att.verdict, Verdict::BuildFailed);
}

// =========================================================================
// 2. Multi-File Evidence & Dynamic Sandbox Integration
// =========================================================================

#[test]
fn test_pipeline_multi_file_static_findings_aggregation() {
    let sandbox = TestSandbox::new("tier3_multi_file");
    let pkgbuild_json = r#"{"file":"PKGBUILD","findings":[{"rule_id":"EXFIL_RAW_IP","severity":"HIGH","description":"raw ip","line_number":5,"matched_text":"1.2.3.4","behavior":"NETWORK_ACCESS"}]}"#;
    let install_json = r#"{"file":"pkg.install","findings":[{"rule_id":"PERSIST_SYSTEMD","severity":"CRITICAL","description":"systemd","line_number":10,"matched_text":"/etc/systemd/system","behavior":"PERSISTENCE"}]}"#;

    let static_file =
        sandbox.write_file("static.json", &format!("[{pkgbuild_json}, {install_json}]"));

    let inputs = AttestInputs {
        package: "multi-file-pkg".into(),
        version: "1.0.0-1".into(),
        arch: "x86_64".into(),
        aur_commit: "12345678".into(),
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
    assert_eq!(att.static_findings.len(), 2);
    assert!(att.static_findings.iter().any(|f| f.file == "PKGBUILD"));
    assert!(att.static_findings.iter().any(|f| f.file == "pkg.install"));
    assert_eq!(att.verdict, Verdict::Suspicious);
}

#[test]
fn test_pipeline_dynamic_evidence_canary_access_produces_malicious() {
    let sandbox = TestSandbox::new("tier3_canary");
    let telemetry_content = r#"
1001 openat(AT_FDCWD, "/home/build/.ssh/id_fake_canary", O_RDONLY) = 3
1002 read(3, "super_secret", 12) = 12
"#;
    let telem_file = sandbox.write_file("telemetry.log", telemetry_content);

    let inputs = AttestInputs {
        package: "canary-stealer".into(),
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
    assert_eq!(
        att.verdict,
        Verdict::Malicious,
        "Canary secret access must escalate verdict to Malicious"
    );
    assert!(
        att.static_findings
            .iter()
            .any(|f| f.description.contains("canary secret"))
    );
}

#[test]
fn test_pipeline_dynamic_evidence_undeclared_network_connection() {
    let sandbox = TestSandbox::new("tier3_undeclared_net");
    let telemetry_content = r#"
2001 connect(4, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("198.51.100.5")}, 16) = 0
"#;
    let telem_file = sandbox.write_file("telemetry.log", telemetry_content);

    let inputs = AttestInputs {
        package: "undeclared-net-pkg".into(),
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
    assert_eq!(
        att.verdict,
        Verdict::Suspicious,
        "Undeclared network connection alone should yield Suspicious"
    );
    assert!(
        att.static_findings
            .iter()
            .any(|f| f.description.contains("not declared in PKGBUILD source=()"))
    );
}

#[test]
fn test_pipeline_declared_source_ip_whitelist_respected() {
    let sandbox = TestSandbox::new("tier3_declared_ip");
    let pkgbuild_content = r#"
pkgname=declared-ip-pkg
pkgver=1.0.0
source=("http://198.51.100.5/archive.tar.gz")
sha256sums=('SKIP')
"#;
    let pkgbuild = sandbox.write_file("PKGBUILD", pkgbuild_content);

    // Telemetry connects to the declared IP: 198.51.100.5
    let telemetry_content = r#"
2001 connect(4, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("198.51.100.5")}, 16) = 0
"#;
    let telem_file = sandbox.write_file("telemetry.log", telemetry_content);

    let inputs = AttestInputs {
        package: "declared-ip-pkg".into(),
        version: "1.0.0-1".into(),
        arch: "x86_64".into(),
        aur_commit: "".into(),
        pkgbuild_path: Some(&pkgbuild),
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
    // Because 198.51.100.5 was declared in source=(), it is allowed
    assert!(
        !att.static_findings
            .iter()
            .any(|f| f.description.contains("not declared in PKGBUILD source=()")),
        "Declared source IP should be whitelisted"
    );
}

// =========================================================================
// 3. Threat Advisory & Feed Management Lifecycle
// =========================================================================

#[test]
fn test_advisory_lifecycle_malicious_upserts_feed_and_readme() {
    let sandbox = TestSandbox::new("tier3_advisory_lifecycle");

    let initial_readme = r#"# AUR-Sentry
Live supply-chain threat radar.

<!-- AUTOPILOT_TABLE_START -->
<!-- AUTOPILOT_TABLE_END -->

License: MIT
"#;
    sandbox.write_file("README.md", initial_readme);

    let advisory = Advisory {
        package: "hacked-pkg".into(),
        version: "3.2.1-1".into(),
        maintainer: "compromised_dev".into(),
        highest_severity: "CRITICAL".into(),
        detected_at: "2026-10-01T12:00:00Z".into(),
        findings: vec![Finding {
            rule_id: "EXFIL_DISCORD_WEBHOOK".into(),
            severity: "CRITICAL".into(),
            description: "Discord token stealer".into(),
            line_number: 12,
            matched_text: "discord.com/api/webhooks".into(),
            behavior: Behavior::NetworkAccess,
        }],
        aur_url: "https://aur.archlinux.org/packages/hacked-pkg".into(),
    };

    write_advisories(sandbox.path(), &[advisory]);

    let loaded = load_advisories(sandbox.path());
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].package, "hacked-pkg");
    assert_eq!(loaded[0].highest_severity, "CRITICAL");

    update_readme_table(sandbox.path(), &loaded);

    let readme = sandbox.read_file("README.md");
    assert!(readme.contains("<details open>"));
    assert!(readme.contains("<summary>Active Threats (1)</summary>"));
    assert!(readme.contains("`[CRITICAL]`"));
    assert!(readme.contains("`hacked-pkg`"));
    assert!(readme.contains("License: MIT"));
}

#[test]
fn test_advisory_lifecycle_severity_ranking_sort_order() {
    let sandbox = TestSandbox::new("tier3_advisory_sorting");

    let adv_crit = Advisory {
        package: "crit-pkg".into(),
        version: "1.0".into(),
        maintainer: "dev1".into(),
        highest_severity: "CRITICAL".into(),
        detected_at: "2026-10-01T10:00:00Z".into(),
        findings: vec![],
        aur_url: "".into(),
    };
    let adv_high = Advisory {
        package: "high-pkg".into(),
        version: "1.0".into(),
        maintainer: "dev2".into(),
        highest_severity: "HIGH".into(),
        detected_at: "2026-10-01T11:00:00Z".into(),
        findings: vec![],
        aur_url: "".into(),
    };
    let adv_med = Advisory {
        package: "med-pkg".into(),
        version: "1.0".into(),
        maintainer: "dev3".into(),
        highest_severity: "MEDIUM".into(),
        detected_at: "2026-10-01T12:00:00Z".into(),
        findings: vec![],
        aur_url: "".into(),
    };

    // Pass in reverse order: MEDIUM, HIGH, CRITICAL
    write_advisories(sandbox.path(), &[adv_med, adv_high, adv_crit]);

    let loaded = load_advisories(sandbox.path());
    assert_eq!(loaded.len(), 3);
    assert_eq!(loaded[0].package, "crit-pkg", "CRITICAL must sort first");
    assert_eq!(loaded[1].package, "high-pkg", "HIGH must sort second");
    assert_eq!(loaded[2].package, "med-pkg", "MEDIUM must sort third");
}

#[test]
fn test_advisory_lifecycle_removal_cleans_feed() {
    let sandbox = TestSandbox::new("tier3_advisory_remove");

    let adv1 = Advisory {
        package: "keep-me".into(),
        version: "1.0".into(),
        maintainer: "dev1".into(),
        highest_severity: "HIGH".into(),
        detected_at: "2026-10-01T10:00:00Z".into(),
        findings: vec![],
        aur_url: "".into(),
    };
    let adv2 = Advisory {
        package: "remove-me".into(),
        version: "2.0".into(),
        maintainer: "dev2".into(),
        highest_severity: "CRITICAL".into(),
        detected_at: "2026-10-01T11:00:00Z".into(),
        findings: vec![],
        aur_url: "".into(),
    };

    write_advisories(sandbox.path(), &[adv1, adv2]);
    let initial = load_advisories(sandbox.path());
    assert_eq!(initial.len(), 2);

    remove_advisory(sandbox.path(), "remove-me");

    let remaining = load_advisories(sandbox.path());
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].package, "keep-me");
}

#[test]
fn test_advisory_lifecycle_update_advisories_markdown_creates_table() {
    let sandbox = TestSandbox::new("tier3_advisories_md");

    let advisory = Advisory {
        package: "flagged-driver".into(),
        version: "1.0.0-1".into(),
        maintainer: "malicious_user".into(),
        highest_severity: "CRITICAL".into(),
        detected_at: "2026-10-01T15:00:00Z".into(),
        findings: vec![],
        aur_url: "https://aur.archlinux.org/packages/flagged-driver".into(),
    };

    update_advisories_markdown(sandbox.path(), &[advisory]);

    let gen_adv = sandbox.path().join("generated").join("ADVISORIES.md");
    assert!(gen_adv.exists(), "generated/ADVISORIES.md must be created");
    let content = std::fs::read_to_string(&gen_adv).unwrap();
    assert!(content.contains("`flagged-driver`"));
    assert!(content.contains("`[CRITICAL]`"));
}

// =========================================================================
// 4. Attestation Evidence Hash Determinism & Signature Independence
// =========================================================================

#[test]
fn test_attestation_evidence_hash_determinism_and_mutation_sensitivity() {
    let sample = Attestation {
        schema_version: "1.0".into(),
        package: PackageIdentity {
            name: "test-pkg".into(),
            version: "1.0.0-1".into(),
            arch: "x86_64".into(),
        },
        source: SourceIdentity {
            aur_commit: "deadbeef".into(),
            pkgbuild_sha256: "0".repeat(64),
            install_sha256: None,
        },
        analyzed_at: "2026-10-01T00:00:00Z".into(),
        scanner_version: "0.1.0".into(),
        static_findings: vec![AttFinding {
            behavior: Behavior::NetworkAccess,
            file: "PKGBUILD".into(),
            line: 10,
            severity: AttSeverity::High,
            description: "raw ip".into(),
        }],
        dynamic_evidence: DynamicEvidence::default(),
        package_analysis: PackageAnalysis::default(),
        reproducibility: ReproducibilityStatus::NotAttempted,
        external_intelligence: vec![],
        verdict: Verdict::Suspicious,
        evidence_hash: String::new(),
        signature: None,
    };

    let hash1 = sample.compute_evidence_hash();
    let hash2 = sample.compute_evidence_hash();
    assert_eq!(hash1, hash2, "Evidence hash must be deterministic");

    // Mutation test: changing line must produce a different hash
    let mut mutated = sample.clone();
    mutated.static_findings[0].line = 99;
    let hash_mutated = mutated.compute_evidence_hash();
    assert_ne!(
        hash1, hash_mutated,
        "Hash must change when evidence changes"
    );

    // Signature independence test: setting signature must NOT change evidence_hash
    let mut with_sig = sample.clone();
    with_sig.signature = Some("cosign_signature_base64_blob".into());
    let hash_with_sig = with_sig.compute_evidence_hash();
    assert_eq!(
        hash1, hash_with_sig,
        "Evidence hash must be independent of signature"
    );
}

#[test]
fn test_attestation_serialization_roundtrip_all_fields() {
    let att = Attestation {
        schema_version: "1.0".into(),
        package: PackageIdentity {
            name: "schema-pkg".into(),
            version: "2.0.0-1".into(),
            arch: "x86_64".into(),
        },
        source: SourceIdentity {
            aur_commit: "abcdef12".into(),
            pkgbuild_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .into(),
            install_sha256: None,
        },
        analyzed_at: "2026-10-01T12:00:00Z".into(),
        scanner_version: "0.1.0".into(),
        static_findings: vec![],
        dynamic_evidence: DynamicEvidence::default(),
        package_analysis: PackageAnalysis::default(),
        reproducibility: ReproducibilityStatus::Reproduced,
        external_intelligence: vec![],
        verdict: Verdict::Verified,
        evidence_hash: "abcd1234efgh5678".into(),
        signature: Some("sig_blob".into()),
    };

    let json_val = serde_json::to_value(&att).unwrap();
    let roundtripped: Attestation = serde_json::from_value(json_val).unwrap();

    assert_eq!(roundtripped.package.name, "schema-pkg");
    assert_eq!(
        roundtripped.reproducibility,
        ReproducibilityStatus::Reproduced
    );
    assert_eq!(roundtripped.verdict, Verdict::Verified);
    assert_eq!(roundtripped.evidence_hash, "abcd1234efgh5678");
}

// =========================================================================
// 5. Verdict Derivation Rules Matrix
// =========================================================================

#[test]
fn test_verdict_derivation_matrix() {
    // 1. Clean findings -> VERIFIED
    assert_eq!(verdict_from_findings(&[]), Verdict::Verified);

    // 2. Only INFO / LOW findings -> VERIFIED
    let low_findings = vec![AttFinding {
        behavior: Behavior::DynamicDownload,
        file: "PKGBUILD".into(),
        line: 1,
        severity: AttSeverity::Low,
        description: "npm install".into(),
    }];
    assert_eq!(verdict_from_findings(&low_findings), Verdict::Verified);

    // 3. HIGH finding without critical credentials/exfil -> SUSPICIOUS
    let high_findings = vec![AttFinding {
        behavior: Behavior::ArbitraryFilesystemWrite,
        file: "PKGBUILD".into(),
        line: 1,
        severity: AttSeverity::High,
        description: "raw dd".into(),
    }];
    assert_eq!(verdict_from_findings(&high_findings), Verdict::Suspicious);

    // 4. CRITICAL with CredentialAccess -> MALICIOUS
    let cred_findings = vec![AttFinding {
        behavior: Behavior::CredentialAccess,
        file: "PKGBUILD".into(),
        line: 1,
        severity: AttSeverity::Critical,
        description: "ssh keys".into(),
    }];
    assert_eq!(verdict_from_findings(&cred_findings), Verdict::Malicious);

    // 5. CRITICAL with NetworkAccess -> MALICIOUS
    let net_findings = vec![AttFinding {
        behavior: Behavior::NetworkAccess,
        file: "PKGBUILD".into(),
        line: 1,
        severity: AttSeverity::Critical,
        description: "webhook".into(),
    }];
    assert_eq!(verdict_from_findings(&net_findings), Verdict::Malicious);
}
