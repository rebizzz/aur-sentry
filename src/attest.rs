//! Assembles a full `attestation::Attestation` from the static scanner's
//! JSON findings and the dynamic sandbox's evidence (see `crate::evidence`)
//! — the native replacement for `scripts/build_attestation.py`.

use crate::attestation::{
    Attestation, DynamicEvidence, PHASE_BUILD, PHASE_INSTALL, PackageIdentity,
    ReproducibilityStatus, SourceIdentity, Verdict, verdict_from_findings,
};
use crate::evidence::{self, intel, package, strace};
use sha2::{Digest, Sha256};
use std::path::Path;

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Everything `build_attestation` needs — mirrors the flags `aur-sentry
/// attest` exposes on the CLI (see cli/attest.rs) and build_attestation.py's args.
pub struct AttestInputs<'a> {
    pub package: String,
    pub version: String,
    pub arch: String,
    pub aur_commit: String,
    pub pkgbuild_path: Option<&'a Path>,
    pub install_path: Option<&'a Path>,
    /// JSON array of `scan-file --json` outputs (see `evidence::parse_static_findings`).
    pub static_findings_path: Option<&'a Path>,
    pub telemetry_path: Option<&'a Path>,
    /// Path to the install-phase strace telemetry log (`pacman -U`/`-R`
    /// under strace, see scripts/dynamic_sandbox.sh's install-phase step).
    /// `None`/missing degrades to "no install-phase evidence" rather than
    /// failing the attestation — this pass is skipped entirely upstream
    /// whenever no built package file exists (e.g. reproducibility failed).
    pub install_telemetry_path: Option<&'a Path>,
    /// Path to the package-content/ELF-analysis JSON blob assembled by
    /// `scripts/dynamic_sandbox.sh` (`jq`, from the real `makepkg`-built
    /// package). `None`/unreadable/unparseable degrades to an "unavailable"
    /// `PackageAnalysis` rather than failing the attestation.
    pub package_analysis_path: Option<&'a Path>,
    /// Path to the `external_intel.json` array assembled by
    /// `scripts/dynamic_sandbox.sh` from OSV.dev vulnerability-query
    /// results. `None`/unreadable/unparseable degrades to no external
    /// evidence rather than failing the attestation. Purely informational:
    /// never feeds `verdict_from_findings` (see `intel::parse_external_intelligence`).
    pub external_intelligence_path: Option<&'a Path>,
    pub strace_available: bool,
    pub makepkg_exit: Option<i32>,
    pub scanner_version: String,
    /// Phase 3 reproducibility comparison result (second independent build +
    /// diff — see scripts/dynamic_sandbox.sh). Purely informational: never
    /// feeds `verdict_from_findings`.
    pub reproducibility: ReproducibilityStatus,
}

/// Build and hash a full `Attestation` from the given evidence inputs. Any
/// missing/unreadable file is treated as "no evidence from that source"
/// rather than a hard error, matching build_attestation.py's leniency.
pub fn build_attestation(inputs: &AttestInputs) -> Attestation {
    let pkgbuild_text = inputs
        .pkgbuild_path
        .and_then(|p| std::fs::read_to_string(p).ok());
    let pkgbuild_sha256 = pkgbuild_text
        .as_deref()
        .map(|t| sha256_hex(t.as_bytes()))
        .unwrap_or_else(|| "0".repeat(64));
    let install_sha256 = inputs
        .install_path
        .and_then(|p| std::fs::read(p).ok())
        .map(|bytes| sha256_hex(&bytes));

    let mut findings = evidence::parse_static_findings(inputs.static_findings_path);

    let allowed_ips = pkgbuild_text
        .as_deref()
        .map(strace::declared_source_ips)
        .unwrap_or_default();

    let (mut network, mut filesystem) = if inputs.strace_available {
        let telemetry_text = inputs
            .telemetry_path
            .and_then(|p| std::fs::read_to_string(p).ok())
            .unwrap_or_default();
        strace::parse_telemetry(&telemetry_text, &allowed_ips, PHASE_BUILD)
    } else {
        (Vec::new(), Vec::new())
    };
    findings.extend(strace::dynamic_findings(&network, &filesystem, "build"));

    // Same strace gate and allowlist as the build pass; skipped upstream when
    // no built package file exists.
    if inputs.strace_available {
        if let Some(install_telemetry_text) = inputs
            .install_telemetry_path
            .and_then(|p| std::fs::read_to_string(p).ok())
        {
            let (install_network, install_filesystem) =
                strace::parse_telemetry(&install_telemetry_text, &allowed_ips, PHASE_INSTALL);
            findings.extend(strace::dynamic_findings(
                &install_network,
                &install_filesystem,
                "install",
            ));
            network.extend(install_network);
            filesystem.extend(install_filesystem);
        }
    }

    let (package_analysis, package_findings) =
        package::parse_package_analysis(inputs.package_analysis_path);
    findings.extend(package_findings);

    let external_intelligence =
        intel::parse_external_intelligence(inputs.external_intelligence_path);

    // BUILD_FAILED can't come out of verdict_from_findings (findings-only), so
    // it's handled as the one explicit fallback when the build itself failed.
    let verdict = if findings.is_empty() && matches!(inputs.makepkg_exit, Some(code) if code != 0) {
        Verdict::BuildFailed
    } else {
        verdict_from_findings(&findings)
    };

    let mut attestation = Attestation {
        schema_version: "1.0".into(),
        package: PackageIdentity {
            name: inputs.package.clone(),
            version: inputs.version.clone(),
            arch: inputs.arch.clone(),
        },
        source: SourceIdentity {
            aur_commit: inputs.aur_commit.clone(),
            pkgbuild_sha256,
            install_sha256,
        },
        analyzed_at: chrono::Utc::now().to_rfc3339(),
        scanner_version: inputs.scanner_version.clone(),
        static_findings: findings,
        dynamic_evidence: DynamicEvidence {
            collected: inputs.strace_available,
            processes: Vec::new(),
            network,
            filesystem,
        },
        package_analysis,
        reproducibility: inputs.reproducibility,
        external_intelligence,
        verdict,
        evidence_hash: String::new(),
        signature: None,
    };
    attestation.evidence_hash = attestation.compute_evidence_hash();
    attestation
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::Behavior;
    use crate::findings::{FileFindings, Finding};

    #[test]
    fn build_attestation_consumes_scan_json_preserving_file_and_behavior() {
        let scan = |file: &str, rule_id: &str, behavior| FileFindings {
            file: file.into(),
            findings: vec![Finding {
                rule_id: rule_id.into(),
                severity: "CRITICAL".into(),
                description: rule_id.to_lowercase(),
                line_number: 4,
                matched_text: String::new(),
                behavior,
            }],
        };
        let json = serde_json::to_string(&vec![
            scan("PKGBUILD", "OBFUSCATED_EVAL", Behavior::Obfuscation),
            scan("evil.install", "CRED_SSH_KEYS", Behavior::CredentialAccess),
        ])
        .unwrap();
        let path = std::env::temp_dir().join(format!(
            "aur_sentry_attest_static_{}.json",
            std::process::id()
        ));
        std::fs::write(&path, json).unwrap();

        let inputs = AttestInputs {
            package: "foo".into(),
            version: "1.0-1".into(),
            arch: "x86_64".into(),
            aur_commit: "deadbeef".into(),
            pkgbuild_path: None,
            install_path: None,
            static_findings_path: Some(&path),
            package_analysis_path: None,
            external_intelligence_path: None,
            telemetry_path: None,
            install_telemetry_path: None,
            strace_available: false,
            makepkg_exit: Some(0),
            scanner_version: "test".into(),
            reproducibility: ReproducibilityStatus::NotAttempted,
        };
        let att = build_attestation(&inputs);
        let _ = std::fs::remove_file(&path);

        assert_eq!(att.static_findings.len(), 2);
        assert_eq!(att.static_findings[0].file, "PKGBUILD");
        assert_eq!(att.static_findings[0].behavior, Behavior::Obfuscation);
        assert_eq!(att.static_findings[1].file, "evil.install");
        assert_eq!(att.static_findings[1].behavior, Behavior::CredentialAccess);
        assert_eq!(att.static_findings[1].line, 4);
        assert_eq!(att.verdict, Verdict::Malicious);
    }

    #[test]
    fn build_attestation_clean_evidence_is_verified() {
        let inputs = AttestInputs {
            package: "foo".into(),
            version: "1.0-1".into(),
            arch: "x86_64".into(),
            aur_commit: "deadbeef".into(),
            pkgbuild_path: None,
            install_path: None,
            static_findings_path: None,
            package_analysis_path: None,
            external_intelligence_path: None,
            telemetry_path: None,
            install_telemetry_path: None,
            strace_available: false,
            makepkg_exit: Some(0),
            scanner_version: "test".into(),
            reproducibility: ReproducibilityStatus::NotAttempted,
        };
        let att = build_attestation(&inputs);
        assert_eq!(att.verdict, Verdict::Verified);
        assert_eq!(att.source.pkgbuild_sha256, "0".repeat(64));
        assert!(!att.dynamic_evidence.collected);
        assert_eq!(att.evidence_hash.len(), 64);
    }

    #[test]
    fn build_attestation_canary_access_is_malicious() {
        let dir =
            std::env::temp_dir().join(format!("aur_sentry_attest_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let telemetry_path = dir.join("telemetry.log");
        std::fs::write(
            &telemetry_path,
            "12345 openat(AT_FDCWD, \"/home/builder/.ssh/id_fake\", O_RDONLY) = 4\n",
        )
        .unwrap();

        let inputs = AttestInputs {
            package: "evil-pkg".into(),
            version: "1.0-1".into(),
            arch: "x86_64".into(),
            aur_commit: "".into(),
            pkgbuild_path: None,
            install_path: None,
            static_findings_path: None,
            package_analysis_path: None,
            external_intelligence_path: None,
            telemetry_path: Some(&telemetry_path),
            install_telemetry_path: None,
            strace_available: true,
            makepkg_exit: Some(0),
            scanner_version: "test".into(),
            reproducibility: ReproducibilityStatus::NotAttempted,
        };
        let att = build_attestation(&inputs);
        assert_eq!(att.verdict, Verdict::Malicious);
        assert_eq!(att.dynamic_evidence.filesystem.len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn build_attestation_install_phase_canary_access_is_malicious() {
        // A clean build-phase telemetry log, but the .install script reads
        // the canary during `pacman -U` — this must feed the same verdict
        // path as a build-phase hit (ARCHITECTURE.md: installing malware via
        // .install is just as bad as building it).
        let dir = std::env::temp_dir().join(format!(
            "aur_sentry_attest_install_test_{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let telemetry_path = dir.join("telemetry.log");
        std::fs::write(&telemetry_path, "").unwrap();
        let install_telemetry_path = dir.join("install_telemetry.log");
        std::fs::write(
            &install_telemetry_path,
            "12345 openat(AT_FDCWD, \"/root/.aws/credentials\", O_RDONLY) = 4\n",
        )
        .unwrap();

        let inputs = AttestInputs {
            package: "evil-install-pkg".into(),
            version: "1.0-1".into(),
            arch: "x86_64".into(),
            aur_commit: "".into(),
            pkgbuild_path: None,
            install_path: None,
            static_findings_path: None,
            package_analysis_path: None,
            external_intelligence_path: None,
            telemetry_path: Some(&telemetry_path),
            install_telemetry_path: Some(&install_telemetry_path),
            strace_available: true,
            makepkg_exit: Some(0),
            scanner_version: "test".into(),
            reproducibility: ReproducibilityStatus::NotAttempted,
        };
        let att = build_attestation(&inputs);
        assert_eq!(att.verdict, Verdict::Malicious);
        assert_eq!(att.dynamic_evidence.filesystem.len(), 1);
        assert_eq!(att.dynamic_evidence.filesystem[0].phase, "install");
        assert!(
            att.static_findings
                .iter()
                .any(|f| f.description.contains("during install"))
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn build_attestation_missing_install_telemetry_degrades_gracefully() {
        // No install_telemetry_path at all (upstream skipped the pass, e.g.
        // no built package file existed) must not affect the attestation.
        let inputs = AttestInputs {
            package: "foo".into(),
            version: "1.0-1".into(),
            arch: "x86_64".into(),
            aur_commit: "deadbeef".into(),
            pkgbuild_path: None,
            install_path: None,
            static_findings_path: None,
            package_analysis_path: None,
            external_intelligence_path: None,
            telemetry_path: None,
            install_telemetry_path: None,
            strace_available: true,
            makepkg_exit: Some(0),
            scanner_version: "test".into(),
            reproducibility: ReproducibilityStatus::NotAttempted,
        };
        let att = build_attestation(&inputs);
        assert_eq!(att.verdict, Verdict::Verified);
        assert!(att.dynamic_evidence.filesystem.is_empty());
    }

    #[test]
    fn build_attestation_carries_reproducibility_status_without_affecting_verdict() {
        let inputs = AttestInputs {
            package: "foo".into(),
            version: "1.0-1".into(),
            arch: "x86_64".into(),
            aur_commit: "deadbeef".into(),
            pkgbuild_path: None,
            install_path: None,
            static_findings_path: None,
            package_analysis_path: None,
            external_intelligence_path: None,
            telemetry_path: None,
            install_telemetry_path: None,
            strace_available: false,
            makepkg_exit: Some(0),
            scanner_version: "test".into(),
            reproducibility: ReproducibilityStatus::Diverged,
        };
        let att = build_attestation(&inputs);
        assert_eq!(att.reproducibility, ReproducibilityStatus::Diverged);
        // DIVERGED reproducibility must not downgrade an otherwise-clean
        // build to SUSPICIOUS/MALICIOUS (ARCHITECTURE.md Phase 3 caution).
        assert_eq!(att.verdict, Verdict::Verified);
    }

    #[test]
    fn build_attestation_falls_back_to_build_failed() {
        let inputs = AttestInputs {
            package: "foo".into(),
            version: "1.0-1".into(),
            arch: "x86_64".into(),
            aur_commit: "".into(),
            pkgbuild_path: None,
            install_path: None,
            static_findings_path: None,
            package_analysis_path: None,
            external_intelligence_path: None,
            telemetry_path: None,
            install_telemetry_path: None,
            strace_available: false,
            makepkg_exit: Some(1),
            scanner_version: "test".into(),
            reproducibility: ReproducibilityStatus::NotAttempted,
        };
        let att = build_attestation(&inputs);
        assert_eq!(att.verdict, Verdict::BuildFailed);
    }
}
