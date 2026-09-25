//! Phase 1 evidence-based attestation data model.
//!
//! Mirrors `schemas/attestation.schema.json`. Static findings bridge from
//! `crate::findings::Finding` rather than duplicating the scanner's rule output.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Bridge from the scanner's free-form severity strings.
    pub fn from_scanner_str(s: &str) -> Self {
        match s {
            "CRITICAL" => Severity::Critical,
            "HIGH" => Severity::High,
            "MEDIUM" => Severity::Medium,
            "LOW" => Severity::Low,
            _ => Severity::Info,
        }
    }
}

pub use crate::findings::Behavior;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub behavior: Behavior,
    pub file: String,
    pub line: usize,
    pub severity: Severity,
    pub description: String,
}

impl Finding {
    /// Reshape a scanner-level `Finding` (rule id + string severity) into an
    /// attestation `Finding`, keeping the behavior its rule declared.
    pub fn from_scanner(f: &crate::findings::Finding, file: impl Into<String>) -> Self {
        Finding {
            behavior: f.behavior,
            file: file.into(),
            line: f.line_number,
            severity: Severity::from_scanner_str(&f.severity),
            description: f.description.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageIdentity {
    pub name: String,
    pub version: String,
    pub arch: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceIdentity {
    pub aur_commit: String,
    pub pkgbuild_sha256: String,
    pub install_sha256: Option<String>,
}

/// Sandbox pass name used to tag build-phase (`makepkg`) telemetry events.
pub const PHASE_BUILD: &str = "build";
/// Sandbox pass name used to tag install-phase (`pacman -U`/`-R`) telemetry events.
pub const PHASE_INSTALL: &str = "install";

/// Which sandbox pass produced a piece of dynamic telemetry. Build-phase
/// telemetry predates this field, so it defaults to `"build"` on
/// deserialization for backward compatibility with older attestation JSON
/// that doesn't carry a `phase` key at all.
fn default_telemetry_phase() -> String {
    PHASE_BUILD.to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEvent {
    pub command: String,
    pub parent: Option<String>,
    pub timestamp: String,
    #[serde(default = "default_telemetry_phase")]
    pub phase: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEvent {
    pub destination: String,
    pub port: Option<u16>,
    pub protocol: Option<String>,
    pub timestamp: String,
    /// `"build"` (makepkg telemetry) or `"install"` (pacman -U/-R telemetry).
    #[serde(default = "default_telemetry_phase")]
    pub phase: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemEvent {
    pub path: String,
    pub operation: String,
    pub timestamp: String,
    /// `"build"` (makepkg telemetry) or `"install"` (pacman -U/-R telemetry).
    #[serde(default = "default_telemetry_phase")]
    pub phase: String,
}

/// Minimal/optional in Phase 1 — the dynamic sandbox lands separately.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DynamicEvidence {
    pub collected: bool,
    pub processes: Vec<ProcessEvent>,
    pub network: Vec<NetworkEvent>,
    pub filesystem: Vec<FilesystemEvent>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ElfObjectInfo {
    pub path: String,
    pub arch: String,
    pub stripped: bool,
    pub pie: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PackageAnalysis {
    /// False when no package could be extracted/analyzed for this run (e.g.
    /// the reproducibility build failed both independent attempts). Package
    /// analysis degrades gracefully — this is not an attestation failure.
    pub available: bool,
    pub file_count: u64,
    pub elf_object_count: u64,
    pub elf_objects: Vec<ElfObjectInfo>,
    /// Count of files with the setuid or setgid bit set in the extracted
    /// package tree.
    pub setuid_files: u64,
    /// Count of world-writable files in the extracted package tree.
    pub world_writable_files: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReproducibilityStatus {
    NotAttempted,
    Reproduced,
    Diverged,
    Failed,
    /// A second independent build could not meaningfully be compared to the
    /// first (e.g. `--nodeps` build failed for both/either attempt because
    /// the package needs network-fetched dependencies). Phase 3: this is a
    /// deliberate degrade path, not a build/attestation failure — see
    /// ARCHITECTURE.md's "non-reproducible must not automatically mean
    /// malicious" caution, which is exactly why this status must never feed
    /// `verdict_from_findings`.
    Unsupported,
}

impl ReproducibilityStatus {
    /// Bridge from the dynamic sandbox's `--reproducibility-status` CLI
    /// value (see src/attest.rs / .github: scripts/dynamic_sandbox.sh).
    /// Anything unrecognized conservatively falls back to `NotAttempted`
    /// rather than guessing.
    pub fn from_cli_str(s: &str) -> Self {
        match s.to_ascii_uppercase().as_str() {
            "REPRODUCED" => ReproducibilityStatus::Reproduced,
            "DIVERGED" => ReproducibilityStatus::Diverged,
            "FAILED" => ReproducibilityStatus::Failed,
            "UNSUPPORTED" => ReproducibilityStatus::Unsupported,
            _ => ReproducibilityStatus::NotAttempted,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelligenceEntry {
    pub source: String,
    pub summary: String,
    pub url: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Verdict {
    Verified,
    Suspicious,
    Malicious,
    Inconclusive,
    BuildFailed,
    AnalysisFailed,
    Stale,
    Unsupported,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    pub schema_version: String,
    pub package: PackageIdentity,
    pub source: SourceIdentity,
    pub analyzed_at: String,
    pub scanner_version: String,
    pub static_findings: Vec<Finding>,
    pub dynamic_evidence: DynamicEvidence,
    pub package_analysis: PackageAnalysis,
    /// Informational evidence only. Per ARCHITECTURE.md: "non-reproducible
    /// must not automatically mean malicious" — `verdict_from_findings`
    /// intentionally never reads this field, and it must stay that way.
    pub reproducibility: ReproducibilityStatus,
    pub external_intelligence: Vec<IntelligenceEntry>,
    pub verdict: Verdict,
    pub evidence_hash: String,
    pub signature: Option<String>,
}

impl Attestation {
    /// sha256 over the canonical (compact JSON) serialization of every field
    /// except `evidence_hash` and `signature`, so re-signing never changes it.
    pub fn compute_evidence_hash(&self) -> String {
        let mut evidence_only = self.clone();
        evidence_only.evidence_hash = String::new();
        evidence_only.signature = None;
        let canonical = serde_json::to_string(&evidence_only).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

/// Deterministic, extensible verdict rules — no ML/LLM judgment (Phase 1 scope).
///
/// Deliberately takes only `findings`: reproducibility status is evidence,
/// never a verdict input (see the `reproducibility` field's doc comment on
/// `Attestation` and ARCHITECTURE.md's Phase 3 caution).
pub fn verdict_from_findings(findings: &[Finding]) -> Verdict {
    let critical_exfil_or_creds = findings.iter().any(|f| {
        f.severity == Severity::Critical
            && matches!(
                f.behavior,
                Behavior::CredentialAccess | Behavior::NetworkAccess
            )
    });
    if critical_exfil_or_creds {
        return Verdict::Malicious;
    }
    if findings
        .iter()
        .any(|f| f.severity == Severity::High || f.severity == Severity::Critical)
    {
        return Verdict::Suspicious;
    }
    Verdict::Verified
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_attestation() -> Attestation {
        Attestation {
            schema_version: "1.0".into(),
            package: PackageIdentity {
                name: "foo".into(),
                version: "1.0-1".into(),
                arch: "x86_64".into(),
            },
            source: SourceIdentity {
                aur_commit: "deadbeef".into(),
                pkgbuild_sha256: "a".repeat(64),
                install_sha256: None,
            },
            analyzed_at: "2026-01-01T00:00:00Z".into(),
            scanner_version: "0.1.0".into(),
            static_findings: vec![],
            dynamic_evidence: DynamicEvidence::default(),
            package_analysis: PackageAnalysis::default(),
            reproducibility: ReproducibilityStatus::NotAttempted,
            external_intelligence: vec![],
            verdict: Verdict::Verified,
            evidence_hash: String::new(),
            signature: None,
        }
    }

    #[test]
    fn serialization_round_trip_matches_schema_shape() {
        let mut att = sample_attestation();
        att.evidence_hash = att.compute_evidence_hash();

        let json = serde_json::to_value(&att).unwrap();
        for key in [
            "schema_version",
            "package",
            "source",
            "analyzed_at",
            "scanner_version",
            "static_findings",
            "dynamic_evidence",
            "package_analysis",
            "reproducibility",
            "external_intelligence",
            "verdict",
            "evidence_hash",
            "signature",
        ] {
            assert!(json.get(key).is_some(), "missing field: {key}");
        }
        assert_eq!(json["verdict"], "VERIFIED");
        assert_eq!(json["reproducibility"], "NOT_ATTEMPTED");

        let round_tripped: Attestation = serde_json::from_value(json).unwrap();
        assert_eq!(round_tripped.package.name, "foo");
        assert_eq!(round_tripped.evidence_hash, att.evidence_hash);
    }

    #[test]
    fn verdict_critical_credential_access_is_malicious() {
        let findings = vec![Finding {
            behavior: Behavior::CredentialAccess,
            file: "PKGBUILD".into(),
            line: 5,
            severity: Severity::Critical,
            description: "reads ~/.ssh/id_rsa".into(),
        }];
        assert_eq!(verdict_from_findings(&findings), Verdict::Malicious);
    }

    #[test]
    fn verdict_critical_network_access_is_malicious() {
        let findings = vec![Finding {
            behavior: Behavior::NetworkAccess,
            file: "PKGBUILD".into(),
            line: 5,
            severity: Severity::Critical,
            description: "exfiltrates to discord webhook".into(),
        }];
        assert_eq!(verdict_from_findings(&findings), Verdict::Malicious);
    }

    #[test]
    fn verdict_high_severity_is_suspicious() {
        let findings = vec![Finding {
            behavior: Behavior::Obfuscation,
            file: "PKGBUILD".into(),
            line: 12,
            severity: Severity::High,
            description: "high entropy blob".into(),
        }];
        assert_eq!(verdict_from_findings(&findings), Verdict::Suspicious);
    }

    #[test]
    fn verdict_no_findings_or_low_severity_is_verified() {
        assert_eq!(verdict_from_findings(&[]), Verdict::Verified);

        let findings = vec![Finding {
            behavior: Behavior::PackageInstallation,
            file: "PKGBUILD".into(),
            line: 1,
            severity: Severity::Low,
            description: "installs package".into(),
        }];
        assert_eq!(verdict_from_findings(&findings), Verdict::Verified);
    }

    #[test]
    fn verdict_critical_but_unrelated_behavior_is_not_malicious() {
        // CRITICAL severity alone isn't enough — only credential-access/exfil-shaped
        // (network-access) behaviors trigger MALICIOUS per the Phase 1 rule.
        let findings = vec![Finding {
            behavior: Behavior::Obfuscation,
            file: "PKGBUILD".into(),
            line: 3,
            severity: Severity::Critical,
            description: "packed payload".into(),
        }];
        assert_eq!(verdict_from_findings(&findings), Verdict::Suspicious);
    }

    #[test]
    fn evidence_hash_is_stable_for_same_input() {
        let att = sample_attestation();
        let h1 = att.compute_evidence_hash();
        let h2 = att.compute_evidence_hash();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn evidence_hash_changes_when_evidence_changes() {
        let att1 = sample_attestation();
        let mut att2 = sample_attestation();
        att2.package.version = "2.0-1".into();

        assert_ne!(att1.compute_evidence_hash(), att2.compute_evidence_hash());
    }

    #[test]
    fn evidence_hash_ignores_signature_and_hash_fields() {
        let mut att1 = sample_attestation();
        let mut att2 = sample_attestation();
        att1.evidence_hash = "stale-hash".into();
        att2.evidence_hash = "different-stale-hash".into();
        att2.signature = Some("sig".into());

        assert_eq!(att1.compute_evidence_hash(), att2.compute_evidence_hash());
    }

    #[test]
    fn reproducibility_status_from_cli_str_round_trips_known_values() {
        assert_eq!(
            ReproducibilityStatus::from_cli_str("REPRODUCED"),
            ReproducibilityStatus::Reproduced
        );
        assert_eq!(
            ReproducibilityStatus::from_cli_str("diverged"),
            ReproducibilityStatus::Diverged
        );
        assert_eq!(
            ReproducibilityStatus::from_cli_str("Failed"),
            ReproducibilityStatus::Failed
        );
        assert_eq!(
            ReproducibilityStatus::from_cli_str("unsupported"),
            ReproducibilityStatus::Unsupported
        );
        assert_eq!(
            ReproducibilityStatus::from_cli_str("garbage"),
            ReproducibilityStatus::NotAttempted
        );
    }

    #[test]
    fn verdict_from_findings_ignores_reproducibility_by_construction() {
        // verdict_from_findings takes only `&[Finding]` — there is no
        // reproducibility parameter to accidentally wire in. This test just
        // pins that a non-reproducible-but-otherwise-clean attestation
        // still verdicts VERIFIED via the normal findings path.
        let mut att = sample_attestation();
        att.reproducibility = ReproducibilityStatus::Diverged;
        att.verdict = verdict_from_findings(&att.static_findings);
        assert_eq!(att.verdict, Verdict::Verified);
    }

    #[test]
    fn finding_bridges_from_scanner_finding() {
        let scanner_finding = crate::findings::Finding {
            rule_id: "EXFIL_DISCORD_WEBHOOK".into(),
            severity: "CRITICAL".into(),
            description: "discord webhook exfil".into(),
            line_number: 7,
            matched_text: "discord.com/api/webhooks".into(),
            behavior: Behavior::NetworkAccess,
        };
        let finding = Finding::from_scanner(&scanner_finding, "PKGBUILD");
        assert_eq!(finding.behavior, Behavior::NetworkAccess);
        assert_eq!(finding.severity, Severity::Critical);
        assert_eq!(finding.line, 7);
        assert_eq!(finding.file, "PKGBUILD");
    }
}
