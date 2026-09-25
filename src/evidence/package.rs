//! Built-package content/ELF analysis evidence (`attest --package-analysis`).

use crate::attestation::{Behavior, ElfObjectInfo, Finding, PackageAnalysis, Severity};
use serde::Deserialize;
use std::path::Path;

/// Shape of the JSON blob `scripts/dynamic_sandbox.sh` assembles with `jq`
/// from its package-extraction/ELF-analysis pass (see `--package-analysis`).
/// A superset of `attestation::PackageAnalysis`: it additionally carries the
/// raw setuid/world-writable paths so they can become `Finding`s, since the
/// stored `PackageAnalysis` only needs the counts.
#[derive(Debug, Deserialize, Default)]
struct PackageAnalysisInput {
    #[serde(default)]
    available: bool,
    #[serde(default)]
    file_count: u64,
    #[serde(default)]
    elf_object_count: u64,
    #[serde(default)]
    elf_objects: Vec<ElfObjectInfo>,
    #[serde(default)]
    setuid_files: u64,
    #[serde(default)]
    world_writable_files: u64,
    #[serde(default)]
    setuid_paths: Vec<String>,
    #[serde(default)]
    world_writable_paths: Vec<String>,
}

/// Parse the `--package-analysis` JSON blob into the stored `PackageAnalysis`
/// plus any setuid/world-writable `Finding`s it implies. Any missing/
/// unreadable/unparseable file degrades to "analysis unavailable" rather than
/// failing the attestation.
pub fn parse_package_analysis(path: Option<&Path>) -> (PackageAnalysis, Vec<Finding>) {
    let Some(raw) = path
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|text| serde_json::from_str::<PackageAnalysisInput>(&text).ok())
    else {
        return (PackageAnalysis::default(), Vec::new());
    };

    let mut findings = Vec::new();
    if !raw.setuid_paths.is_empty() {
        findings.push(Finding {
            behavior: Behavior::PrivilegeEscalation,
            file: "dynamic-sandbox".into(),
            line: 0,
            severity: Severity::Critical,
            description: format!(
                "setuid/setgid file(s) found in built package: {}",
                raw.setuid_paths.join(", ")
            ),
        });
    }
    if !raw.world_writable_paths.is_empty() {
        findings.push(Finding {
            behavior: Behavior::ArbitraryFilesystemWrite,
            file: "dynamic-sandbox".into(),
            line: 0,
            severity: Severity::High,
            description: format!(
                "world-writable file(s) found in built package: {}",
                raw.world_writable_paths.join(", ")
            ),
        });
    }

    let analysis = PackageAnalysis {
        available: raw.available,
        file_count: raw.file_count,
        elf_object_count: raw.elf_object_count,
        elf_objects: raw.elf_objects,
        setuid_files: raw.setuid_files,
        world_writable_files: raw.world_writable_files,
    };
    (analysis, findings)
}
