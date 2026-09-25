//! External vulnerability intelligence (OSV.dev results, `attest --external-intel`).

use crate::attestation::IntelligenceEntry;
use serde::Deserialize;
use std::path::Path;

/// Shape of the JSON array `scripts/dynamic_sandbox.sh` assembles (`jq`,
/// from OSV.dev query results — see `--external-intel`). Deliberately the
/// same shape as `attestation::IntelligenceEntry` itself: there's no extra
/// raw data to carry, just evidence entries ready to store as-is.
#[derive(Debug, Deserialize)]
struct IntelligenceEntryInput {
    source: String,
    summary: String,
    #[serde(default)]
    url: Option<String>,
}

/// Parse the `--external-intel` JSON blob into `IntelligenceEntry`s. Any
/// missing/unreadable/unparseable file degrades to "no external evidence"
/// rather than failing the attestation.
///
/// Deliberately returns no `Finding`s: per ARCHITECTURE.md's "external
/// signals become another evidence source" design and this project's
/// existing `reproducibility`-is-informational-only precedent,
/// `external_intelligence` never feeds `verdict_from_findings`. OSV
/// correlation here is a best-effort, sometimes name-guessed match (see
/// scripts/dynamic_sandbox.sh) rather than a directly-observed fact about
/// *this* build the way canary/network/setuid evidence is, so it stays
/// informational until that confidence bar is met.
pub fn parse_external_intelligence(path: Option<&Path>) -> Vec<IntelligenceEntry> {
    let Some(raw) = path
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|text| serde_json::from_str::<Vec<IntelligenceEntryInput>>(&text).ok())
    else {
        return Vec::new();
    };

    raw.into_iter()
        .map(|e| IntelligenceEntry {
            source: e.source,
            summary: e.summary,
            url: e.url,
        })
        .collect()
}
