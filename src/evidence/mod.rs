//! Evidence parsers feeding `attest::build_attestation`: static scanner
//! JSON, strace telemetry, built-package analysis, and external intel.

pub mod intel;
pub mod package;
pub mod strace;

use crate::attestation::Finding;
use crate::findings::FileFindings;
use std::path::Path;

/// Parse `--static-findings`: a JSON array of `scan-file --json` objects
/// (`jq -s .` over one file per scanned PKGBUILD/.install). A lone object is
/// accepted too. Missing/unparseable input degrades to no static findings.
pub fn parse_static_findings(path: Option<&Path>) -> Vec<Finding> {
    let Some(text) = path.and_then(|p| std::fs::read_to_string(p).ok()) else {
        return Vec::new();
    };
    let files = serde_json::from_str::<Vec<FileFindings>>(&text)
        .or_else(|_| serde_json::from_str::<FileFindings>(&text).map(|f| vec![f]))
        .unwrap_or_default();
    files
        .iter()
        .flat_map(|ff| {
            ff.findings
                .iter()
                .map(|f| Finding::from_scanner(f, ff.file.as_str()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::{Behavior, Severity};

    const SAMPLE: &str = r#"[
      {"file":"PKGBUILD","findings":[
        {"rule_id":"EXFIL_DISCORD_WEBHOOK","severity":"CRITICAL","description":"webhook","line_number":7,"matched_text":"discord.com/api/webhooks","behavior":"NETWORK_ACCESS"},
        {"rule_id":"SUS_VARIABLE_SPLICING","severity":"HIGH","description":"splicing","line_number":2,"matched_text":"a=b","behavior":"OBFUSCATION"}]},
      {"file":"foo.install","findings":[
        {"rule_id":"PERSIST_CRON","severity":"CRITICAL","description":"cron","line_number":3,"matched_text":"crontab -","behavior":"PERSISTENCE"}]}
    ]"#;

    fn write_tmp(name: &str, content: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "aur_sentry_static_{}_{name}.json",
            std::process::id()
        ));
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn parses_multi_file_json_preserving_file_and_behavior() {
        let path = write_tmp("multi", SAMPLE);
        let findings = parse_static_findings(Some(&path));
        let _ = std::fs::remove_file(&path);

        assert_eq!(findings.len(), 3);
        assert_eq!(findings[0].file, "PKGBUILD");
        assert_eq!(findings[0].behavior, Behavior::NetworkAccess);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].line, 7);
        assert_eq!(findings[1].behavior, Behavior::Obfuscation);
        assert_eq!(findings[1].severity, Severity::High);
        assert_eq!(findings[2].file, "foo.install");
        assert_eq!(findings[2].behavior, Behavior::Persistence);
        assert_eq!(findings[2].line, 3);
    }

    #[test]
    fn accepts_single_scan_file_object() {
        let path = write_tmp(
            "single",
            r#"{"file":"PKGBUILD","findings":[{"rule_id":"CRED_SSH_KEYS","severity":"CRITICAL","description":"ssh","line_number":1,"matched_text":"~/.ssh/id_rsa","behavior":"CREDENTIAL_ACCESS"}]}"#,
        );
        let findings = parse_static_findings(Some(&path));
        let _ = std::fs::remove_file(&path);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].behavior, Behavior::CredentialAccess);
    }

    #[test]
    fn missing_or_garbage_input_yields_no_findings() {
        assert!(parse_static_findings(None).is_empty());
        let path = write_tmp("garbage", "[CRITICAL] not json");
        assert!(parse_static_findings(Some(&path)).is_empty());
        let _ = std::fs::remove_file(&path);
    }
}
