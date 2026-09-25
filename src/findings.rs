//! Scanner-level finding type shared by the static scanner, the analyzer
//! passes, the advisory reports, and the `--json` output that
//! `attest --static-findings` consumes.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Behavior {
    NetworkAccess,
    ShellExecution,
    CredentialAccess,
    Persistence,
    PrivilegeEscalation,
    Obfuscation,
    DynamicDownload,
    ArbitraryFilesystemWrite,
    PackageInstallation,
    ServiceManipulation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub severity: String,
    pub description: String,
    pub line_number: usize,
    pub matched_text: String,
    // advisories.json written before findings carried a behavior must still load
    #[serde(default = "legacy_behavior")]
    pub behavior: Behavior,
}

fn legacy_behavior() -> Behavior {
    Behavior::ShellExecution
}

/// One scanned file's findings: the `scan-file --json` output object and one
/// element of the array `attest --static-findings` reads.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileFindings {
    pub file: String,
    pub findings: Vec<Finding>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_findings_json_shape() {
        let ff = FileFindings {
            file: "PKGBUILD".into(),
            findings: vec![Finding {
                rule_id: "EXFIL_DISCORD_WEBHOOK".into(),
                severity: "CRITICAL".into(),
                description: "webhook".into(),
                line_number: 7,
                matched_text: "discord.com/api/webhooks".into(),
                behavior: Behavior::NetworkAccess,
            }],
        };
        let json = serde_json::to_string(&ff).unwrap();
        assert_eq!(
            json,
            r#"{"file":"PKGBUILD","findings":[{"rule_id":"EXFIL_DISCORD_WEBHOOK","severity":"CRITICAL","description":"webhook","line_number":7,"matched_text":"discord.com/api/webhooks","behavior":"NETWORK_ACCESS"}]}"#
        );
    }

    #[test]
    fn legacy_finding_without_behavior_still_deserializes() {
        let f: Finding = serde_json::from_str(
            r#"{"rule_id":"X","severity":"HIGH","description":"d","line_number":1,"matched_text":"m"}"#,
        )
        .unwrap();
        assert_eq!(f.behavior, Behavior::ShellExecution);
    }
}
