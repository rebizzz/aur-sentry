//! Assembles a full `attestation::Attestation` from the static analyzer's
//! text output and the dynamic sandbox's strace telemetry log — the native
//! replacement for `scripts/build_attestation.py` (see that file for the
//! reference behavior this ports; not required to be byte-identical).

use crate::attestation::{
    Attestation, Behavior, DynamicEvidence, ElfObjectInfo, FilesystemEvent, Finding,
    IntelligenceEntry, NetworkEvent, PackageAnalysis, PackageIdentity, ReproducibilityStatus,
    Severity, SourceIdentity, Verdict, verdict_from_findings,
};
use crate::scanner;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::net::ToSocketAddrs;
use std::path::Path;
use std::sync::LazyLock;

static FINDING_BLOCK_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
        r"(?m)\[(?P<sev>[A-Z]+)\]\s+(?P<rule>\S+)\s*\n\s*(?P<desc>.+?)\s*\n\s*line (?P<line>\d+): (?P<matched>.*)",
    )
    .unwrap()
});

static STRACE_CONNECT_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
        r#"(?:connect|sendto)\(.*?sin_port=htons\((?P<port>\d+)\).*?sin_addr=inet_addr\("(?P<ip>[\d.]+)"\)"#,
    )
    .unwrap()
});

// `[^")]*` (not just `[^)]*`, unlike build_attestation.py's version of this
// regex) so the greedy prefix can't backtrack past the *closing* quote of
// the path and swallow text from a subsequent syscall on the same line.
static STRACE_OPEN_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r#"open(?:at)?\([^")]*"(?P<path>[^"]+)""#).unwrap());

static URL_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r#"https?://[^\s"'()]+"#).unwrap());

const SEVERITIES: [&str; 5] = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];

/// Heuristic rule_id/description keyword -> Behavior mapping, ported from
/// scripts/build_attestation.py's BEHAVIOR_KEYWORDS so both assemblers agree.
const BEHAVIOR_KEYWORDS: &[(&[&str], Behavior)] = &[
    (&["OBFUSCAT", "BASE64", "HEX"], Behavior::Obfuscation),
    (
        &[
            "CREDENTIAL",
            "SSH",
            "AWS",
            "GCLOUD",
            "KUBE",
            "PASSWORD",
            "TOKEN",
            "BROWSER",
        ],
        Behavior::CredentialAccess,
    ),
    (
        &[
            "CURL", "WGET", "NETWORK", "DOWNLOAD", "HTTP", "WEBHOOK", "C2", "EXFIL",
        ],
        Behavior::NetworkAccess,
    ),
    (
        &[
            "CRON",
            "SYSTEMD",
            "AUTOSTART",
            "PERSIST",
            "BASHRC",
            "PROFILE.D",
        ],
        Behavior::Persistence,
    ),
    (
        &["SUID", "SUDO", "ROOT", "PRIVILEGE"],
        Behavior::PrivilegeEscalation,
    ),
    (&["SERVICE", "SYSTEMCTL"], Behavior::ServiceManipulation),
    (
        &["PACMAN", "MAKEPKG", "INSTALL"],
        Behavior::PackageInstallation,
    ),
    (
        &["CHMOD", "RM ", "WRITE", "DD ", "/DEV/"],
        Behavior::ArbitraryFilesystemWrite,
    ),
    (
        &["EVAL", "PIPE", "SH -C", "BASH -C", "EXEC"],
        Behavior::ShellExecution,
    ),
];

fn classify_behavior(rule_id: &str, description: &str) -> Behavior {
    let hay = format!("{rule_id} {description}").to_uppercase();
    for (keywords, behavior) in BEHAVIOR_KEYWORDS {
        if keywords.iter().any(|k| hay.contains(k)) {
            return *behavior;
        }
    }
    Behavior::ShellExecution // conservative default — something matched a rule at all
}

/// Parse the human-readable text emitted by `scan-file`/`scan-pkg`'s
/// `print_findings` (caller must strip ANSI codes first, as the sandbox
/// script already does) into attestation findings via `Finding::from_scanner`.
pub fn parse_static_findings(text: &str) -> Vec<Finding> {
    FINDING_BLOCK_RE
        .captures_iter(text)
        .filter_map(|cap| {
            let sev = cap["sev"].to_string();
            if !SEVERITIES.contains(&sev.as_str()) {
                return None;
            }
            let rule_id = cap["rule"].to_string();
            let description = cap["desc"].trim().to_string();
            let line_number: usize = cap["line"].parse().ok()?;
            let matched_text = cap["matched"].to_string();
            let behavior = classify_behavior(&rule_id, &description);

            let scanner_finding = scanner::Finding {
                rule_id,
                severity: sev,
                description,
                line_number,
                matched_text,
            };
            Some(Finding::from_scanner(
                &scanner_finding,
                behavior,
                "PKGBUILD",
            ))
        })
        .collect()
}

/// Best-effort DNS resolution of PKGBUILD `source=()` hosts, so telemetry
/// connections outside this allowlist can be flagged as undeclared network.
pub fn declared_source_ips(pkgbuild_text: &str) -> HashSet<String> {
    let mut ips = HashSet::new();
    for m in URL_RE.find_iter(pkgbuild_text) {
        let Some(host) = extract_host(m.as_str()) else {
            continue;
        };
        if let Ok(mut addrs) = (host.as_str(), 80u16).to_socket_addrs() {
            if let Some(addr) = addrs.next() {
                ips.insert(addr.ip().to_string());
            }
        }
    }
    ips
}

fn extract_host(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://")?.1;
    let host_port = after_scheme.split(['/', '?', '#']).next()?;
    let host = host_port.rsplit('@').next()?.split(':').next()?;
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// Parse strace `-e trace=network,file` output into network/filesystem
/// events. Process events aren't recoverable from this telemetry shape yet,
/// so that vector stays empty (mirrors the Python fallback).
pub fn parse_telemetry(
    text: &str,
    allowed_ips: &HashSet<String>,
) -> (Vec<NetworkEvent>, Vec<FilesystemEvent>) {
    let now = chrono::Utc::now().to_rfc3339();

    let mut network = Vec::new();
    let mut seen_net = HashSet::new();
    for cap in STRACE_CONNECT_RE.captures_iter(text) {
        let Ok(port) = cap["port"].parse::<u16>() else {
            continue;
        };
        let ip = cap["ip"].to_string();
        if !seen_net.insert((ip.clone(), port)) {
            continue;
        }
        let undeclared = !allowed_ips.contains(&ip) && !ip.starts_with("127.");
        network.push(NetworkEvent {
            destination: ip,
            port: Some(port),
            protocol: Some(if undeclared {
                "undeclared".into()
            } else {
                "declared-source".into()
            }),
            timestamp: now.clone(),
        });
    }

    let mut filesystem = Vec::new();
    let mut seen_fs = HashSet::new();
    for cap in STRACE_OPEN_RE.captures_iter(text) {
        let path = cap["path"].to_string();
        if !path.contains("id_fake") && !path.contains(".aws/credentials") {
            continue;
        }
        if !seen_fs.insert(path.clone()) {
            continue;
        }
        filesystem.push(FilesystemEvent {
            path,
            operation: "canary_access".into(),
            timestamp: now.clone(),
        });
    }

    (network, filesystem)
}

/// Shape of the JSON blob `scripts/dynamic_sandbox.sh` assembles with `jq`
/// from its package-extraction/ELF-analysis pass (see `--package-analysis`).
/// A superset of `attestation::PackageAnalysis`: it additionally carries the
/// raw setuid/world-writable paths so `build_attestation` can turn them into
/// `Finding`s, since the stored `PackageAnalysis` only needs the counts.
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
/// failing the attestation (matches this module's general leniency).
fn parse_package_analysis(path: Option<&Path>) -> (PackageAnalysis, Vec<Finding>) {
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

/// Shape of the JSON array `scripts/dynamic_sandbox.sh` assembles (`jq`,
/// from OSV.dev query results — see `--external-intel`). Deliberately the
/// same shape as `attestation::IntelligenceEntry` itself: there's no extra
/// raw data to carry (unlike `PackageAnalysisInput`), just evidence entries
/// ready to store as-is.
#[derive(Debug, Deserialize)]
struct IntelligenceEntryInput {
    source: String,
    summary: String,
    #[serde(default)]
    url: Option<String>,
}

/// Parse the `--external-intel` JSON blob into `IntelligenceEntry`s. Any
/// missing/unreadable/unparseable file degrades to "no external evidence"
/// rather than failing the attestation (matches this module's general
/// leniency for optional evidence sources).
///
/// Deliberately returns no `Finding`s: per ARCHITECTURE.md's "external
/// signals become another evidence source" design and this project's
/// existing `reproducibility`-is-informational-only precedent,
/// `external_intelligence` never feeds `verdict_from_findings`. OSV
/// correlation here is a best-effort, sometimes name-guessed match (see
/// scripts/dynamic_sandbox.sh) rather than a directly-observed fact about
/// *this* build the way canary/network/setuid evidence is, so it stays
/// informational until that confidence bar is met.
fn parse_external_intelligence(path: Option<&Path>) -> Vec<IntelligenceEntry> {
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

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// Everything `build_attestation` needs — mirrors the flags `aur-sentry
/// attest` exposes on the CLI (see main.rs) and build_attestation.py's args.
pub struct AttestInputs<'a> {
    pub package: String,
    pub version: String,
    pub arch: String,
    pub aur_commit: String,
    pub pkgbuild_path: Option<&'a Path>,
    pub install_path: Option<&'a Path>,
    pub static_findings_path: Option<&'a Path>,
    pub telemetry_path: Option<&'a Path>,
    /// Path to the package-content/ELF-analysis JSON blob assembled by
    /// `scripts/dynamic_sandbox.sh` (`jq`, from the real `makepkg`-built
    /// package). `None`/unreadable/unparseable degrades to an "unavailable"
    /// `PackageAnalysis` rather than failing the attestation.
    pub package_analysis_path: Option<&'a Path>,
    /// Path to the `external_intel.json` array assembled by
    /// `scripts/dynamic_sandbox.sh` from OSV.dev vulnerability-query
    /// results (dependency names + the upstream project's Go-module
    /// identity when `url=` is a github.com repo — see that script for the
    /// exact, deliberately modest correlation it attempts).
    /// `None`/unreadable/unparseable degrades to no external evidence
    /// rather than failing the attestation. Purely informational: never
    /// feeds `verdict_from_findings` (see `parse_external_intelligence`).
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

    let static_text = inputs
        .static_findings_path
        .and_then(|p| std::fs::read_to_string(p).ok())
        .unwrap_or_default();
    let mut findings = parse_static_findings(&static_text);

    let allowed_ips = pkgbuild_text
        .as_deref()
        .map(declared_source_ips)
        .unwrap_or_default();

    let (network, filesystem) = if inputs.strace_available {
        let telemetry_text = inputs
            .telemetry_path
            .and_then(|p| std::fs::read_to_string(p).ok())
            .unwrap_or_default();
        parse_telemetry(&telemetry_text, &allowed_ips)
    } else {
        (Vec::new(), Vec::new())
    };

    // Fold dynamic evidence into the same finding set so `verdict_from_findings`
    // (Phase 1's single source of verdict truth) sees canary/network hits too,
    // instead of duplicating verdict logic here.
    if !filesystem.is_empty() {
        let touched: Vec<&str> = filesystem.iter().map(|f| f.path.as_str()).collect();
        findings.push(Finding {
            behavior: Behavior::CredentialAccess,
            file: "dynamic-sandbox".into(),
            line: 0,
            severity: Severity::Critical,
            description: format!(
                "canary secret accessed during build: {}",
                touched.join(", ")
            ),
        });
    }
    if network
        .iter()
        .any(|n| n.protocol.as_deref() == Some("undeclared"))
    {
        findings.push(Finding {
            behavior: Behavior::NetworkAccess,
            file: "dynamic-sandbox".into(),
            line: 0,
            severity: Severity::High,
            description: "connected to network destination(s) not declared in PKGBUILD source=()"
                .into(),
        });
    }

    let (package_analysis, package_findings) = parse_package_analysis(inputs.package_analysis_path);
    findings.extend(package_findings);

    let external_intelligence = parse_external_intelligence(inputs.external_intelligence_path);

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

    const SAMPLE_STATIC_LOG: &str = "\n  threat(s) detected\n\n  [CRITICAL] EXFIL_DISCORD_WEBHOOK\n     discord webhook exfil\n     line 7: discord.com/api/webhooks\n\n  [HIGH] SUS_VARIABLE_SPLICING\n     variable splicing\n     line 2: a=b\n\n";

    #[test]
    fn parses_static_findings_from_scan_file_text_output() {
        let findings = parse_static_findings(SAMPLE_STATIC_LOG);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].behavior, Behavior::NetworkAccess);
        assert_eq!(findings[0].line, 7);
        assert_eq!(findings[1].severity, Severity::High);
    }

    #[test]
    fn classify_behavior_matches_keyword_map() {
        assert_eq!(
            classify_behavior("EXFIL_DISCORD_WEBHOOK", "webhook"),
            Behavior::NetworkAccess
        );
        assert_eq!(
            classify_behavior("REVSHELL_DEV_TCP", "reverse shell"),
            Behavior::ShellExecution
        );
        assert_eq!(
            classify_behavior("CRED_SSH_KEY_READ", "reads ssh key"),
            Behavior::CredentialAccess
        );
        assert_eq!(
            classify_behavior("CRON_PERSIST", "adds cron job"),
            Behavior::Persistence
        );
    }

    #[test]
    fn parses_telemetry_connect_and_canary_open() {
        let text = concat!(
            "12345 connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr(\"1.2.3.4\")}, 16) = 0\n",
            "12345 openat(AT_FDCWD, \"/home/builder/.ssh/id_fake\", O_RDONLY) = 4\n",
            "12345 openat(AT_FDCWD, \"/etc/passwd\", O_RDONLY) = 5\n",
        );
        let allowed: HashSet<String> = HashSet::new();
        let (network, filesystem) = parse_telemetry(text, &allowed);
        assert_eq!(network.len(), 1);
        assert_eq!(network[0].destination, "1.2.3.4");
        assert_eq!(network[0].protocol.as_deref(), Some("undeclared"));
        assert_eq!(filesystem.len(), 1);
        assert!(filesystem[0].path.contains("id_fake"));
    }

    #[test]
    fn declared_ip_is_not_flagged_as_undeclared() {
        let text = "12345 connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr(\"127.0.0.1\")}, 16) = 0\n";
        let allowed: HashSet<String> = HashSet::new();
        let (network, _) = parse_telemetry(text, &allowed);
        assert_eq!(network[0].protocol.as_deref(), Some("declared-source"));
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
            strace_available: false,
            makepkg_exit: Some(1),
            scanner_version: "test".into(),
            reproducibility: ReproducibilityStatus::NotAttempted,
        };
        let att = build_attestation(&inputs);
        assert_eq!(att.verdict, Verdict::BuildFailed);
    }
}
