//! `check`: look up the published attestation registry for a package.
//!
//! Native equivalent of bin/safeaur's fetch_attestation()/check_attestation_policy():
//! look up the published attestation registry (data/attestations/<pkg>/<version>.json)
//! over the GitHub Contents/raw APIs, no auth required. Missing/unreachable
//! data is always treated as "no attestation found" — the registry is new
//! and sparse, so it must never break a normal `check && makepkg` pipeline.

use crate::attestation::{Attestation, ReproducibilityStatus, Severity, Verdict};
use crate::ui::*;
use serde::Deserialize;
use std::cmp::Ordering;
use std::process::ExitCode;

// Published attestation registry (see ARCHITECTURE.md Phase 4 / bin/safeaur's
// fetch_attestation()). No auth needed — public repo, read-only.
const GH_CONTENTS_API: &str =
    "https://api.github.com/repos/rebizzz/aur-sentry/contents/data/attestations";
const GH_RAW_BASE: &str =
    "https://raw.githubusercontent.com/rebizzz/aur-sentry/main/data/attestations";

#[derive(Debug, Deserialize)]
struct GhContentEntry {
    name: String,
}

fn build_registry_agent() -> ureq::Agent {
    let config = ureq::config::Config::builder()
        .timeout_global(Some(std::time::Duration::from_secs(10)))
        .build();
    ureq::Agent::new_with_config(config)
}

/// Natural ("sort -V"-like) comparison for `pkgver-pkgrel` version strings:
/// splits into alternating digit/non-digit runs and compares numeric runs
/// numerically so "1.9-1" sorts before "1.10-1".
fn compare_versions(a: &str, b: &str) -> Ordering {
    fn chunks(v: &str) -> Vec<Result<u64, &str>> {
        let bytes = v.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            let start = i;
            if bytes[i].is_ascii_digit() {
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                out.push(Ok(v[start..i].parse::<u64>().unwrap_or(0)));
            } else {
                while i < bytes.len() && !bytes[i].is_ascii_digit() {
                    i += 1;
                }
                out.push(Err(&v[start..i]));
            }
        }
        out
    }

    let (ca, cb) = (chunks(a), chunks(b));
    for pair in ca.iter().zip(cb.iter()) {
        let ord = match pair {
            (Ok(x), Ok(y)) => x.cmp(y),
            (Err(x), Err(y)) => x.cmp(y),
            // A numeric chunk outranks a non-numeric chunk at the same
            // position (matches GNU sort -V's behavior).
            (Ok(_), Err(_)) => Ordering::Greater,
            (Err(_), Ok(_)) => Ordering::Less,
        };
        if ord != Ordering::Equal {
            return ord;
        }
    }
    ca.len().cmp(&cb.len())
}

fn pick_highest_version(versions: &[String]) -> Option<String> {
    versions
        .iter()
        .max_by(|a, b| compare_versions(a, b))
        .cloned()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LineStatus {
    Ok,
    Warn,
    Bad,
    Neutral,
}

fn status_icon(s: LineStatus) -> &'static str {
    match s {
        LineStatus::Ok => "✓",
        LineStatus::Warn => "⚠",
        LineStatus::Bad => "✗",
        LineStatus::Neutral => "•",
    }
}

fn status_color(s: LineStatus) -> &'static str {
    match s {
        LineStatus::Ok => GREEN,
        LineStatus::Warn => YELLOW,
        LineStatus::Bad => RED,
        LineStatus::Neutral => DIM,
    }
}

/// Derive a plain-language checklist from an attestation's evidence,
/// mirroring docs/package.html's `buildPlainSummary()` phrasing so the CLI
/// and the web registry read consistently.
fn build_checklist(att: &Attestation) -> Vec<(LineStatus, String)> {
    let mut lines = Vec::new();

    if att.verdict == Verdict::BuildFailed {
        lines.push((LineStatus::Bad, "Build failed".to_string()));
    } else {
        lines.push((LineStatus::Ok, "Build succeeded".to_string()));
    }

    let findings = &att.static_findings;
    let high_sev = findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::High | Severity::Critical))
        .count();
    if findings.is_empty() {
        lines.push((
            LineStatus::Ok,
            "No suspicious code patterns found in the PKGBUILD".to_string(),
        ));
    } else if high_sev > 0 {
        lines.push((
            LineStatus::Bad,
            format!("{high_sev} high/critical severity finding(s) in the PKGBUILD"),
        ));
    } else {
        lines.push((
            LineStatus::Warn,
            format!(
                "{} lower-severity finding(s) in the PKGBUILD",
                findings.len()
            ),
        ));
    }

    let dyn_ev = &att.dynamic_evidence;
    if !dyn_ev.collected {
        lines.push((
            LineStatus::Neutral,
            "No dynamic sandbox run performed for this attestation yet".to_string(),
        ));
    } else {
        let undeclared = dyn_ev
            .network
            .iter()
            .filter(|n| n.protocol.as_deref() == Some("undeclared"))
            .count();
        if undeclared > 0 {
            lines.push((
                LineStatus::Bad,
                format!(
                    "{undeclared} network connection(s) to destinations not declared in the PKGBUILD"
                ),
            ));
        } else {
            lines.push((
                LineStatus::Ok,
                "No suspicious network connections".to_string(),
            ));
        }

        let canary = dyn_ev
            .filesystem
            .iter()
            .filter(|f| f.operation == "canary_access")
            .count();
        if canary > 0 {
            lines.push((
                LineStatus::Bad,
                format!("Touched {canary} canary credential file(s) planted for detection"),
            ));
        } else {
            lines.push((
                LineStatus::Ok,
                "Canary credentials were not touched".to_string(),
            ));
        }
    }

    match att.reproducibility {
        ReproducibilityStatus::Reproduced => lines.push((
            LineStatus::Ok,
            "Build was independently reproduced".to_string(),
        )),
        ReproducibilityStatus::Diverged => lines.push((
            LineStatus::Bad,
            "A second independent build produced a different result".to_string(),
        )),
        ReproducibilityStatus::Failed => {
            lines.push((LineStatus::Warn, "Reproducibility build failed".to_string()))
        }
        _ => lines.push((
            LineStatus::Neutral,
            "Reproducibility not yet attempted".to_string(),
        )),
    }

    lines
}

fn verdict_style(v: Verdict) -> (&'static str, &'static str) {
    match v {
        Verdict::Verified => (GREEN, ICON_CHECK),
        Verdict::Malicious => (RED, ICON_SKULL),
        Verdict::Suspicious
        | Verdict::Stale
        | Verdict::Inconclusive
        | Verdict::Unsupported
        | Verdict::BuildFailed
        | Verdict::AnalysisFailed => (YELLOW, ICON_WARN),
    }
}

/// Verdict -> ExitCode mapping shared with `attest`, so `aur-sentry check
/// <pkg> && makepkg` is a usable manual pre-build gate, same spirit as
/// `safeaur check`.
pub(super) fn verdict_exit_code(v: Verdict) -> ExitCode {
    match v {
        Verdict::Verified => ExitCode::SUCCESS,
        _ => ExitCode::from(2),
    }
}

pub fn run(pkgname: &str) -> ExitCode {
    eprintln!(
        "{BLUE}{ICON_SEARCH} checking attestation registry for {BOLD}{pkgname}{RESET}{BLUE}...{RESET}"
    );

    let agent = build_registry_agent();

    let listing_url = format!("{GH_CONTENTS_API}/{pkgname}");
    let versions: Vec<String> = match agent
        .get(&listing_url)
        .header("User-Agent", "aur-sentry-cli")
        .header("Accept", "application/vnd.github+json")
        .call()
    {
        Ok(mut resp) => resp
            .body_mut()
            .read_json::<Vec<GhContentEntry>>()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|e| e.name.strip_suffix(".json").map(|s| s.to_string()))
            .collect(),
        Err(_) => Vec::new(),
    };

    let Some(version) = pick_highest_version(&versions) else {
        eprintln!();
        eprintln!(
            "  {YELLOW}{ICON_WARN} No attestation found for '{BOLD}{pkgname}{RESET}{YELLOW}' — package has not been analyzed yet.{RESET}"
        );
        return ExitCode::SUCCESS;
    };

    let raw_url = format!("{GH_RAW_BASE}/{pkgname}/{version}.json");
    let attestation: Attestation = match agent
        .get(&raw_url)
        .header("User-Agent", "aur-sentry-cli")
        .call()
    {
        Ok(mut resp) => match resp.body_mut().read_json() {
            Ok(a) => a,
            Err(e) => {
                eprintln!(
                    "  {RED}{ICON_CROSS} failed to parse attestation for '{pkgname}' v{version}: {e}{RESET}"
                );
                return ExitCode::SUCCESS;
            }
        },
        Err(e) => {
            eprintln!(
                "  {RED}{ICON_CROSS} failed to fetch attestation for '{pkgname}' v{version}: {e}{RESET}"
            );
            return ExitCode::SUCCESS;
        }
    };

    let signed = agent.head(&format!("{raw_url}.sig")).call().is_ok()
        && agent.head(&format!("{raw_url}.cert")).call().is_ok();

    print_check_report(pkgname, &attestation, signed);
    verdict_exit_code(attestation.verdict)
}

fn print_check_report(pkgname: &str, att: &Attestation, signed: bool) {
    let (color, icon) = verdict_style(att.verdict);
    let short_commit = if att.source.aur_commit.is_empty() {
        "unknown".to_string()
    } else {
        att.source.aur_commit.chars().take(8).collect()
    };

    eprintln!();
    eprintln!(
        "{CYAN}{ICON_PKG} {BOLD}{pkgname}{RESET}{CYAN} v{}{RESET}",
        att.package.version
    );
    eprintln!("  {DIM}AUR commit     {short_commit}{RESET}");
    eprintln!("  {DIM}last analyzed  {}{RESET}", att.analyzed_at);
    eprintln!();

    for (status, text) in build_checklist(att) {
        eprintln!(
            "  {}{} {text}{RESET}",
            status_color(status),
            status_icon(status)
        );
    }

    if signed {
        eprintln!(
            "  {GREEN}✓{RESET} Cryptographically signed {DIM}— verify independently with `scripts/verify_attestation.sh {pkgname} {}`{RESET}",
            att.package.version
        );
    }

    eprintln!();
    eprintln!("  {color}{icon} verdict: {BOLD}{:?}{RESET}", att.verdict);
    eprintln!();
}

#[cfg(test)]
mod check_tests {
    use super::*;
    use crate::attestation::{
        Behavior, DynamicEvidence, FilesystemEvent, NetworkEvent, PackageAnalysis, PackageIdentity,
        SourceIdentity,
    };

    fn sample_attestation() -> Attestation {
        Attestation {
            schema_version: "1.0".into(),
            package: PackageIdentity {
                name: "foo".into(),
                version: "1.0-1".into(),
                arch: "x86_64".into(),
            },
            source: SourceIdentity {
                aur_commit: "deadbeefcafefeed".into(),
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
    fn compare_versions_orders_numeric_runs_numerically() {
        assert_eq!(compare_versions("1.9-1", "1.10-1"), Ordering::Less);
        assert_eq!(compare_versions("2.0-1", "1.9-2"), Ordering::Greater);
        assert_eq!(compare_versions("1.0-1", "1.0-1"), Ordering::Equal);
        assert_eq!(compare_versions("1.0-1", "1.0-2"), Ordering::Less);
    }

    #[test]
    fn pick_highest_version_picks_max_via_version_compare() {
        let versions = vec![
            "1.2-1".to_string(),
            "1.10-1".to_string(),
            "1.9-3".to_string(),
        ];
        assert_eq!(pick_highest_version(&versions), Some("1.10-1".to_string()));
    }

    #[test]
    fn pick_highest_version_empty_is_none() {
        assert_eq!(pick_highest_version(&[]), None);
    }

    #[test]
    fn verdict_exit_code_verified_is_success() {
        assert_eq!(verdict_exit_code(Verdict::Verified), ExitCode::SUCCESS);
    }

    #[test]
    fn verdict_exit_code_non_verified_is_nonzero() {
        for v in [
            Verdict::Suspicious,
            Verdict::Malicious,
            Verdict::Inconclusive,
            Verdict::BuildFailed,
            Verdict::AnalysisFailed,
            Verdict::Stale,
            Verdict::Unsupported,
        ] {
            assert_eq!(verdict_exit_code(v), ExitCode::from(2));
        }
    }

    #[test]
    fn checklist_clean_attestation_is_all_ok_or_neutral() {
        let att = sample_attestation();
        let lines = build_checklist(&att);
        assert!(
            lines
                .iter()
                .any(|(s, t)| *s == LineStatus::Ok && t == "Build succeeded")
        );
        assert!(lines.iter().any(|(s, t)| *s == LineStatus::Ok
            && t == "No suspicious code patterns found in the PKGBUILD"));
        assert!(lines.iter().any(|(s, t)| *s == LineStatus::Neutral
            && t == "No dynamic sandbox run performed for this attestation yet"));
        assert!(lines
            .iter()
            .any(|(s, t)| *s == LineStatus::Neutral && t == "Reproducibility not yet attempted"));
    }

    #[test]
    fn checklist_build_failed_verdict_flags_bad() {
        let mut att = sample_attestation();
        att.verdict = Verdict::BuildFailed;
        let lines = build_checklist(&att);
        assert_eq!(lines[0], (LineStatus::Bad, "Build failed".to_string()));
    }

    #[test]
    fn checklist_high_severity_finding_is_bad() {
        let mut att = sample_attestation();
        att.static_findings.push(crate::attestation::Finding {
            behavior: Behavior::Obfuscation,
            file: "PKGBUILD".into(),
            line: 3,
            severity: Severity::Critical,
            description: "packed payload".into(),
        });
        let lines = build_checklist(&att);
        assert!(lines.iter().any(|(s, t)| *s == LineStatus::Bad
            && t == "1 high/critical severity finding(s) in the PKGBUILD"));
    }

    #[test]
    fn checklist_undeclared_network_and_canary_hits_are_bad() {
        let mut att = sample_attestation();
        att.dynamic_evidence = DynamicEvidence {
            collected: true,
            processes: vec![],
            network: vec![NetworkEvent {
                destination: "1.2.3.4".into(),
                port: Some(443),
                protocol: Some("undeclared".into()),
                timestamp: "2026-01-01T00:00:00Z".into(),
                phase: "build".into(),
            }],
            filesystem: vec![FilesystemEvent {
                path: "/home/user/.ssh/id_rsa".into(),
                operation: "canary_access".into(),
                timestamp: "2026-01-01T00:00:00Z".into(),
                phase: "build".into(),
            }],
        };
        let lines = build_checklist(&att);
        assert!(lines.iter().any(|(s, t)| *s == LineStatus::Bad
            && t.contains("network connection(s) to destinations not declared")));
        assert!(
            lines
                .iter()
                .any(|(s, t)| *s == LineStatus::Bad && t.contains("canary credential file(s)"))
        );
    }

    #[test]
    fn checklist_reproduced_status_is_ok() {
        let mut att = sample_attestation();
        att.reproducibility = ReproducibilityStatus::Reproduced;
        let lines = build_checklist(&att);
        assert!(
            lines
                .iter()
                .any(|(s, t)| *s == LineStatus::Ok && t == "Build was independently reproduced")
        );
    }

    #[test]
    fn verdict_style_maps_severity_colors() {
        assert_eq!(verdict_style(Verdict::Verified), (GREEN, ICON_CHECK));
        assert_eq!(verdict_style(Verdict::Malicious), (RED, ICON_SKULL));
        assert_eq!(verdict_style(Verdict::Suspicious), (YELLOW, ICON_WARN));
    }
}
