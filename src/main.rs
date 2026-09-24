#![allow(clippy::collapsible_if)]

//! CLI entry point for AUR-Sentry.
//! Nerdfont-powered, colored, human-readable output.

use aur_sentry::attest::{self, AttestInputs};
use aur_sentry::attestation::{Attestation, ReproducibilityStatus, Severity, Verdict};
use aur_sentry::aur_client::AURClient;
use aur_sentry::report::{self, Advisory};
use aur_sentry::scanner::PKGBUILDScanner;
use clap::{Parser, Subcommand};
use rayon::prelude::*;
use serde::Deserialize;
use std::cmp::Ordering;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::LazyLock;

// Published attestation registry (see ARCHITECTURE.md Phase 4 / bin/safeaur's
// fetch_attestation()). No auth needed — public repo, read-only.
const GH_CONTENTS_API: &str =
    "https://api.github.com/repos/rebizzz/aur-sentry/contents/data/attestations";
const GH_RAW_BASE: &str =
    "https://raw.githubusercontent.com/rebizzz/aur-sentry/main/data/attestations";

static INSTALL_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r##"install=\s*['"]?([a-zA-Z0-9._-]+\.install)"##).unwrap());

// ── Nerdfont glyphs & ANSI colors ───────────────────────────────────

const RED: &str = "\x1b[1;31m";
const GREEN: &str = "\x1b[1;32m";
const YELLOW: &str = "\x1b[1;33m";
const BLUE: &str = "\x1b[1;34m";
const MAGENTA: &str = "\x1b[1;35m";
const CYAN: &str = "\x1b[1;36m";
const DIM: &str = "\x1b[2m";
const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";

// Nerdfont icons
const ICON_SHIELD: &str = "󰒃"; // nf-md-shield_check
const ICON_SKULL: &str = "󰚌"; // nf-md-skull
const ICON_WARN: &str = "󰀦"; // nf-md-alert
const ICON_BUG: &str = "󰨰"; // nf-md-bug
const ICON_SEARCH: &str = "󰍉"; // nf-md-magnify
const ICON_CHECK: &str = "󰄬"; // nf-md-check
const ICON_CROSS: &str = "󰅖"; // nf-md-close
const ICON_PKG: &str = "󰏗"; // nf-md-package_variant
const ICON_FIRE: &str = "󰈸"; // nf-md-fire
const ICON_DOWNLOAD: &str = "󰇚"; // nf-md-download
const ICON_RADAR: &str = "󰐻"; // nf-md-radar

fn severity_icon(sev: &str) -> &'static str {
    match sev {
        "CRITICAL" => ICON_SKULL,
        "HIGH" => ICON_FIRE,
        "MEDIUM" => ICON_WARN,
        "LOW" => ICON_BUG,
        _ => ICON_SEARCH,
    }
}

fn severity_color(sev: &str) -> &'static str {
    match sev {
        "CRITICAL" => RED,
        "HIGH" => YELLOW,
        "MEDIUM" => MAGENTA,
        _ => DIM,
    }
}

// ── CLI definition ──────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "aur-sentry",
    version,
    about = "supply-chain security watchdog for the AUR"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)] // Attest carries many CLI flags; clap subcommand enums aren't hot-path values
enum Commands {
    /// Scan a local PKGBUILD or .install file
    ScanFile {
        /// Path to PKGBUILD or .install file
        path: PathBuf,
    },
    /// Scan a remote AUR package by name
    ScanPkg {
        /// AUR package name
        pkgname: String,
    },
    /// Check the published attestation registry for a package (Phase 4 —
    /// see ARCHITECTURE.md). Native equivalent of `bin/safeaur check`.
    Check {
        /// AUR package name
        pkgname: String,
    },
    /// Run full autopilot — downloads AUR metadata dump, scans recently
    /// modified packages, updates advisories
    Autopilot {
        /// Repo root for writing advisories.json, advisories.xml, README.md
        #[arg(long, default_value = ".")]
        repo_root: PathBuf,

        /// Scan packages modified in the last N hours
        #[arg(long, default_value_t = 6)]
        window_hours: u64,

        /// Max packages to scan per run
        #[arg(long, default_value_t = 500)]
        limit: usize,
    },
    /// Display active threat radar in the terminal
    Radar {
        /// Max threats to display
        #[arg(long, default_value_t = 25)]
        limit: usize,
    },
    /// Assemble an evidence-based Attestation JSON from static + dynamic
    /// sandbox evidence (native replacement for scripts/build_attestation.py)
    Attest {
        /// AUR package name
        pkgname: String,

        /// Resolved package version (pkgver-pkgrel)
        #[arg(long, default_value = "unknown")]
        version: String,

        /// Target architecture
        #[arg(long, default_value = "x86_64")]
        arch: String,

        /// AUR git commit the source was fetched at
        #[arg(long, default_value = "")]
        aur_commit: String,

        /// Path to the fetched PKGBUILD (for hashing + declared-source IPs)
        #[arg(long)]
        pkgbuild: Option<PathBuf>,

        /// Path to a .install file, if the package has one
        #[arg(long)]
        install_file: Option<PathBuf>,

        /// Path to scan-file/scan-pkg's ANSI-stripped text output
        #[arg(long)]
        static_findings: Option<PathBuf>,

        /// Path to the strace telemetry log from the dynamic sandbox
        #[arg(long)]
        telemetry: Option<PathBuf>,

        /// Path to the package-content/ELF-analysis JSON blob assembled by
        /// scripts/dynamic_sandbox.sh from the real makepkg-built package
        /// (file/ELF counts, setuid/world-writable findings). Missing/absent
        /// degrades to an "unavailable" package_analysis rather than failing.
        #[arg(long)]
        package_analysis: Option<PathBuf>,

        /// Whether strace telemetry was actually collected this run
        #[arg(long)]
        strace_available: bool,

        /// makepkg's exit code, if known
        #[arg(long)]
        makepkg_exit: Option<i32>,

        /// Reproducibility comparison result from a second independent
        /// makepkg build (NOT_ATTEMPTED | REPRODUCED | DIVERGED | FAILED |
        /// UNSUPPORTED). Informational evidence only — never affects verdict.
        #[arg(long, default_value = "NOT_ATTEMPTED")]
        reproducibility_status: String,

        /// Where to write the attestation JSON
        #[arg(long)]
        output: PathBuf,
    },
}

fn main() -> ExitCode {
    print_banner();
    let cli = Cli::parse();
    match cli.command {
        Commands::ScanFile { path } => cmd_scan_file(&path),
        Commands::ScanPkg { pkgname } => cmd_scan_pkg(&pkgname),
        Commands::Check { pkgname } => cmd_check(&pkgname),
        Commands::Autopilot {
            repo_root,
            window_hours,
            limit,
        } => cmd_autopilot(&repo_root, window_hours, limit),
        Commands::Radar { limit } => cmd_radar(limit),
        Commands::Attest {
            pkgname,
            version,
            arch,
            aur_commit,
            pkgbuild,
            install_file,
            static_findings,
            telemetry,
            package_analysis,
            strace_available,
            makepkg_exit,
            reproducibility_status,
            output,
        } => cmd_attest(
            &pkgname,
            &version,
            &arch,
            &aur_commit,
            pkgbuild.as_deref(),
            install_file.as_deref(),
            static_findings.as_deref(),
            telemetry.as_deref(),
            package_analysis.as_deref(),
            strace_available,
            makepkg_exit,
            &reproducibility_status,
            &output,
        ),
    }
}

fn print_banner() {
    eprintln!("{CYAN}{BOLD}");
    eprintln!("  {ICON_SHIELD}  AUR-Sentry v{}", env!("CARGO_PKG_VERSION"));
    eprintln!("  {DIM}supply-chain threat radar for the arch user repository{RESET}");
    eprintln!();
}

// ── scan-file ───────────────────────────────────────────────────────

fn cmd_scan_file(path: &Path) -> ExitCode {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "{RED}{ICON_CROSS} can't read {}: {e}{RESET}",
                path.display()
            );
            return ExitCode::FAILURE;
        }
    };
    eprintln!("{BLUE}{ICON_SEARCH} scanning {}{RESET}", path.display());
    let scanner = PKGBUILDScanner::new();
    let findings = scanner.scan(&content, None);
    print_findings(&findings);
    if findings.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    }
}

// ── scan-pkg ────────────────────────────────────────────────────────

fn cmd_scan_pkg(pkgname: &str) -> ExitCode {
    let client = AURClient::new();
    let scanner = PKGBUILDScanner::new();

    eprintln!(
        "{BLUE}{ICON_DOWNLOAD} fetching PKGBUILD for {BOLD}{pkgname}{RESET}{BLUE} from AUR...{RESET}"
    );
    let pkgbuild = match client.fetch_pkgbuild(pkgname) {
        Some(c) => c,
        None => {
            eprintln!(
                "{RED}{ICON_CROSS} couldn't find or download PKGBUILD for '{pkgname}'{RESET}"
            );
            return ExitCode::FAILURE;
        }
    };

    let mut findings = scanner.scan(&pkgbuild, Some(pkgname));

    // Also check .install file if referenced
    if let Some(cap) = INSTALL_RE.captures(&pkgbuild) {
        let install_name = &cap[1];
        eprintln!("{BLUE}{ICON_SEARCH} found .install ref: {install_name}, scanning...{RESET}");
        if let Some(install_content) = client.fetch_install_file(pkgname, install_name) {
            let install_findings = scanner.scan(&install_content, None);
            for mut f in install_findings {
                f.description = format!("[.install] {}", f.description);
                findings.push(f);
            }
        }
    }

    print_findings(&findings);
    if findings.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    }
}

// ── autopilot ───────────────────────────────────────────────────────

fn cmd_autopilot(repo_root: &Path, window_hours: u64, limit: usize) -> ExitCode {
    eprintln!("{CYAN}{ICON_RADAR} {BOLD}autopilot mode{RESET}");
    eprintln!("{DIM}  window: last {window_hours}h  |  limit: {limit} packages{RESET}");
    eprintln!();

    let client = AURClient::new();
    let scanner = PKGBUILDScanner::new();

    let recent = client.get_recently_modified(window_hours);
    let to_scan: Vec<_> = recent.into_iter().take(limit).collect();
    eprintln!(
        "{BLUE}{ICON_PKG} {BOLD}{}{RESET}{BLUE} packages modified in the last {window_hours}h{RESET}",
        to_scan.len()
    );

    // 1. Re-evaluate existing active advisories from previous windows in parallel
    let existing = report::load_advisories(repo_root);
    let mut active_advisories: Vec<Advisory> = Vec::new();
    let re_evaluated = existing.len() as u32;
    let mut resolved_count = 0u32;

    if !existing.is_empty() {
        eprintln!(
            "{CYAN}{ICON_RADAR} {BOLD}{}{RESET}{CYAN} active advisories from previous windows being re-evaluated in parallel...{RESET}",
            existing.len()
        );
        let results: Vec<Option<Advisory>> = existing
            .into_par_iter()
            .map(|mut adv| {
                let worker_client = AURClient::new();
                let pkg_info = worker_client.get_package_info(&adv.package);
                let pkgbuild_opt = worker_client.fetch_pkgbuild(&adv.package);

                if pkg_info.is_none() || pkgbuild_opt.is_none() {
                    eprintln!(
                        "  {YELLOW}{ICON_WARN} {BOLD}{}{RESET} removed from AUR (takedown) — resolving active advisory",
                        adv.package
                    );
                    return None;
                }

                let pkgbuild = pkgbuild_opt.unwrap();
                let mut findings = scanner.scan(&pkgbuild, Some(&adv.package));

                if let Some(cap) = INSTALL_RE.captures(&pkgbuild) {
                    if let Some(install_content) = worker_client.fetch_install_file(&adv.package, &cap[1]) {
                        let install_findings = scanner.scan(&install_content, None);
                        for mut f in install_findings {
                            f.description = format!("[.install] {}", f.description);
                            findings.push(f);
                        }
                    }
                }

                let actionable: Vec<_> = findings
                    .into_iter()
                    .filter(|f| f.severity != "INFO" && f.severity != "LOW")
                    .collect();

                if actionable.is_empty() {
                    eprintln!(
                        "  {GREEN}{ICON_CHECK} {BOLD}{}{RESET} no longer has threat signatures (patched clean) — resolving advisory",
                        adv.package
                    );
                    return None;
                }

                // Still vulnerable: update metadata and retain
                let highest = if actionable.iter().any(|f| f.severity == "CRITICAL") {
                    "CRITICAL"
                } else if actionable.iter().any(|f| f.severity == "HIGH") {
                    "HIGH"
                } else {
                    "MEDIUM"
                };

                if let Some(info) = pkg_info {
                    adv.version = info.version;
                    adv.maintainer = info.maintainer.unwrap_or_else(|| "orphan".into());
                }
                adv.highest_severity = highest.to_string();
                adv.findings = actionable;
                Some(adv)
            })
            .collect();

        for opt in results {
            if let Some(adv) = opt {
                active_advisories.push(adv);
            } else {
                resolved_count += 1;
            }
        }
    }

    // 2. Scan recent packages from the time window in parallel
    let scanned = to_scan.len() as u32;
    eprintln!(
        "{BLUE}{ICON_SEARCH} scanning {scanned} packages in parallel across worker pool...{RESET}"
    );

    let newly_flagged: Vec<Advisory> = to_scan
        .par_iter()
        .filter_map(|pkg| {
            let worker_client = AURClient::new();
            let pkgbuild = worker_client.fetch_pkgbuild(&pkg.name)?;

            let mut findings = scanner.scan(&pkgbuild, Some(&pkg.name));

            // Also scan .install if referenced
            if let Some(cap) = INSTALL_RE.captures(&pkgbuild) {
                if let Some(install_content) = worker_client.fetch_install_file(&pkg.name, &cap[1]) {
                    let install_findings = scanner.scan(&install_content, None);
                    for mut f in install_findings {
                        f.description = format!("[.install] {}", f.description);
                        findings.push(f);
                    }
                }
            }

            let actionable: Vec<_> = findings
                .into_iter()
                .filter(|f| f.severity != "INFO" && f.severity != "LOW")
                .collect();

            if actionable.is_empty() {
                return None;
            }

            let highest = if actionable.iter().any(|f| f.severity == "CRITICAL") {
                "CRITICAL"
            } else if actionable.iter().any(|f| f.severity == "HIGH") {
                "HIGH"
            } else {
                "MEDIUM"
            };
            let maintainer = pkg.maintainer.clone().unwrap_or_else(|| "orphan".into());
            let color = severity_color(highest);
            let icon = severity_icon(highest);
            eprintln!(
                "  {color}{icon} {BOLD}{}{RESET} {DIM}v{} by {}{RESET} {color}— {} hit(s), {highest}{RESET}",
                pkg.name,
                pkg.version,
                maintainer,
                actionable.len()
            );
            Some(Advisory {
                package: pkg.name.clone(),
                version: pkg.version.clone(),
                maintainer,
                highest_severity: highest.to_string(),
                detected_at: chrono::Utc::now().to_rfc3339(),
                findings: actionable,
                aur_url: format!("https://aur.archlinux.org/packages/{}", pkg.name),
            })
        })
        .collect();

    let new_flagged = newly_flagged.len() as u32;
    for adv in newly_flagged {
        if let Some(pos) = active_advisories
            .iter()
            .position(|a| a.package == adv.package)
        {
            active_advisories[pos] = adv;
        } else {
            active_advisories.push(adv);
        }
    }

    // 3. Save advisories sorted severity-wise and update markdown
    active_advisories.sort_by(|a, b| {
        report::severity_rank(&a.highest_severity)
            .cmp(&report::severity_rank(&b.highest_severity))
            .then_with(|| b.detected_at.cmp(&a.detected_at))
    });
    report::write_advisories(repo_root, &active_advisories);
    report::update_readme_table(repo_root, &active_advisories);

    eprintln!();
    eprintln!("{CYAN}╭──────────────────────────────────╮{RESET}");
    eprintln!(
        "{CYAN}│{RESET} {ICON_SHIELD}  {BOLD}autopilot complete{RESET}            {CYAN}│{RESET}"
    );
    eprintln!("{CYAN}├──────────────────────────────────┤{RESET}");
    eprintln!(
        "{CYAN}│{RESET}  {ICON_SEARCH}  scanned    {BOLD}{scanned:>6}{RESET}           {CYAN}│{RESET}"
    );
    if re_evaluated > 0 {
        eprintln!(
            "{CYAN}│{RESET}  {ICON_RADAR}  re-eval    {BOLD}{re_evaluated:>6}{RESET}           {CYAN}│{RESET}"
        );
    }
    if resolved_count > 0 {
        eprintln!(
            "{CYAN}│{RESET}  {GREEN}{ICON_CHECK}  resolved   {BOLD}{resolved_count:>6}{RESET}           {CYAN}│{RESET}"
        );
    }
    if new_flagged > 0 {
        eprintln!(
            "{CYAN}│{RESET}  {RED}{ICON_SKULL}  flagged    {BOLD}{new_flagged:>6}{RESET}           {CYAN}│{RESET}"
        );
    } else {
        eprintln!(
            "{CYAN}│{RESET}  {GREEN}{ICON_CHECK}  new flags  {BOLD}{new_flagged:>6}{RESET}           {CYAN}│{RESET}"
        );
    }
    eprintln!(
        "{CYAN}│{RESET}  {ICON_RADAR}  active     {BOLD}{:>6}{RESET}           {CYAN}│{RESET}",
        active_advisories.len()
    );
    eprintln!("{CYAN}╰──────────────────────────────────╯{RESET}");

    ExitCode::SUCCESS
}

// ── Pretty finding printer ──────────────────────────────────────────

fn print_findings(findings: &[aur_sentry::scanner::Finding]) {
    if findings.is_empty() {
        eprintln!();
        eprintln!("  {GREEN}{ICON_CHECK} {BOLD}clean{RESET}{GREEN} — no threats detected{RESET}");
        eprintln!();
        return;
    }

    eprintln!();
    eprintln!(
        "  {RED}{ICON_SKULL} {BOLD}{} threat(s) detected{RESET}",
        findings.len()
    );
    eprintln!();

    for f in findings {
        let color = severity_color(&f.severity);
        let icon = severity_icon(&f.severity);
        eprintln!(
            "  {color}{icon}  [{BOLD}{}{RESET}{color}] {}{RESET}",
            f.severity, f.rule_id
        );
        eprintln!("     {}", f.description);
        eprintln!(
            "     {DIM}line {}: {}{RESET}",
            f.line_number, f.matched_text
        );
        eprintln!();
    }
}

// ── radar ───────────────────────────────────────────────────────────

fn cmd_radar(limit: usize) -> ExitCode {
    let mut advisories = report::load_advisories(Path::new("."));
    if advisories.is_empty() {
        let client = AURClient::new();
        if let Some(remote) = client.fetch_remote_advisories() {
            advisories = remote;
        }
    }

    if advisories.is_empty() {
        eprintln!(
            "  {GREEN}{ICON_CHECK} {BOLD}radar clean{RESET}{GREEN} — no active threats recorded{RESET}"
        );
        return ExitCode::SUCCESS;
    }

    eprintln!(
        "{CYAN}{ICON_RADAR} {BOLD}Live Threat Radar ({}){RESET}",
        advisories.len()
    );
    eprintln!();
    for adv in advisories.iter().take(limit) {
        let color = severity_color(&adv.highest_severity);
        let icon = severity_icon(&adv.highest_severity);
        let triggers: Vec<_> = adv
            .findings
            .iter()
            .take(3)
            .map(|f| f.rule_id.as_str())
            .collect();
        eprintln!(
            "  {color}{icon} [{BOLD}{}{RESET}{color}] {BOLD}{}{RESET} {DIM}v{} by {}{RESET} {color}— {}{RESET}",
            adv.highest_severity,
            adv.package,
            adv.version,
            adv.maintainer,
            triggers.join(", ")
        );
        eprintln!("     {DIM}{}{RESET}", adv.aur_url);
    }
    eprintln!();
    ExitCode::SUCCESS
}

// ── attest ──────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn cmd_attest(
    pkgname: &str,
    version: &str,
    arch: &str,
    aur_commit: &str,
    pkgbuild: Option<&Path>,
    install_file: Option<&Path>,
    static_findings: Option<&Path>,
    telemetry: Option<&Path>,
    package_analysis: Option<&Path>,
    strace_available: bool,
    makepkg_exit: Option<i32>,
    reproducibility_status: &str,
    output: &Path,
) -> ExitCode {
    eprintln!(
        "{BLUE}{ICON_SEARCH} assembling attestation for {BOLD}{pkgname}{RESET}{BLUE} v{version}{RESET}"
    );

    let inputs = AttestInputs {
        package: pkgname.to_string(),
        version: version.to_string(),
        arch: arch.to_string(),
        aur_commit: aur_commit.to_string(),
        pkgbuild_path: pkgbuild,
        install_path: install_file,
        static_findings_path: static_findings,
        telemetry_path: telemetry,
        package_analysis_path: package_analysis,
        strace_available,
        makepkg_exit,
        scanner_version: format!("aur-sentry/{}", env!("CARGO_PKG_VERSION")),
        reproducibility: ReproducibilityStatus::from_cli_str(reproducibility_status),
    };
    let attestation = attest::build_attestation(&inputs);

    let json = match serde_json::to_string_pretty(&attestation) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("{RED}{ICON_CROSS} failed to serialize attestation: {e}{RESET}");
            return ExitCode::FAILURE;
        }
    };
    if let Some(parent) = output.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            eprintln!(
                "{RED}{ICON_CROSS} can't create {}: {e}{RESET}",
                parent.display()
            );
            return ExitCode::FAILURE;
        }
    }
    if let Err(e) = std::fs::write(output, format!("{json}\n")) {
        eprintln!(
            "{RED}{ICON_CROSS} can't write {}: {e}{RESET}",
            output.display()
        );
        return ExitCode::FAILURE;
    }

    let (color, icon) = match attestation.verdict {
        Verdict::Verified => (GREEN, ICON_CHECK),
        Verdict::Suspicious => (YELLOW, ICON_WARN),
        Verdict::Malicious => (RED, ICON_SKULL),
        _ => (DIM, ICON_SEARCH),
    };
    eprintln!(
        "  {color}{icon} verdict: {BOLD}{:?}{RESET}{color} — {} static finding(s){RESET}",
        attestation.verdict,
        attestation.static_findings.len()
    );
    eprintln!("  {DIM}wrote {}{RESET}", output.display());

    match attestation.verdict {
        Verdict::Verified => ExitCode::SUCCESS,
        _ => ExitCode::from(2),
    }
}

// ── check ───────────────────────────────────────────────────────────
//
// Native equivalent of bin/safeaur's fetch_attestation()/check_attestation_policy():
// look up the published attestation registry (data/attestations/<pkg>/<version>.json)
// over the GitHub Contents/raw APIs, no auth required. Missing/unreachable
// data is always treated as "no attestation found" — the registry is new
// and sparse, so it must never break a normal `check && makepkg` pipeline.

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

/// Mirrors cmd_attest's Verdict -> ExitCode mapping so `aur-sentry check
/// <pkg> && makepkg` is a usable manual pre-build gate, same spirit as
/// `safeaur check`.
fn verdict_exit_code(v: Verdict) -> ExitCode {
    match v {
        Verdict::Verified => ExitCode::SUCCESS,
        _ => ExitCode::from(2),
    }
}

fn cmd_check(pkgname: &str) -> ExitCode {
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
    use aur_sentry::attestation::{
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
        att.static_findings.push(aur_sentry::attestation::Finding {
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
            }],
            filesystem: vec![FilesystemEvent {
                path: "/home/user/.ssh/id_rsa".into(),
                operation: "canary_access".into(),
                timestamp: "2026-01-01T00:00:00Z".into(),
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
