#![allow(clippy::collapsible_if)]

//! CLI entry point for AUR-Sentry.
//! Nerdfont-powered, colored, human-readable output.

use aur_sentry::aur_client::AURClient;
use aur_sentry::report::{self, Advisory};
use aur_sentry::scanner::PKGBUILDScanner;
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

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
}

fn main() -> ExitCode {
    print_banner();
    let cli = Cli::parse();
    match cli.command {
        Commands::ScanFile { path } => cmd_scan_file(&path),
        Commands::ScanPkg { pkgname } => cmd_scan_pkg(&pkgname),
        Commands::Autopilot {
            repo_root,
            window_hours,
            limit,
        } => cmd_autopilot(&repo_root, window_hours, limit),
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
    let install_re = regex::Regex::new(r##"install=\s*['"]?([a-zA-Z0-9._-]+\.install)"##).unwrap();
    if let Some(cap) = install_re.captures(&pkgbuild) {
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
    let install_re = regex::Regex::new(r##"install=\s*['"]?([a-zA-Z0-9._-]+\.install)"##).unwrap();

    let recent = client.get_recently_modified(window_hours);
    let to_scan: Vec<_> = recent.into_iter().take(limit).collect();
    eprintln!(
        "{BLUE}{ICON_PKG} {BOLD}{}{RESET}{BLUE} packages modified in the last {window_hours}h{RESET}",
        to_scan.len()
    );

    let mut new_advisories: Vec<Advisory> = Vec::new();
    let mut scanned = 0u32;
    let mut flagged = 0u32;

    for pkg in &to_scan {
        scanned += 1;
        let pkgbuild = match client.fetch_pkgbuild(&pkg.name) {
            Some(c) => c,
            None => continue,
        };

        let mut findings = scanner.scan(&pkgbuild, Some(&pkg.name));

        // Also scan .install if referenced
        if let Some(cap) = install_re.captures(&pkgbuild) {
            if let Some(install_content) = client.fetch_install_file(&pkg.name, &cap[1]) {
                let install_findings = scanner.scan(&install_content, None);
                for mut f in install_findings {
                    f.description = format!("[.install] {}", f.description);
                    findings.push(f);
                }
            }
        }

        let actionable: Vec<_> = findings
            .into_iter()
            .filter(|f| f.severity != "INFO")
            .collect();

        if !actionable.is_empty() {
            flagged += 1;
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
            new_advisories.push(Advisory {
                package: pkg.name.clone(),
                version: pkg.version.clone(),
                maintainer,
                highest_severity: highest.to_string(),
                detected_at: chrono::Utc::now().to_rfc3339(),
                findings: actionable,
                aur_url: format!("https://aur.archlinux.org/packages/{}", pkg.name),
            });
        }
    }

    // Save and update
    report::save_advisories(repo_root, &new_advisories);
    let all = report::load_advisories(repo_root);
    report::update_readme_table(repo_root, &all);

    eprintln!();
    eprintln!("{CYAN}╭──────────────────────────────────╮{RESET}");
    eprintln!(
        "{CYAN}│{RESET} {ICON_SHIELD}  {BOLD}autopilot complete{RESET}            {CYAN}│{RESET}"
    );
    eprintln!("{CYAN}├──────────────────────────────────┤{RESET}");
    eprintln!(
        "{CYAN}│{RESET}  {ICON_SEARCH}  scanned    {BOLD}{scanned:>6}{RESET}           {CYAN}│{RESET}"
    );
    if flagged > 0 {
        eprintln!(
            "{CYAN}│{RESET}  {RED}{ICON_SKULL}  flagged    {BOLD}{flagged:>6}{RESET}           {CYAN}│{RESET}"
        );
    } else {
        eprintln!(
            "{CYAN}│{RESET}  {GREEN}{ICON_CHECK}  flagged    {BOLD}{flagged:>6}{RESET}           {CYAN}│{RESET}"
        );
    }
    eprintln!(
        "{CYAN}│{RESET}  {ICON_RADAR}  advisories {BOLD}{:>6}{RESET}           {CYAN}│{RESET}",
        all.len()
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
