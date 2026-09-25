//! `aur-sentry` command-line interface: clap definitions and dispatch.

mod attest;
mod autopilot;
mod check;
mod radar;
mod scan;

use crate::aur_client::AURClient;
use crate::findings::Finding;
use crate::scanner::PKGBUILDScanner;
use crate::ui::print_banner;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::LazyLock;

static INSTALL_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r##"install=\s*['"]?([a-zA-Z0-9._-]+\.install)"##).unwrap());

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
#[allow(clippy::large_enum_variant)] // Attest carries many CLI flags; parsed once, never hot-path
enum Commands {
    /// Scan a local PKGBUILD or .install file
    ScanFile {
        /// Path to PKGBUILD or .install file
        path: PathBuf,

        /// Print findings as JSON on stdout
        #[arg(long)]
        json: bool,
    },
    /// Scan a remote AUR package by name
    ScanPkg {
        /// AUR package name
        pkgname: String,

        /// Print findings as a JSON array (one object per scanned file) on stdout
        #[arg(long)]
        json: bool,
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
    Attest(attest::AttestArgs),
}

pub fn run() -> ExitCode {
    print_banner();
    let cli = Cli::parse();
    match cli.command {
        Commands::ScanFile { path, json } => scan::scan_file(&path, json),
        Commands::ScanPkg { pkgname, json } => scan::scan_pkg(&pkgname, json),
        Commands::Check { pkgname } => check::run(&pkgname),
        Commands::Autopilot {
            repo_root,
            window_hours,
            limit,
        } => autopilot::run(&repo_root, window_hours, limit),
        Commands::Radar { limit } => radar::run(limit),
        Commands::Attest(args) => attest::run(&args),
    }
}

fn install_file_name(pkgbuild: &str) -> Option<&str> {
    INSTALL_RE
        .captures(pkgbuild)
        .and_then(|cap| cap.get(1))
        .map(|m| m.as_str())
}

/// Scan a PKGBUILD plus the `.install` scriptlet it references, prefixing
/// the scriptlet's finding descriptions with `[.install]`.
fn scan_with_install(
    client: &AURClient,
    scanner: &PKGBUILDScanner,
    pkgname: &str,
    pkgbuild: &str,
) -> Vec<Finding> {
    let mut findings = scanner.scan(pkgbuild, Some(pkgname));
    if let Some(install_name) = install_file_name(pkgbuild) {
        if let Some(install_content) = client.fetch_install_file(pkgname, install_name) {
            findings.extend(tag_install(scanner.scan(&install_content, None)));
        }
    }
    findings
}

fn tag_install(findings: Vec<Finding>) -> impl Iterator<Item = Finding> {
    findings.into_iter().map(|mut f| {
        f.description = format!("[.install] {}", f.description);
        f
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_file_name_extracts_scriptlet_reference() {
        assert_eq!(
            install_file_name("pkgname=foo\ninstall=foo.install\n"),
            Some("foo.install")
        );
        assert_eq!(
            install_file_name("install='bar-baz.install'"),
            Some("bar-baz.install")
        );
        assert_eq!(install_file_name("pkgname=foo\n"), None);
    }

    #[test]
    fn attest_flags_parse_unchanged() {
        let cli = Cli::try_parse_from([
            "aur-sentry",
            "attest",
            "foo",
            "--version",
            "1.0-1",
            "--arch",
            "x86_64",
            "--aur-commit",
            "abc",
            "--pkgbuild",
            "PKGBUILD",
            "--install-file",
            "foo.install",
            "--static-findings",
            "static.json",
            "--telemetry",
            "t.log",
            "--install-telemetry",
            "it.log",
            "--package-analysis",
            "pa.json",
            "--external-intel",
            "ei.json",
            "--strace-available",
            "--makepkg-exit",
            "0",
            "--reproducibility-status",
            "REPRODUCED",
            "--output",
            "out.json",
        ]);
        assert!(cli.is_ok(), "{:?}", cli.err());
    }

    #[test]
    fn scan_commands_accept_json_flag() {
        assert!(Cli::try_parse_from(["aur-sentry", "scan-file", "PKGBUILD", "--json"]).is_ok());
        assert!(Cli::try_parse_from(["aur-sentry", "scan-pkg", "foo", "--json"]).is_ok());
    }
}
