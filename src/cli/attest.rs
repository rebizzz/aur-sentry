//! `attest`: assemble and write an Attestation JSON from sandbox evidence.

use super::check::verdict_exit_code;
use crate::attest::{self, AttestInputs};
use crate::attestation::{ReproducibilityStatus, Verdict};
use crate::ui::*;
use clap::Args;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Args)]
pub struct AttestArgs {
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

    /// Path to a JSON array of `scan-file --json` outputs, one per scanned
    /// file (e.g. `jq -s . pkgbuild.json foo.install.json`)
    #[arg(long)]
    static_findings: Option<PathBuf>,

    /// Path to the build-phase strace telemetry log from the dynamic
    /// sandbox (`makepkg` under strace)
    #[arg(long)]
    telemetry: Option<PathBuf>,

    /// Path to the install-phase strace telemetry log from the dynamic
    /// sandbox (`pacman -U`/`-R` under strace — see
    /// scripts/dynamic_sandbox.sh's install-phase step). Missing/absent
    /// degrades to "no install-phase evidence" rather than failing the
    /// attestation; the sandbox script itself skips this pass entirely
    /// when no built package file exists.
    #[arg(long)]
    install_telemetry: Option<PathBuf>,

    /// Path to the package-content/ELF-analysis JSON blob assembled by
    /// scripts/dynamic_sandbox.sh from the real makepkg-built package
    /// (file/ELF counts, setuid/world-writable findings). Missing/absent
    /// degrades to an "unavailable" package_analysis rather than failing.
    #[arg(long)]
    package_analysis: Option<PathBuf>,

    /// Path to the `external_intel.json` array assembled by
    /// scripts/dynamic_sandbox.sh from OSV.dev vulnerability-query
    /// results (declared dependency names + the upstream project's
    /// identity, where those map to an ecosystem OSV tracks). Missing/
    /// absent degrades to no external evidence rather than failing.
    /// Informational only — never affects verdict.
    #[arg(long)]
    external_intel: Option<PathBuf>,

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
}

pub fn run(args: &AttestArgs) -> ExitCode {
    let AttestArgs {
        pkgname,
        version,
        output,
        ..
    } = args;
    eprintln!(
        "{BLUE}{ICON_SEARCH} assembling attestation for {BOLD}{pkgname}{RESET}{BLUE} v{version}{RESET}"
    );

    let inputs = AttestInputs {
        package: pkgname.clone(),
        version: version.clone(),
        arch: args.arch.clone(),
        aur_commit: args.aur_commit.clone(),
        pkgbuild_path: args.pkgbuild.as_deref(),
        install_path: args.install_file.as_deref(),
        static_findings_path: args.static_findings.as_deref(),
        telemetry_path: args.telemetry.as_deref(),
        install_telemetry_path: args.install_telemetry.as_deref(),
        package_analysis_path: args.package_analysis.as_deref(),
        external_intelligence_path: args.external_intel.as_deref(),
        strace_available: args.strace_available,
        makepkg_exit: args.makepkg_exit,
        scanner_version: format!("aur-sentry/{}", env!("CARGO_PKG_VERSION")),
        reproducibility: ReproducibilityStatus::from_cli_str(&args.reproducibility_status),
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

    verdict_exit_code(attestation.verdict)
}
