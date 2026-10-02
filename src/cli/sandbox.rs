//! `aur-sentry sandbox` subcommand: Disposable container dynamic execution and strace auditing.

use crate::attestation::Verdict;
use crate::sandbox_runner::{
    EnginePreference, NetworkMode, SandboxAuditResult, SandboxOptions, run_sandbox_audit,
};
use crate::ui::*;
use clap::Args;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

#[derive(Args, Debug, Clone)]
pub struct SandboxArgs {
    /// AUR package name or local path to PKGBUILD/package directory
    pub target: String,

    /// Container engine to use
    #[arg(long, default_value = "auto", value_parser = ["auto", "podman", "docker"])]
    pub engine: String,

    /// Container execution timeout per phase (e.g. "15m", "600s")
    #[arg(long, default_value = "15m")]
    pub timeout: String,

    /// Keep container after execution for post-mortem debugging
    #[arg(long)]
    pub keep_container: bool,

    /// Network isolation mode: "host" (allow source downloads) or "none" (isolated)
    #[arg(long, default_value = "host", value_parser = ["host", "none"])]
    pub network: String,

    /// Disable strace dynamic telemetry tracing
    #[arg(long)]
    pub no_strace: bool,

    /// Memory limit for container (e.g. "4g", "2g")
    #[arg(long, default_value = "4g")]
    pub memory: String,

    /// Output results as structured JSON on stdout
    #[arg(long)]
    pub json: bool,

    /// Custom output directory (strictly inside generated/)
    #[arg(long)]
    pub output_dir: Option<PathBuf>,
}

pub fn run(args: &SandboxArgs) -> ExitCode {
    let engine_pref = match args.engine.as_str() {
        "podman" => EnginePreference::Podman,
        "docker" => EnginePreference::Docker,
        _ => EnginePreference::Auto,
    };

    let net_mode = match args.network.as_str() {
        "none" => NetworkMode::None,
        _ => NetworkMode::Host,
    };

    let timeout = parse_duration_string(&args.timeout).unwrap_or(Duration::from_secs(15 * 60));

    let options = SandboxOptions {
        engine: engine_pref,
        timeout,
        memory_limit: args.memory.clone(),
        cpu_limit: "2".to_string(),
        network_mode: net_mode,
        enable_strace: !args.no_strace,
        keep_container: args.keep_container,
        custom_output_dir: args.output_dir.clone(),
    };

    match run_sandbox_audit(&args.target, &options) {
        Ok(result) => {
            if args.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&result)
                        .expect("SandboxAuditResult serializes to JSON")
                );
            } else {
                render_sandbox_terminal(&result);
            }

            match result.attestation.verdict {
                Verdict::Verified => ExitCode::SUCCESS,
                Verdict::Suspicious | Verdict::Malicious => ExitCode::from(2),
                _ => ExitCode::from(1),
            }
        }
        Err(e) => {
            eprintln!("{RED}{ICON_CROSS} Sandbox Audit Failed: {e}{RESET}");
            ExitCode::from(1)
        }
    }
}

fn parse_duration_string(s: &str) -> Option<Duration> {
    let s = s.trim();
    if let Some(stripped) = s.strip_suffix('m') {
        let mins: u64 = stripped.parse().ok()?;
        Some(Duration::from_secs(mins * 60))
    } else if let Some(stripped) = s.strip_suffix('s') {
        let secs: u64 = stripped.parse().ok()?;
        Some(Duration::from_secs(secs))
    } else if let Some(stripped) = s.strip_suffix('h') {
        let hours: u64 = stripped.parse().ok()?;
        Some(Duration::from_secs(hours * 3600))
    } else {
        let secs: u64 = s.parse().ok()?;
        Some(Duration::from_secs(secs))
    }
}

fn render_sandbox_terminal(res: &SandboxAuditResult) {
    let border_color = match res.attestation.verdict {
        Verdict::Verified => GREEN,
        Verdict::Suspicious => YELLOW,
        Verdict::Malicious => RED,
        _ => CYAN,
    };

    let verdict_str = format!("{:?}", res.attestation.verdict);
    let makepkg_str = match res.makepkg_exit {
        Some(0) => format!("{GREEN}Exit 0 (SUCCESS){RESET}"),
        Some(code) => format!("{RED}Exit {code} (FAILED){RESET}"),
        None => format!("{YELLOW}Not executed / Killed{RESET}"),
    };

    let engine_desc = format!(
        "{} (rootless: {})",
        res.engine.binary_path.display(),
        res.engine.is_rootless
    );

    let rows = [
        BoxRow::new("Package:", format!("{} v{}", res.package, res.version)),
        BoxRow::new("Container Engine:", engine_desc),
        BoxRow::new("Build Status:", makepkg_str),
        BoxRow::new(
            "Strace Telemetry:",
            if res.strace_available {
                format!("{GREEN}Active (network & filesystem tracked){RESET}")
            } else {
                format!("{YELLOW}Unavailable (ptrace restricted){RESET}")
            },
        ),
        BoxRow::new(
            "Network Events:",
            format!("{} connection(s) observed", res.network_events.len()),
        ),
        BoxRow::new(
            "Filesystem Events:",
            format!("{} file event(s) observed", res.filesystem_events.len()),
        ),
        BoxRow::new(
            "Evidence Path:",
            res.evidence_directory.display().to_string(),
        ),
        BoxRow::new(
            "Final Verdict:",
            format!("{BOLD}{border_color}[ {verdict_str} ]{RESET}"),
        ),
    ];

    let box_str = render_box("DYNAMIC CONTAINER SANDBOX AUDIT", &rows, border_color, 66);
    eprint!("{box_str}");
    eprintln!();
}
