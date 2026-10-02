//! `aur-sentry deps` subcommand: Dependency tree analysis and BOM generation.

use crate::aur_client::AURClient;
use crate::deps::{
    DependencyBom, RawDependency, ThreatLevel, compile_dependency_bom,
    extract_pkgbuild_dependencies,
};
use crate::multisource::MultiSourceClient;
use crate::ui::*;
use clap::Args;
use std::path::Path;
use std::process::ExitCode;

#[derive(Args, Debug, Clone)]
pub struct DepsArgs {
    /// Package name or path to PKGBUILD/.SRCINFO file
    pub target: String,

    /// Print Dependency BOM as JSON on stdout
    #[arg(long)]
    pub json: bool,

    /// Use local embedded catalog only without live network queries
    #[arg(long)]
    pub offline: bool,

    /// Maximum dependency resolution depth
    #[arg(long, default_value_t = 3)]
    pub depth: usize,
}

pub fn run(args: &DepsArgs) -> ExitCode {
    let target = &args.target;
    let target_path = Path::new(target);

    let (pkgname, pkgver, content) = if target_path.exists() {
        let text = match std::fs::read_to_string(target_path) {
            Ok(t) => t,
            Err(e) => {
                eprintln!(
                    "{RED}{ICON_CROSS} can't read {}: {e}{RESET}",
                    target_path.display()
                );
                return ExitCode::FAILURE;
            }
        };
        let (name, ver) = extract_identity(&text, target);
        (name, ver, text)
    } else {
        if args.offline {
            // In offline mode with non-existent file, construct synthetic stub
            let (name, ver) = (target.clone(), "1.0.0-1".to_string());
            (name, ver, String::new())
        } else {
            eprintln!(
                "{BLUE}{ICON_DOWNLOAD} fetching PKGBUILD for {BOLD}{target}{RESET}{BLUE} from AUR...{RESET}"
            );
            let client = AURClient::new();
            match client.fetch_pkgbuild(target) {
                Some(text) => {
                    let (name, ver) = extract_identity(&text, target);
                    (name, ver, text)
                }
                None => {
                    eprintln!(
                        "{RED}{ICON_CROSS} couldn't find or download PKGBUILD for '{target}'{RESET}"
                    );
                    return ExitCode::FAILURE;
                }
            }
        }
    };

    let raw_deps: Vec<RawDependency> = if content.is_empty() {
        Vec::new()
    } else {
        extract_pkgbuild_dependencies(&content)
    };

    let client = MultiSourceClient::new(args.offline);
    let bom: DependencyBom =
        compile_dependency_bom(&pkgname, &pkgver, &raw_deps, &client, args.depth);

    if args.json {
        let json_out =
            serde_json::to_string_pretty(&bom).expect("DependencyBom serializes to JSON");
        println!("{json_out}");
    } else {
        render_deps_terminal(&bom);
    }

    let has_critical = bom
        .warnings
        .iter()
        .any(|w| w.level == ThreatLevel::Critical);

    if has_critical {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    }
}

fn extract_identity(content: &str, fallback: &str) -> (String, String) {
    let mut pkgname = None;
    let mut pkgver = None;
    let mut pkgrel = None;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = trimmed.split_once('=') {
            let key = k.trim();
            let val = v.trim().trim_matches(|c| c == '\'' || c == '"').trim();
            match key {
                "pkgbase" | "pkgname" if pkgname.is_none() => pkgname = Some(val.to_string()),
                "pkgver" if pkgver.is_none() => pkgver = Some(val.to_string()),
                "pkgrel" if pkgrel.is_none() => pkgrel = Some(val.to_string()),
                _ => {}
            }
        }
    }

    let name = pkgname.unwrap_or_else(|| fallback.to_string());
    let ver = format!(
        "{}-{}",
        pkgver.unwrap_or_else(|| "1.0.0".to_string()),
        pkgrel.unwrap_or_else(|| "1".to_string())
    );
    (name, ver)
}

fn render_deps_terminal(bom: &DependencyBom) {
    let sum = &bom.summary;
    let score = if sum.warning_count > 0 {
        let crit = bom
            .warnings
            .iter()
            .filter(|w| w.level == ThreatLevel::Critical)
            .count();
        if crit > 0 {
            10.0
        } else {
            (sum.warning_count as f64 * 2.5).min(8.0)
        }
    } else {
        0.0
    };

    let gauge = threat_gauge(score, 10.0, 10, true);
    let border_color = if score >= 7.0 {
        RED
    } else if score >= 4.0 {
        YELLOW
    } else {
        CYAN
    };

    let rows = [
        BoxRow::new(
            "Target:",
            format!("{} v{}", bom.root_package, bom.root_version),
        ),
        BoxRow::new(
            "Total Deps:",
            format!("{} packages resolved", sum.total_dependencies),
        ),
        BoxRow::new(
            "Breakdown:",
            format!(
                "{} Official [core/extra] • {} AUR [community] • {} Virtual • {} Unresolved",
                sum.official_count, sum.aur_count, sum.virtual_count, sum.unresolved_count
            ),
        ),
        BoxRow::new("Threat Gauge:", gauge),
        BoxRow::new(
            "Threats:",
            if sum.warning_count == 0 {
                format!("{GREEN}0 warnings (clean provenance){RESET}")
            } else {
                format!("{RED}{} warning(s) detected{RESET}", sum.warning_count)
            },
        ),
    ];

    let box_str = render_box(
        "DEPENDENCY AUDIT & BILL OF MATERIALS",
        &rows,
        border_color,
        66,
    );
    eprint!("{box_str}");
    eprintln!();

    // Render tree view to stderr
    eprintln!("{}", bom.format_terminal_tree());

    // Print warnings if any
    if !bom.warnings.is_empty() {
        eprintln!("{RED}{BOLD}Threat Warnings / Suspicious Dependencies:{RESET}");
        for w in &bom.warnings {
            let (icon, color) = match w.level {
                ThreatLevel::Critical => (ICON_SKULL, RED),
                ThreatLevel::Warning => (ICON_WARN, YELLOW),
                ThreatLevel::Info => (ICON_SEARCH, BLUE),
                ThreatLevel::Clean => (ICON_CHECK, GREEN),
            };
            eprintln!(
                "  {color}{icon} [{BOLD}{}{RESET}{color}] {}: {}{RESET}",
                w.rule_id, w.package_name, w.message
            );
        }
        eprintln!();
    }
}
