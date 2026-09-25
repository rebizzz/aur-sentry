//! `radar`: print active advisories (local advisories.json, else remote).

use crate::aur_client::AURClient;
use crate::report;
use crate::ui::*;
use std::path::Path;
use std::process::ExitCode;

pub fn run(limit: usize) -> ExitCode {
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
