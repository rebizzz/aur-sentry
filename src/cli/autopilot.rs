//! `autopilot`: re-evaluate active advisories, scan the recent AUR window,
//! and rewrite advisories.json/xml + the README table.

use super::scan_with_install;
use crate::aur_client::AURClient;
use crate::findings::Finding;
use crate::report::{self, Advisory};
use crate::scanner::PKGBUILDScanner;
use crate::ui::*;
use rayon::prelude::*;
use std::path::Path;
use std::process::ExitCode;

fn actionable(findings: Vec<Finding>) -> Vec<Finding> {
    findings
        .into_iter()
        .filter(|f| f.severity != "INFO" && f.severity != "LOW")
        .collect()
}

fn highest_severity(findings: &[Finding]) -> &'static str {
    if findings.iter().any(|f| f.severity == "CRITICAL") {
        "CRITICAL"
    } else if findings.iter().any(|f| f.severity == "HIGH") {
        "HIGH"
    } else {
        "MEDIUM"
    }
}

pub fn run(repo_root: &Path, window_hours: u64, limit: usize) -> ExitCode {
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

                let (Some(info), Some(pkgbuild)) = (pkg_info, pkgbuild_opt) else {
                    eprintln!(
                        "  {YELLOW}{ICON_WARN} {BOLD}{}{RESET} removed from AUR (takedown) — resolving active advisory",
                        adv.package
                    );
                    return None;
                };

                let actionable = actionable(scan_with_install(
                    &worker_client,
                    &scanner,
                    &adv.package,
                    &pkgbuild,
                ));

                if actionable.is_empty() {
                    eprintln!(
                        "  {GREEN}{ICON_CHECK} {BOLD}{}{RESET} no longer has threat signatures (patched clean) — resolving advisory",
                        adv.package
                    );
                    return None;
                }

                adv.version = info.version;
                adv.maintainer = info.maintainer.unwrap_or_else(|| "orphan".into());
                adv.highest_severity = highest_severity(&actionable).to_string();
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

            let actionable = actionable(scan_with_install(
                &worker_client,
                &scanner,
                &pkg.name,
                &pkgbuild,
            ));

            if actionable.is_empty() {
                return None;
            }

            let highest = highest_severity(&actionable);
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
