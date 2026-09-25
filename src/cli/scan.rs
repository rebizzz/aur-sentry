//! `scan-file` / `scan-pkg`: human output on stderr, `--json` on stdout.

use super::{install_file_name, tag_install};
use crate::aur_client::AURClient;
use crate::findings::{FileFindings, Finding};
use crate::scanner::PKGBUILDScanner;
use crate::ui::*;
use serde::Serialize;
use std::path::Path;
use std::process::ExitCode;

pub fn scan_file(path: &Path, json: bool) -> ExitCode {
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
    let found = !findings.is_empty();
    if json {
        print_json(&FileFindings {
            file: file_label(path),
            findings,
        });
    }
    exit_code(found)
}

pub fn scan_pkg(pkgname: &str, json: bool) -> ExitCode {
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

    let mut files = vec![FileFindings {
        file: "PKGBUILD".into(),
        findings: scanner.scan(&pkgbuild, Some(pkgname)),
    }];
    if let Some(install_name) = install_file_name(&pkgbuild) {
        eprintln!("{BLUE}{ICON_SEARCH} found .install ref: {install_name}, scanning...{RESET}");
        if let Some(install_content) = client.fetch_install_file(pkgname, install_name) {
            files.push(FileFindings {
                file: install_name.to_string(),
                findings: scanner.scan(&install_content, None),
            });
        }
    }

    let mut combined = files[0].findings.clone();
    for install in &files[1..] {
        combined.extend(tag_install(install.findings.clone()));
    }
    print_findings(&combined);
    if json {
        print_json(&files);
    }
    exit_code(!combined.is_empty())
}

fn exit_code(found: bool) -> ExitCode {
    if found {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    }
}

fn file_label(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

fn print_json(value: &impl Serialize) {
    println!(
        "{}",
        serde_json::to_string(value).expect("findings serialize to JSON")
    );
}

fn print_findings(findings: &[Finding]) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_label_is_basename() {
        assert_eq!(file_label(Path::new("/tmp/src/foo/PKGBUILD")), "PKGBUILD");
        assert_eq!(file_label(Path::new("bar.install")), "bar.install");
    }

    #[test]
    fn scan_file_json_matches_pipeline_contract() {
        let findings = PKGBUILDScanner::new().scan("cat ~/.ssh/id_rsa\n", None);
        let json = serde_json::to_value(FileFindings {
            file: file_label(Path::new("/work/PKGBUILD")),
            findings,
        })
        .unwrap();
        assert_eq!(json["file"], "PKGBUILD");
        let first = &json["findings"][0];
        let mut keys: Vec<_> = first.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "behavior",
                "description",
                "line_number",
                "matched_text",
                "rule_id",
                "severity"
            ]
        );
        assert_eq!(first["rule_id"], "CRED_SSH_KEYS");
        assert_eq!(first["behavior"], "CREDENTIAL_ACCESS");
        assert!(!json.to_string().contains('\x1b'));
    }
}
