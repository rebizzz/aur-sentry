//! Report generation — advisories.json and RSS feed output.

use crate::findings::Finding;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Advisory {
    pub package: String,
    pub version: String,
    pub maintainer: String,
    pub highest_severity: String,
    pub detected_at: String,
    pub findings: Vec<Finding>,
    pub aur_url: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AdvisoryFeed {
    pub version: String,
    pub updated_at: String,
    pub total_flagged: usize,
    pub advisories: Vec<Advisory>,
}

/// Load existing advisories from disk if present.
pub fn load_advisories(repo_root: &Path) -> Vec<Advisory> {
    let path = repo_root.join("advisories.json");
    if !path.exists() {
        return Vec::new();
    }
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    match serde_json::from_str::<AdvisoryFeed>(&content) {
        Ok(feed) => feed.advisories,
        Err(_) => Vec::new(),
    }
}

/// Rank severities for sorting (CRITICAL=0, HIGH=1, MEDIUM=2, LOW=3, other=4).
pub fn severity_rank(s: &str) -> u8 {
    match s {
        "CRITICAL" => 0,
        "HIGH" => 1,
        "MEDIUM" => 2,
        "LOW" => 3,
        _ => 4,
    }
}

/// Write advisories list directly to disk, sorted by severity and recency.
pub fn write_advisories(repo_root: &Path, advisories: &[Advisory]) {
    let mut sorted = advisories.to_vec();
    sorted.sort_by(|a, b| {
        severity_rank(&a.highest_severity)
            .cmp(&severity_rank(&b.highest_severity))
            .then_with(|| b.detected_at.cmp(&a.detected_at))
    });

    let feed = AdvisoryFeed {
        version: "1.0".into(),
        updated_at: Utc::now().to_rfc3339(),
        total_flagged: sorted.len(),
        advisories: sorted.clone(),
    };

    let json = serde_json::to_string_pretty(&feed).unwrap_or_default();
    let _ = std::fs::write(repo_root.join("advisories.json"), json);

    // Generate RSS
    generate_rss(repo_root, &sorted);
}

/// Remove an advisory by package name (e.g. when taken down or patched) and persist changes.
pub fn remove_advisory(repo_root: &Path, pkgname: &str) -> bool {
    let mut existing = load_advisories(repo_root);
    let original_len = existing.len();
    existing.retain(|a| a.package != pkgname);
    if existing.len() != original_len {
        write_advisories(repo_root, &existing);
        update_advisories_markdown(repo_root, &existing);
        let readme_path = repo_root.join("README.md");
        if readme_path.exists() {
            update_markdown_table_in_file(&readme_path, &existing);
        }
        true
    } else {
        false
    }
}

/// Merge new advisories into existing and save.
pub fn save_advisories(repo_root: &Path, new: &[Advisory]) {
    let mut existing = load_advisories(repo_root);

    // Upsert by package name
    for adv in new {
        if let Some(pos) = existing.iter().position(|a| a.package == adv.package) {
            existing[pos] = adv.clone();
        } else {
            existing.push(adv.clone());
        }
    }

    write_advisories(repo_root, &existing);
}

fn generate_rss(repo_root: &Path, advisories: &[Advisory]) {
    let now = Utc::now().to_rfc2822();
    let items: String = advisories
        .iter()
        .take(30)
        .map(|a| {
            let triggers: Vec<_> = a.findings.iter().map(|f| f.rule_id.as_str()).collect();
            format!(
                r#"    <item>
      <title>[{sev}] {pkg} ({ver})</title>
      <link>{url}</link>
      <description>Maintainer: {maint} — Triggers: {triggers}</description>
      <pubDate>{date}</pubDate>
      <guid>{url}#{ver}</guid>
    </item>"#,
                sev = a.highest_severity,
                pkg = a.package,
                ver = a.version,
                url = a.aur_url,
                maint = a.maintainer,
                triggers = triggers.join(", "),
                date = a.detected_at,
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let rss = format!(
        r#"<?xml version="1.0" encoding="UTF-8" ?>
<rss version="2.0">
  <channel>
    <title>AUR-Sentry Security Advisories</title>
    <link>https://github.com/rebizzz/aur-sentry</link>
    <description>Automated supply-chain security alerts for Arch User Repository packages</description>
    <lastBuildDate>{now}</lastBuildDate>
{items}
  </channel>
</rss>"#
    );

    let _ = std::fs::write(repo_root.join("advisories.xml"), rss);
}

/// Helper to update an existing markdown file containing AUTOPILOT markers.
pub fn update_markdown_table_in_file(file_path: &Path, advisories: &[Advisory]) -> bool {
    let content = match std::fs::read_to_string(file_path) {
        Ok(c) => c,
        Err(_) => return false,
    };

    let start = "<!-- AUTOPILOT_TABLE_START -->";
    let end = "<!-- AUTOPILOT_TABLE_END -->";
    if !content.contains(start) || !content.contains(end) {
        return false;
    }

    let mut sorted = advisories.to_vec();
    sorted.sort_by(|a, b| {
        severity_rank(&a.highest_severity)
            .cmp(&severity_rank(&b.highest_severity))
            .then_with(|| b.detected_at.cmp(&a.detected_at))
    });

    let table = if sorted.is_empty() {
        "\n<details>\n<summary>Active Threats (0)</summary>\n\n*No active threats recorded in the radar.*\n</details>\n".to_string()
    } else {
        let mut lines = vec![
            format!(
                "\n<details open>\n<summary>Active Threats ({})</summary>\n",
                sorted.len()
            ),
            "| Severity | Package | Version | Maintainer | Triggers | Link |".to_string(),
            "| :--- | :--- | :--- | :--- | :--- | :--- |".to_string(),
        ];
        for adv in sorted.iter().take(50) {
            let badge = match adv.highest_severity.as_str() {
                "CRITICAL" => "`[CRITICAL]`",
                "HIGH" => "`[HIGH]`",
                "MEDIUM" => "`[MEDIUM]`",
                _ => &adv.highest_severity,
            };
            let triggers: Vec<_> = adv
                .findings
                .iter()
                .take(3)
                .map(|f| format!("`{}`", f.rule_id))
                .collect();
            lines.push(format!(
                "| {badge} | `{}` | {} | {} | {} | [AUR]({}) |",
                adv.package,
                adv.version,
                adv.maintainer,
                triggers.join(", "),
                adv.aur_url
            ));
        }
        lines.push("</details>\n".to_string());
        format!("{}\n", lines.join("\n"))
    };

    let start_idx = content.find(start).unwrap() + start.len();
    let end_idx = content.find(end).unwrap();
    let new_content = format!("{}{}{}", &content[..start_idx], table, &content[end_idx..]);
    std::fs::write(file_path, new_content).is_ok()
}

/// Update the ADVISORIES.md threat radar table.
pub fn update_advisories_markdown(repo_root: &Path, advisories: &[Advisory]) {
    let doc_path = repo_root.join("ADVISORIES.md");
    if !doc_path.exists() {
        let initial = "# AUR Security Advisories & Threat Radar\n\nLive threat radar generated automatically on schedule every 2 hours by `aur-sentry` autopilot.\n\n<!-- AUTOPILOT_TABLE_START -->\n<!-- AUTOPILOT_TABLE_END -->\n\n- Full JSON Feed: [`advisories.json`](advisories.json)\n- RSS Feed: [`advisories.xml`](advisories.xml)\n";
        let _ = std::fs::write(&doc_path, initial);
    }
    update_markdown_table_in_file(&doc_path, advisories);
}

/// Update threat radar tables in ADVISORIES.md and (if markers exist) README.md.
pub fn update_readme_table(repo_root: &Path, advisories: &[Advisory]) {
    update_advisories_markdown(repo_root, advisories);
    let readme_path = repo_root.join("README.md");
    if readme_path.exists() {
        update_markdown_table_in_file(&readme_path, advisories);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::Behavior;

    #[test]
    fn advisory_feed_save_and_load_roundtrip() {
        let temp_dir = std::env::temp_dir().join(format!("aur_sentry_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);

        let adv1 = Advisory {
            package: "foo-malware".into(),
            version: "1.0-1".into(),
            maintainer: "badactor".into(),
            highest_severity: "CRITICAL".into(),
            detected_at: "2026-03-24T12:00:00Z".into(),
            findings: vec![Finding {
                rule_id: "REVSHELL_DEV_TCP".into(),
                severity: "CRITICAL".into(),
                description: "Reverse shell".into(),
                line_number: 10,
                matched_text: "bash -i >& /dev/tcp".into(),
                behavior: Behavior::NetworkAccess,
            }],
            aur_url: "https://aur.archlinux.org/packages/foo-malware".into(),
        };

        let adv2 = Advisory {
            package: "bar-suspicious".into(),
            version: "0.2-1".into(),
            maintainer: "orphan".into(),
            highest_severity: "HIGH".into(),
            detected_at: "2026-03-24T11:00:00Z".into(),
            findings: vec![Finding {
                rule_id: "SUS_VARIABLE_SPLICING".into(),
                severity: "HIGH".into(),
                description: "Variable splicing".into(),
                line_number: 2,
                matched_text: "a=b".into(),
                behavior: Behavior::Obfuscation,
            }],
            aur_url: "https://aur.archlinux.org/packages/bar-suspicious".into(),
        };

        save_advisories(&temp_dir, &[adv2.clone(), adv1.clone()]);

        let loaded = load_advisories(&temp_dir);
        assert_eq!(loaded.len(), 2);
        // CRITICAL must be sorted before HIGH
        assert_eq!(loaded[0].package, "foo-malware");
        assert_eq!(loaded[0].highest_severity, "CRITICAL");
        assert_eq!(loaded[1].package, "bar-suspicious");
        assert_eq!(loaded[1].highest_severity, "HIGH");

        // Verify RSS exists and contains both packages
        let rss_path = temp_dir.join("advisories.xml");
        assert!(rss_path.exists());
        let rss_content = std::fs::read_to_string(&rss_path).unwrap();
        assert!(rss_content.contains("foo-malware"));
        assert!(rss_content.contains("bar-suspicious"));
        assert!(rss_content.contains("<channel>"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn update_readme_table_preserves_surrounding_markdown() {
        let temp_dir =
            std::env::temp_dir().join(format!("aur_sentry_readme_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);

        let initial_readme = r#"# AUR Sentry
Header text.

<!-- AUTOPILOT_TABLE_START -->
<!-- AUTOPILOT_TABLE_END -->

Footer notes.
"#;
        std::fs::write(temp_dir.join("README.md"), initial_readme).unwrap();

        let adv = Advisory {
            package: "bad-pkg".into(),
            version: "1.0".into(),
            maintainer: "hacker".into(),
            highest_severity: "CRITICAL".into(),
            detected_at: "2026-03-24T12:00:00Z".into(),
            findings: vec![Finding {
                rule_id: "EXFIL_DISCORD_WEBHOOK".into(),
                severity: "CRITICAL".into(),
                description: "Discord webhook".into(),
                line_number: 5,
                matched_text: "discord.com".into(),
                behavior: Behavior::NetworkAccess,
            }],
            aur_url: "https://aur.archlinux.org/packages/bad-pkg".into(),
        };

        update_readme_table(&temp_dir, &[adv]);

        let updated = std::fs::read_to_string(temp_dir.join("README.md")).unwrap();
        assert!(updated.contains("Header text."));
        assert!(updated.contains("Footer notes."));
        assert!(updated.contains("<details open>"));
        assert!(updated.contains("<summary>Active Threats (1)</summary>"));
        assert!(updated.contains("`[CRITICAL]`"));
        assert!(updated.contains("`bad-pkg`"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn remove_advisory_cleans_feeds_and_markdown() {
        let temp_dir =
            std::env::temp_dir().join(format!("aur_sentry_remove_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);

        let adv1 = Advisory {
            package: "pkg-to-remove".into(),
            version: "1.0".into(),
            maintainer: "hacker".into(),
            highest_severity: "CRITICAL".into(),
            detected_at: "2026-03-24T12:00:00Z".into(),
            findings: vec![],
            aur_url: "https://aur.archlinux.org/packages/pkg-to-remove".into(),
        };
        let adv2 = Advisory {
            package: "pkg-to-keep".into(),
            version: "2.0".into(),
            maintainer: "user".into(),
            highest_severity: "HIGH".into(),
            detected_at: "2026-03-24T13:00:00Z".into(),
            findings: vec![],
            aur_url: "https://aur.archlinux.org/packages/pkg-to-keep".into(),
        };

        save_advisories(&temp_dir, &[adv1, adv2]);
        assert_eq!(load_advisories(&temp_dir).len(), 2);

        // Remove the taken-down / patched advisory
        let removed = remove_advisory(&temp_dir, "pkg-to-remove");
        assert!(removed);

        let remaining = load_advisories(&temp_dir);
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].package, "pkg-to-keep");

        let adv_md = std::fs::read_to_string(temp_dir.join("ADVISORIES.md")).unwrap();
        assert!(!adv_md.contains("pkg-to-remove"));
        assert!(adv_md.contains("pkg-to-keep"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn markdown_table_sorts_by_severity() {
        let temp_dir =
            std::env::temp_dir().join(format!("aur_sentry_sort_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);

        let adv_high = Advisory {
            package: "high-pkg".into(),
            version: "1.0".into(),
            maintainer: "user".into(),
            highest_severity: "HIGH".into(),
            detected_at: "2026-03-24T12:00:00Z".into(),
            findings: vec![],
            aur_url: "https://aur.archlinux.org/packages/high-pkg".into(),
        };
        let adv_crit = Advisory {
            package: "crit-pkg".into(),
            version: "1.0".into(),
            maintainer: "hacker".into(),
            highest_severity: "CRITICAL".into(),
            detected_at: "2026-03-24T11:00:00Z".into(),
            findings: vec![],
            aur_url: "https://aur.archlinux.org/packages/crit-pkg".into(),
        };

        // Pass HIGH before CRITICAL to update_readme_table
        update_readme_table(&temp_dir, &[adv_high, adv_crit]);

        let adv_md = std::fs::read_to_string(temp_dir.join("ADVISORIES.md")).unwrap();
        let crit_pos = adv_md.find("`crit-pkg`").expect("crit-pkg present");
        let high_pos = adv_md.find("`high-pkg`").expect("high-pkg present");
        // CRITICAL must appear before HIGH in the markdown table
        assert!(crit_pos < high_pos);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
