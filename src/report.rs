//! Report generation — advisories.json and RSS feed output.

use crate::scanner::Finding;
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

    // Sort: CRITICAL first, then HIGH, then by detected_at desc
    existing.sort_by(|a, b| {
        severity_rank(&a.highest_severity)
            .cmp(&severity_rank(&b.highest_severity))
            .then_with(|| b.detected_at.cmp(&a.detected_at))
    });

    let feed = AdvisoryFeed {
        version: "1.0".into(),
        updated_at: Utc::now().to_rfc3339(),
        total_flagged: existing.len(),
        advisories: existing.clone(),
    };

    let json = serde_json::to_string_pretty(&feed).unwrap_or_default();
    let _ = std::fs::write(repo_root.join("advisories.json"), json);

    // Generate RSS
    generate_rss(repo_root, &existing);
}

fn severity_rank(s: &str) -> u8 {
    match s {
        "CRITICAL" => 0,
        "HIGH" => 1,
        "MEDIUM" => 2,
        "LOW" => 3,
        _ => 4,
    }
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

/// Update the README.md threat radar table.
pub fn update_readme_table(repo_root: &Path, advisories: &[Advisory]) {
    let readme_path = repo_root.join("README.md");
    let content = match std::fs::read_to_string(&readme_path) {
        Ok(c) => c,
        Err(_) => return,
    };

    let start = "<!-- AUTOPILOT_TABLE_START -->";
    let end = "<!-- AUTOPILOT_TABLE_END -->";
    if !content.contains(start) || !content.contains(end) {
        return;
    }

    let table = if advisories.is_empty() {
        "\n<details>\n<summary>Active Threats (0)</summary>\n\n*No active threats recorded in the radar.*\n</details>\n".to_string()
    } else {
        let mut lines = vec![
            format!(
                "\n<details open>\n<summary>Active Threats ({})</summary>\n",
                advisories.len()
            ),
            "| Severity | Package | Version | Maintainer | Triggers | Link |".to_string(),
            "| :--- | :--- | :--- | :--- | :--- | :--- |".to_string(),
        ];
        for adv in advisories.iter().take(25) {
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
    let _ = std::fs::write(&readme_path, new_content);
}
