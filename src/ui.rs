//! Visual formatting, Unicode box drawing, threat gauges, and trees for aur-sentry.
//! Preserves existing CLI test assertions while providing modern terminal aesthetics.

use std::io::IsTerminal;

pub const RED: &str = "\x1b[1;31m";
pub const GREEN: &str = "\x1b[1;32m";
pub const YELLOW: &str = "\x1b[1;33m";
pub const BLUE: &str = "\x1b[1;34m";
pub const MAGENTA: &str = "\x1b[1;35m";
pub const CYAN: &str = "\x1b[1;36m";
pub const WHITE: &str = "\x1b[1;37m";
pub const GRAY: &str = "\x1b[90m";
pub const DIM: &str = "\x1b[2m";
pub const BOLD: &str = "\x1b[1m";
pub const UNDERLINE: &str = "\x1b[4m";
pub const RESET: &str = "\x1b[0m";

// Legacy and Nerd Font icons
pub const ICON_SHIELD: &str = "󰒃"; // nf-md-shield_check
pub const ICON_SKULL: &str = "󰚌"; // nf-md-skull
pub const ICON_WARN: &str = "󰀦"; // nf-md-alert
pub const ICON_BUG: &str = "󰨰"; // nf-md-bug
pub const ICON_SEARCH: &str = "󰍉"; // nf-md-magnify
pub const ICON_CHECK: &str = "󰄬"; // nf-md-check
pub const ICON_CROSS: &str = "󰅖"; // nf-md-close
pub const ICON_PKG: &str = "󰏗"; // nf-md-package_variant
pub const ICON_FIRE: &str = "󰈸"; // nf-md-fire
pub const ICON_DOWNLOAD: &str = "󰇚"; // nf-md-download
pub const ICON_RADAR: &str = "󰐻"; // nf-md-radar

// Universal Unicode Glyphs
pub const GLYPH_SHIELD: &str = "🛡";
pub const GLYPH_PKG: &str = "📦";
pub const GLYPH_SEARCH: &str = "🔍";
pub const GLYPH_CHECK: &str = "✔";
pub const GLYPH_CROSS: &str = "✖";
pub const GLYPH_WARN: &str = "⚠";
pub const GLYPH_SKULL: &str = "☠";
pub const GLYPH_BOLT: &str = "⚡";
pub const GLYPH_RADAR: &str = "📡";
pub const GLYPH_LOCK: &str = "🔒";
pub const GLYPH_DOT: &str = "•";

// Tree Drawing Connectors
pub const TREE_BRANCH: &str = "├── ";
pub const TREE_LAST: &str = "└── ";
pub const TREE_VERT: &str = "│   ";
pub const TREE_SPACE: &str = "    ";

// Rounded Box Drawing Characters
pub const BOX_TOP_LEFT: &str = "╭";
pub const BOX_TOP_RIGHT: &str = "╮";
pub const BOX_BOT_LEFT: &str = "╰";
pub const BOX_BOT_RIGHT: &str = "╯";
pub const BOX_HORIZ: &str = "─";
pub const BOX_VERT: &str = "│";

pub fn severity_icon(sev: &str) -> &'static str {
    match sev {
        "CRITICAL" => ICON_SKULL,
        "HIGH" => ICON_FIRE,
        "MEDIUM" => ICON_WARN,
        "LOW" => ICON_BUG,
        _ => ICON_SEARCH,
    }
}

pub fn severity_color(sev: &str) -> &'static str {
    match sev {
        "CRITICAL" => RED,
        "HIGH" => YELLOW,
        "MEDIUM" => MAGENTA,
        _ => DIM,
    }
}

/// Calculate visual display width of a string by stripping ANSI escape sequences
/// and accounting for fullwidth/wide Unicode glyphs.
pub fn visual_width(s: &str) -> usize {
    let mut in_escape = false;
    let mut width = 0;
    for c in s.chars() {
        if c == '\x1b' {
            in_escape = true;
        } else if in_escape {
            if c.is_ascii_alphabetic() {
                in_escape = false;
            }
        } else {
            let u = c as u32;
            let is_wide = (0x1100..=0x115F).contains(&u)
                || (0x2E80..=0xA4CF).contains(&u)
                || (0xAC00..=0xD7A3).contains(&u)
                || (0xF900..=0xFAFF).contains(&u)
                || (0xFE10..=0xFE19).contains(&u)
                || (0xFE30..=0xFE6F).contains(&u)
                || (0xFF00..=0xFF60).contains(&u)
                || (0xFFE0..=0xFFE6).contains(&u)
                || (0x1F300..=0x1F64F).contains(&u)
                || (0x1F680..=0x1F6FF).contains(&u)
                || (0x1F900..=0x1F9FF).contains(&u);
            width += if is_wide { 2 } else { 1 };
        }
    }
    width
}

/// Strip ANSI escape codes from string for plain text environments.
pub fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_escape = false;
    for c in s.chars() {
        if c == '\x1b' {
            in_escape = true;
        } else if in_escape {
            if c.is_ascii_alphabetic() {
                in_escape = false;
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Check if stderr supports color output.
pub fn stderr_supports_color() -> bool {
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    std::io::stderr().is_terminal()
}

/// Generate a colored visual block gauge: `[████████░░] 8.0/10 [CRITICAL]`
pub fn threat_gauge(score: f64, max_score: f64, width: usize, colored: bool) -> String {
    let safe_max = if max_score.is_nan() || max_score <= 0.0 { 10.0 } else { max_score };
    let safe_score = if score.is_nan() || score < 0.0 { 0.0 } else { score };
    let clamped = safe_score.clamp(0.0, safe_max);
    let ratio = if safe_max > 0.0 { clamped / safe_max } else { 0.0 };
    let filled_blocks = (ratio * (width as f64)).round() as usize;
    let filled = filled_blocks.min(width);
    let empty = width.saturating_sub(filled);

    let (color, rating) = if ratio >= 0.70 {
        (RED, "CRITICAL")
    } else if ratio >= 0.40 {
        (YELLOW, "MEDIUM")
    } else if ratio > 0.0 {
        (YELLOW, "LOW")
    } else {
        (GREEN, "CLEAN")
    };

    let bar = format!("{}{}", "█".repeat(filled), "░".repeat(empty));

    if colored {
        format!("{color}[{bar}]{RESET} {BOLD}{clamped:.1}/{safe_max:.0}{RESET} {color}[{rating}]{RESET}")
    } else {
        format!("[{bar}] {clamped:.1}/{safe_max:.0} [{rating}]")
    }
}

/// Calculate a standardized 0.0 - 10.0 threat score from scanner findings.
pub fn score_from_findings(findings: &[crate::findings::Finding]) -> f64 {
    let mut score: f64 = 0.0;
    for f in findings {
        match f.severity.as_str() {
            "CRITICAL" => score += 5.0,
            "HIGH" => score += 3.0,
            "MEDIUM" => score += 1.5,
            "LOW" => score += 0.5,
            _ => score += 0.2,
        }
    }
    score.min(10.0)
}

pub struct BoxRow<'a> {
    pub label: &'a str,
    pub value: String,
}

impl<'a> BoxRow<'a> {
    pub fn new(label: &'a str, value: impl Into<String>) -> Self {
        Self {
            label,
            value: value.into(),
        }
    }
}

/// Render a rounded modern box with automatic column padding and pixel-perfect right borders.
pub fn render_box(
    title: &str,
    rows: &[BoxRow],
    border_color: &str,
    min_width: usize,
) -> String {
    let mut content_width = min_width;
    for row in rows {
        let row_w = visual_width(row.label) + 2 + visual_width(&row.value);
        if row_w > content_width {
            content_width = row_w;
        }
    }
    let header_len = visual_width(title) + 6;
    if header_len > content_width {
        content_width = header_len;
    }

    let inner_width = content_width + 2;
    let mut out = String::new();

    // Top border with title
    let title_vis = visual_width(title);
    let top_dashes = inner_width.saturating_sub(title_vis + 3);
    out.push_str(&format!(
        "{border_color}{BOX_TOP_LEFT}{BOX_HORIZ} {BOLD}{title}{RESET}{border_color} {}{BOX_TOP_RIGHT}{RESET}\n",
        BOX_HORIZ.repeat(top_dashes)
    ));

    // Rows
    for row in rows {
        let text = format!("{BOLD}{}{RESET}  {}", row.label, row.value);
        let pad = inner_width.saturating_sub(visual_width(&text) + 1);
        out.push_str(&format!(
            "{border_color}{BOX_VERT}{RESET} {text}{}{border_color}{BOX_VERT}{RESET}\n",
            " ".repeat(pad)
        ));
    }

    // Bottom border
    out.push_str(&format!(
        "{border_color}{BOX_BOT_LEFT}{}{BOX_BOT_RIGHT}{RESET}\n",
        BOX_HORIZ.repeat(inner_width)
    ));

    out
}

#[derive(Debug, Clone)]
pub struct TreeNode {
    pub text: String,
    pub badge: Option<String>,
    pub children: Vec<TreeNode>,
}

impl TreeNode {
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            badge: None,
            children: Vec::new(),
        }
    }

    pub fn with_badge(mut self, badge: impl Into<String>) -> Self {
        self.badge = Some(badge.into());
        self
    }

    pub fn add_child(&mut self, child: TreeNode) {
        self.children.push(child);
    }
}

/// Render a tree structure with standard Unicode branch connectors.
pub fn format_tree(root: &TreeNode) -> String {
    let mut out = String::new();
    format_tree_recursive(root, "", true, true, &mut out);
    out
}

fn format_tree_recursive(
    node: &TreeNode,
    prefix: &str,
    is_last: bool,
    is_root: bool,
    out: &mut String,
) {
    if is_root {
        if let Some(badge) = &node.badge {
            out.push_str(&format!("{} {}\n", node.text, badge));
        } else {
            out.push_str(&format!("{}\n", node.text));
        }
    } else {
        let connector = if is_last { TREE_LAST } else { TREE_BRANCH };
        let badge_str = node
            .badge
            .as_deref()
            .map(|b| format!(" {b}"))
            .unwrap_or_default();
        out.push_str(&format!("{prefix}{connector}{}{badge_str}\n", node.text));
    }

    let count = node.children.len();
    for (i, child) in node.children.iter().enumerate() {
        let child_is_last = i + 1 == count;
        let next_prefix = if is_root {
            ""
        } else if is_last {
            &format!("{prefix}{TREE_SPACE}")
        } else {
            &format!("{prefix}{TREE_VERT}")
        };
        format_tree_recursive(child, next_prefix, child_is_last, false, out);
    }
}

/// Print the primary AUR-Sentry banner.
/// MUST strictly contain the substring "AUR-Sentry" to satisfy test_cli_help_flag_displays_usage_and_banner.
pub fn print_banner() {
    let version = env!("CARGO_PKG_VERSION");
    let width = 66;
    let title = format!("  {ICON_SHIELD}  AUR-Sentry v{version}");
    let subtitle = "  supply-chain threat radar for the arch user repository";

    eprintln!("{CYAN}╭{}╮{RESET}", "─".repeat(width));
    eprintln!("{CYAN}│{BOLD}{WHITE}{:<w$}{RESET}{CYAN}│{RESET}", title, w = width);
    eprintln!("{CYAN}│{DIM}{:<w$}{RESET}{CYAN}│{RESET}", subtitle, w = width);
    eprintln!("{CYAN}╰{}╯{RESET}", "─".repeat(width));
    eprintln!();
}

/// Print formatted scan results for human readability on stderr.
/// Strictly preserves existing CLI test assertions:
/// - "clean" and "no threats detected" on clean scans.
/// - "threat(s) detected" on threat scans.
pub fn print_scan_results(target: &str, findings: &[crate::findings::Finding]) {
    let score = score_from_findings(findings);
    let gauge = threat_gauge(score, 10.0, 10, true);

    if findings.is_empty() {
        let rows = [
            BoxRow::new("Target:", target),
            BoxRow::new("Threat Gauge:", gauge),
            BoxRow::new("Status:", format!("{GREEN}clean — no threats detected{RESET}")),
        ];
        let box_str = render_box("SCAN VERDICT: VERIFIED CLEAN", &rows, GREEN, 60);
        eprint!("{box_str}");
        eprintln!();
        eprintln!("  {GREEN}{ICON_CHECK} {BOLD}clean{RESET}{GREEN} — no threats detected{RESET}");
        eprintln!();
        return;
    }

    let border_color = if score >= 7.0 {
        RED
    } else {
        YELLOW
    };

    let rows = [
        BoxRow::new("Target:", target),
        BoxRow::new("Findings:", format!("{RED}{} threat(s) detected{RESET}", findings.len())),
        BoxRow::new("Threat Gauge:", gauge),
        BoxRow::new("Action:", format!("{RED}QUARANTINE — DO NOT BUILD OR INSTALL{RESET}")),
    ];
    let box_str = render_box("SCAN VERDICT: THREAT DETECTED", &rows, border_color, 60);
    eprint!("{box_str}");
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
    fn test_visual_width_ignores_ansi_escapes() {
        let colored = format!("{RED}hello world{RESET}");
        assert_eq!(visual_width(&colored), 11);
        assert_eq!(strip_ansi(&colored), "hello world");
    }

    #[test]
    fn test_threat_gauge_formatting() {
        let clean = threat_gauge(0.0, 10.0, 10, false);
        assert!(clean.contains("[░░░░░░░░░░]"));
        assert!(clean.contains("0.0/10"));
        assert!(clean.contains("[CLEAN]"));

        let critical = threat_gauge(9.0, 10.0, 10, false);
        assert!(critical.contains("[█████████░]"));
        assert!(critical.contains("9.0/10"));
        assert!(critical.contains("[CRITICAL]"));
    }

    #[test]
    fn test_render_box_contains_title_and_rows() {
        let rows = [
            BoxRow::new("Package:", "aur-sentry"),
            BoxRow::new("Status:", "OK"),
        ];
        let rendered = render_box("TEST BOX", &rows, CYAN, 40);
        assert!(rendered.contains("TEST BOX"));
        assert!(rendered.contains("Package:"));
        assert!(rendered.contains("aur-sentry"));
        assert!(rendered.contains(BOX_TOP_LEFT));
        assert!(rendered.contains(BOX_BOT_RIGHT));
    }

    #[test]
    fn test_format_tree_connectors() {
        let mut root = TreeNode::new("root-pkg");
        let mut child1 = TreeNode::new("dep-a");
        child1.add_child(TreeNode::new("transitive-1"));
        let child2 = TreeNode::new("dep-b");

        root.add_child(child1);
        root.add_child(child2);

        let tree = format_tree(&root);
        assert!(tree.contains("root-pkg"));
        assert!(tree.contains("├── dep-a"));
        assert!(tree.contains("└── dep-b"));
        assert!(tree.contains("transitive-1"));
    }
}
