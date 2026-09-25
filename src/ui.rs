//! Nerdfont glyphs, ANSI colors, and the banner shared by every subcommand.

pub const RED: &str = "\x1b[1;31m";
pub const GREEN: &str = "\x1b[1;32m";
pub const YELLOW: &str = "\x1b[1;33m";
pub const BLUE: &str = "\x1b[1;34m";
pub const MAGENTA: &str = "\x1b[1;35m";
pub const CYAN: &str = "\x1b[1;36m";
pub const DIM: &str = "\x1b[2m";
pub const BOLD: &str = "\x1b[1m";
pub const RESET: &str = "\x1b[0m";

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

pub fn print_banner() {
    eprintln!("{CYAN}{BOLD}");
    eprintln!("  {ICON_SHIELD}  AUR-Sentry v{}", env!("CARGO_PKG_VERSION"));
    eprintln!("  {DIM}supply-chain threat radar for the arch user repository{RESET}");
    eprintln!();
}
