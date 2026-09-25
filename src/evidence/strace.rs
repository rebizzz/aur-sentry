//! Dynamic-sandbox strace telemetry: network/filesystem event extraction,
//! declared-source allowlisting, and the findings those events imply.

use crate::attestation::{Behavior, FilesystemEvent, Finding, NetworkEvent, Severity};
use std::collections::HashSet;
use std::net::ToSocketAddrs;
use std::sync::LazyLock;

static STRACE_CONNECT_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
        r#"(?:connect|sendto)\(.*?sin_port=htons\((?P<port>\d+)\).*?sin_addr=inet_addr\("(?P<ip>[\d.]+)"\)"#,
    )
    .unwrap()
});

// `[^")]*` (not just `[^)]*`, unlike build_attestation.py's version of this
// regex) so the greedy prefix can't backtrack past the *closing* quote of
// the path and swallow text from a subsequent syscall on the same line.
static STRACE_OPEN_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r#"open(?:at)?\([^")]*"(?P<path>[^"]+)""#).unwrap());

static URL_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r#"https?://[^\s"'()]+"#).unwrap());

/// Best-effort DNS resolution of PKGBUILD `source=()` hosts, so telemetry
/// connections outside this allowlist can be flagged as undeclared network.
pub fn declared_source_ips(pkgbuild_text: &str) -> HashSet<String> {
    let mut ips = HashSet::new();
    for m in URL_RE.find_iter(pkgbuild_text) {
        let Some(host) = extract_host(m.as_str()) else {
            continue;
        };
        if let Ok(mut addrs) = (host.as_str(), 80u16).to_socket_addrs() {
            if let Some(addr) = addrs.next() {
                ips.insert(addr.ip().to_string());
            }
        }
    }
    ips
}

fn extract_host(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://")?.1;
    let host_port = after_scheme.split(['/', '?', '#']).next()?;
    let host = host_port.rsplit('@').next()?.split(':').next()?;
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// Parse strace `-e trace=network,file` output into network/filesystem
/// events, tagging each with which sandbox pass (`PHASE_BUILD`/
/// `PHASE_INSTALL`) produced it. Process events aren't recoverable from this
/// telemetry shape yet, so that vector stays empty (mirrors the Python
/// fallback).
pub fn parse_telemetry(
    text: &str,
    allowed_ips: &HashSet<String>,
    phase: &str,
) -> (Vec<NetworkEvent>, Vec<FilesystemEvent>) {
    let now = chrono::Utc::now().to_rfc3339();

    let mut network = Vec::new();
    let mut seen_net = HashSet::new();
    for cap in STRACE_CONNECT_RE.captures_iter(text) {
        let Ok(port) = cap["port"].parse::<u16>() else {
            continue;
        };
        let ip = cap["ip"].to_string();
        if !seen_net.insert((ip.clone(), port)) {
            continue;
        }
        let undeclared = !allowed_ips.contains(&ip) && !ip.starts_with("127.");
        network.push(NetworkEvent {
            destination: ip,
            port: Some(port),
            protocol: Some(if undeclared {
                "undeclared".into()
            } else {
                "declared-source".into()
            }),
            timestamp: now.clone(),
            phase: phase.to_string(),
        });
    }

    let mut filesystem = Vec::new();
    let mut seen_fs = HashSet::new();
    for cap in STRACE_OPEN_RE.captures_iter(text) {
        let path = cap["path"].to_string();
        if !path.contains("id_fake") && !path.contains(".aws/credentials") {
            continue;
        }
        if !seen_fs.insert(path.clone()) {
            continue;
        }
        filesystem.push(FilesystemEvent {
            path,
            operation: "canary_access".into(),
            timestamp: now.clone(),
            phase: phase.to_string(),
        });
    }

    (network, filesystem)
}

/// Fold a phase's canary/network telemetry into findings so
/// `verdict_from_findings` (Phase 1's single source of verdict truth) treats
/// install-phase hits exactly like build-phase hits, instead of duplicating
/// verdict logic per phase. `phase_label` is human-readable text for the
/// finding description only (`"build"`/`"install"`) — not the same as the
/// `phase` field stored on the telemetry events themselves.
pub fn dynamic_findings(
    network: &[NetworkEvent],
    filesystem: &[FilesystemEvent],
    phase_label: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    if !filesystem.is_empty() {
        let touched: Vec<&str> = filesystem.iter().map(|f| f.path.as_str()).collect();
        findings.push(Finding {
            behavior: Behavior::CredentialAccess,
            file: "dynamic-sandbox".into(),
            line: 0,
            severity: Severity::Critical,
            description: format!(
                "canary secret accessed during {phase_label}: {}",
                touched.join(", ")
            ),
        });
    }
    if network
        .iter()
        .any(|n| n.protocol.as_deref() == Some("undeclared"))
    {
        findings.push(Finding {
            behavior: Behavior::NetworkAccess,
            file: "dynamic-sandbox".into(),
            line: 0,
            severity: Severity::High,
            description: format!(
                "connected to network destination(s) not declared in PKGBUILD source=() during {phase_label}"
            ),
        });
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::{PHASE_BUILD, PHASE_INSTALL};

    #[test]
    fn parses_telemetry_connect_and_canary_open() {
        let text = concat!(
            "12345 connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr(\"1.2.3.4\")}, 16) = 0\n",
            "12345 openat(AT_FDCWD, \"/home/builder/.ssh/id_fake\", O_RDONLY) = 4\n",
            "12345 openat(AT_FDCWD, \"/etc/passwd\", O_RDONLY) = 5\n",
        );
        let allowed: HashSet<String> = HashSet::new();
        let (network, filesystem) = parse_telemetry(text, &allowed, PHASE_BUILD);
        assert_eq!(network.len(), 1);
        assert_eq!(network[0].destination, "1.2.3.4");
        assert_eq!(network[0].protocol.as_deref(), Some("undeclared"));
        assert_eq!(network[0].phase, "build");
        assert_eq!(filesystem.len(), 1);
        assert!(filesystem[0].path.contains("id_fake"));
        assert_eq!(filesystem[0].phase, "build");
    }

    #[test]
    fn declared_ip_is_not_flagged_as_undeclared() {
        let text = "12345 connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr(\"127.0.0.1\")}, 16) = 0\n";
        let allowed: HashSet<String> = HashSet::new();
        let (network, _) = parse_telemetry(text, &allowed, PHASE_BUILD);
        assert_eq!(network[0].protocol.as_deref(), Some("declared-source"));
    }

    #[test]
    fn parse_telemetry_tags_install_phase() {
        let text = "12345 openat(AT_FDCWD, \"/root/.ssh/id_fake\", O_RDONLY) = 4\n";
        let allowed: HashSet<String> = HashSet::new();
        let (_, filesystem) = parse_telemetry(text, &allowed, PHASE_INSTALL);
        assert_eq!(filesystem.len(), 1);
        assert_eq!(filesystem[0].phase, "install");
    }
}
