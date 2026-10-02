//! Native container sandbox runner for dynamic strace telemetry and behavioral auditing.
//! Manages container engine detection, disposable execution, and evidence compilation.

use crate::attest::{AttestInputs, build_attestation};
use crate::attestation::{Attestation, FilesystemEvent, NetworkEvent, ReproducibilityStatus};
use crate::aur_client::AURClient;
use crate::evidence::strace::{declared_source_ips, parse_telemetry};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

static PKG_NAME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9@_+][A-Za-z0-9@._+-]{0,127}$").expect("valid regex"));

static INSTALL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"install=\s*['"]?([a-zA-Z0-9._-]+\.install)"#).expect("valid regex")
});

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum EnginePreference {
    #[default]
    Auto,
    Podman,
    Docker,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContainerEngineType {
    Podman,
    Docker,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerEngineInfo {
    pub engine_type: ContainerEngineType,
    pub binary_path: PathBuf,
    pub version: String,
    pub is_rootless: bool,
    pub socket_available: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum NetworkMode {
    #[default]
    Host,
    None,
}

#[derive(Debug, Clone)]
pub struct SandboxOptions {
    pub engine: EnginePreference,
    pub timeout: Duration,
    pub memory_limit: String,
    pub cpu_limit: String,
    pub network_mode: NetworkMode,
    pub enable_strace: bool,
    pub keep_container: bool,
    pub custom_output_dir: Option<PathBuf>,
}

impl Default for SandboxOptions {
    fn default() -> Self {
        Self {
            engine: EnginePreference::Auto,
            timeout: Duration::from_secs(15 * 60),
            memory_limit: "4g".to_string(),
            cpu_limit: "2".to_string(),
            network_mode: NetworkMode::Host,
            enable_strace: true,
            keep_container: false,
            custom_output_dir: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SandboxPaths {
    pub repo_root: PathBuf,
    pub root: PathBuf,         // <repo_root>/generated/sandbox/<pkgname>
    pub source_dir: PathBuf,   // <repo_root>/generated/sandbox/<pkgname>/source
    pub evidence_dir: PathBuf, // <repo_root>/generated/sandbox/<pkgname>/evidence
    pub work_dir: PathBuf,     // <repo_root>/generated/sandbox/<pkgname>/work
}

#[derive(Debug)]
pub enum SandboxError {
    NoContainerEngine,
    DockerDaemonUnavailable(String),
    EngineNotFound(String),
    InvalidPackageName(String),
    SourceAcquisitionFailed(String),
    ImageBuildFailed(String),
    ExecutionFailed {
        phase: String,
        exit_code: i32,
        details: String,
    },
    ExecutionTimedOut {
        phase: String,
        duration: Duration,
    },
    IoError(std::io::Error),
    EvidenceParseError(String),
}

impl std::fmt::Display for SandboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SandboxError::NoContainerEngine => write!(
                f,
                "No container engine (podman or docker) was found on this system.\n\
                 Recommendation:\n  \
                   - Arch Linux:    sudo pacman -S podman\n  \
                   - Debian/Ubuntu: sudo apt-get install podman\n  \
                   - Fedora:        sudo dnf install podman\n  \
                   - Or start Docker: sudo systemctl start docker"
            ),
            SandboxError::DockerDaemonUnavailable(reason) => write!(
                f,
                "Docker binary found, but Docker daemon is unreachable: {reason}\n\
                 Ensure docker service is running: sudo systemctl start docker\n\
                 Or use rootless podman: aur-sentry sandbox <pkg> --engine podman"
            ),
            SandboxError::EngineNotFound(eng) => {
                write!(f, "Requested container engine '{eng}' not found in PATH")
            }
            SandboxError::InvalidPackageName(name) => write!(
                f,
                "Invalid package name '{name}' (must match ^[A-Za-z0-9@_+][A-Za-z0-9@._+-]{{0,127}}$)"
            ),
            SandboxError::SourceAcquisitionFailed(msg) => {
                write!(f, "Failed to acquire package sources: {msg}")
            }
            SandboxError::ImageBuildFailed(msg) => {
                write!(f, "Failed to build sandbox container image: {msg}")
            }
            SandboxError::ExecutionFailed {
                phase,
                exit_code,
                details,
            } => {
                write!(
                    f,
                    "Sandbox execution failed during {phase} (exit code {exit_code}): {details}"
                )
            }
            SandboxError::ExecutionTimedOut { phase, duration } => {
                write!(
                    f,
                    "Sandbox execution timed out during {phase} after {}s",
                    duration.as_secs()
                )
            }
            SandboxError::IoError(e) => write!(f, "I/O error: {e}"),
            SandboxError::EvidenceParseError(msg) => {
                write!(f, "Failed to parse sandbox evidence: {msg}")
            }
        }
    }
}

impl std::error::Error for SandboxError {}
impl From<std::io::Error> for SandboxError {
    fn from(e: std::io::Error) -> Self {
        SandboxError::IoError(e)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxAuditResult {
    pub package: String,
    pub version: String,
    pub engine: ContainerEngineInfo,
    pub makepkg_exit: Option<i32>,
    pub strace_available: bool,
    pub reproducibility: ReproducibilityStatus,
    pub network_events: Vec<NetworkEvent>,
    pub filesystem_events: Vec<FilesystemEvent>,
    pub static_findings_count: usize,
    pub dynamic_findings_count: usize,
    pub attestation: Attestation,
    pub evidence_directory: PathBuf,
    pub execution_duration_ms: u64,
}

/// Find repository root directory by walking up from current directory or CARGO_MANIFEST_DIR.
pub fn find_repo_root() -> PathBuf {
    if let Ok(manifest) = std::env::var("CARGO_MANIFEST_DIR") {
        let p = PathBuf::from(manifest);
        if p.join("sandbox/run.sh").exists() {
            return p;
        }
    }

    if let Ok(cwd) = std::env::current_dir() {
        let mut cur = cwd.as_path();
        loop {
            if cur.join("sandbox/run.sh").exists() && cur.join("Cargo.toml").exists() {
                return cur.to_path_buf();
            }
            match cur.parent() {
                Some(p) => cur = p,
                None => break,
            }
        }
    }

    PathBuf::from(".")
}

/// Detects available container engine honoring user preference.
pub fn detect_container_engine(
    preference: EnginePreference,
) -> Result<ContainerEngineInfo, SandboxError> {
    match preference {
        EnginePreference::Podman => check_podman().map_err(|_| {
            SandboxError::EngineNotFound("podman requested but not found in PATH".into())
        }),
        EnginePreference::Docker => check_docker().map_err(|e| match e {
            SandboxError::DockerDaemonUnavailable(msg) => {
                SandboxError::DockerDaemonUnavailable(msg)
            }
            _ => SandboxError::EngineNotFound("docker requested but not found in PATH".into()),
        }),
        EnginePreference::Auto => {
            // Priority: podman (rootless default) -> docker fallback
            if let Ok(info) = check_podman() {
                return Ok(info);
            }
            if let Ok(info) = check_docker() {
                return Ok(info);
            }
            Err(SandboxError::NoContainerEngine)
        }
    }
}

fn check_podman() -> Result<ContainerEngineInfo, SandboxError> {
    let output = Command::new("podman")
        .arg("--version")
        .output()
        .map_err(SandboxError::IoError)?;

    if !output.status.success() {
        return Err(SandboxError::EngineNotFound("podman".into()));
    }

    let version = String::from_utf8_lossy(&output.stdout).trim().to_string();

    let rootless_out = Command::new("podman")
        .args(["info", "--format", "{{.Host.Security.Rootless}}"])
        .output();

    let is_rootless = rootless_out
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "true")
        .unwrap_or(false);

    Ok(ContainerEngineInfo {
        engine_type: ContainerEngineType::Podman,
        binary_path: PathBuf::from("podman"),
        version,
        is_rootless,
        socket_available: true,
    })
}

fn check_docker() -> Result<ContainerEngineInfo, SandboxError> {
    let output = Command::new("docker")
        .arg("--version")
        .output()
        .map_err(SandboxError::IoError)?;

    if !output.status.success() {
        return Err(SandboxError::EngineNotFound("docker".into()));
    }

    let version = String::from_utf8_lossy(&output.stdout).trim().to_string();

    // Verify docker daemon accessibility
    let info_out = Command::new("docker")
        .arg("info")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output();

    match info_out {
        Ok(out) if out.status.success() => Ok(ContainerEngineInfo {
            engine_type: ContainerEngineType::Docker,
            binary_path: PathBuf::from("docker"),
            version,
            is_rootless: false,
            socket_available: true,
        }),
        Ok(out) => {
            let err_msg = String::from_utf8_lossy(&out.stderr).trim().to_string();
            Err(SandboxError::DockerDaemonUnavailable(err_msg))
        }
        Err(e) => Err(SandboxError::DockerDaemonUnavailable(e.to_string())),
    }
}

/// Validates package name and prepares directory layout inside `generated/sandbox/<pkgname>`.
pub fn prepare_sandbox_paths(
    repo_root: &Path,
    pkgname: &str,
    custom_out: Option<&Path>,
) -> Result<SandboxPaths, SandboxError> {
    if !PKG_NAME_RE.is_match(pkgname) {
        return Err(SandboxError::InvalidPackageName(pkgname.to_string()));
    }

    let has_traversal = custom_out.is_some_and(|p| {
        p.components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    });

    let base_root = if let Some(custom) = custom_out {
        // Enforce that custom directory is anchored within generated/ and contains no traversal
        if has_traversal
            || (!custom.starts_with(repo_root.join("generated"))
                && !custom.starts_with("generated"))
        {
            repo_root.join("generated/sandbox").join(pkgname)
        } else if custom.is_relative() {
            repo_root.join(custom)
        } else {
            custom.to_path_buf()
        }
    } else {
        repo_root.join("generated/sandbox").join(pkgname)
    };

    let source_dir = base_root.join("source");
    let evidence_dir = base_root.join("evidence");
    let work_dir = base_root.join("work");

    std::fs::create_dir_all(&source_dir)?;
    std::fs::create_dir_all(&evidence_dir)?;
    std::fs::create_dir_all(&work_dir)?;

    Ok(SandboxPaths {
        repo_root: repo_root.to_path_buf(),
        root: base_root,
        source_dir,
        evidence_dir,
        work_dir,
    })
}

/// Acquires package snapshot (local directory or download from AUR) and places it into `paths.source_dir`.
pub fn acquire_package_source(
    target: &str,
    paths: &SandboxPaths,
) -> Result<(String, String), SandboxError> {
    let target_path = Path::new(target);

    // Case 1: Target is an existing local file or directory
    if target_path.exists() {
        if target_path.is_file() {
            let file_name = target_path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "PKGBUILD".to_string());

            let content = std::fs::read_to_string(target_path)?;
            let dest_pkgbuild = paths.source_dir.join("PKGBUILD");
            std::fs::write(&dest_pkgbuild, &content)?;

            // Copy parent .SRCINFO or .install files if present
            if let Some(parent) = target_path.parent() {
                copy_auxiliary_source_files(parent, &paths.source_dir);
            }

            let (pkgname, version) = extract_identity_from_pkgbuild(&content)
                .unwrap_or_else(|| (file_name, "1.0.0-1".to_string()));
            return Ok((pkgname, version));
        } else if target_path.is_dir() {
            let pkgbuild_path = target_path.join("PKGBUILD");
            if !pkgbuild_path.is_file() {
                return Err(SandboxError::SourceAcquisitionFailed(format!(
                    "Directory '{}' contains no regular PKGBUILD",
                    target_path.display()
                )));
            }
            let content = std::fs::read_to_string(&pkgbuild_path)?;
            std::fs::write(paths.source_dir.join("PKGBUILD"), &content)?;

            copy_auxiliary_source_files(target_path, &paths.source_dir);

            let (pkgname, version) = extract_identity_from_pkgbuild(&content)
                .unwrap_or_else(|| ("pkg".to_string(), "1.0.0-1".to_string()));
            return Ok((pkgname, version));
        }
    }

    // Case 2: Target is an AUR package name
    if !PKG_NAME_RE.is_match(target) {
        return Err(SandboxError::InvalidPackageName(target.to_string()));
    }

    let client = AURClient::new();
    let pkgbuild_content = client.fetch_pkgbuild(target).ok_or_else(|| {
        SandboxError::SourceAcquisitionFailed(format!(
            "Could not fetch PKGBUILD for '{target}' from AUR"
        ))
    })?;

    let dest_pkgbuild = paths.source_dir.join("PKGBUILD");
    std::fs::write(&dest_pkgbuild, &pkgbuild_content)?;

    // If PKGBUILD references an install file, fetch it too
    if let Some(caps) = INSTALL_RE.captures(&pkgbuild_content) {
        if let Some(install_name) = caps.get(1) {
            let install_name_str = install_name.as_str();
            if let Some(install_content) = client.fetch_install_file(target, install_name_str) {
                let _ = std::fs::write(paths.source_dir.join(install_name_str), &install_content);
            }
        }
    }

    let (pkgname, version) = extract_identity_from_pkgbuild(&pkgbuild_content)
        .unwrap_or_else(|| (target.to_string(), "1.0.0-1".to_string()));

    Ok((pkgname, version))
}

fn copy_auxiliary_source_files(from_dir: &Path, to_dir: &Path) {
    if let Ok(entries) = std::fs::read_dir(from_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name == ".SRCINFO" || name == "SRCINFO" || name.ends_with(".install") {
                    let _ = std::fs::copy(&path, to_dir.join(name));
                }
            }
        }
    }
}

fn extract_identity_from_pkgbuild(content: &str) -> Option<(String, String)> {
    let mut pkgname = None;
    let mut pkgver = None;
    let mut pkgrel = None;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = trimmed.split_once('=') {
            let key = k.trim();
            let val = v.trim().trim_matches(|c| c == '\'' || c == '"').trim();
            match key {
                "pkgname" if pkgname.is_none() => pkgname = Some(val.to_string()),
                "pkgver" if pkgver.is_none() => pkgver = Some(val.to_string()),
                "pkgrel" if pkgrel.is_none() => pkgrel = Some(val.to_string()),
                _ => {}
            }
        }
    }

    let name = pkgname?;
    let ver = format!(
        "{}-{}",
        pkgver.unwrap_or_else(|| "1.0.0".to_string()),
        pkgrel.unwrap_or_else(|| "1".to_string())
    );
    Some((name, ver))
}

/// Runs the full container sandbox dynamic analysis pipeline.
pub fn run_sandbox_audit(
    target: &str,
    options: &SandboxOptions,
) -> Result<SandboxAuditResult, SandboxError> {
    let start_time = Instant::now();
    let repo_root = find_repo_root();

    // 1. Detect container engine
    let engine_info = detect_container_engine(options.engine)?;

    // 2. Validate package and prepare sandbox paths under generated/sandbox/<pkgname>
    let raw_name = Path::new(target)
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| target.to_string());
    let clean_name = if PKG_NAME_RE.is_match(&raw_name) && raw_name != "PKGBUILD" {
        raw_name
    } else if PKG_NAME_RE.is_match(target) {
        target.to_string()
    } else {
        "sandbox-pkg".to_string()
    };

    let paths = prepare_sandbox_paths(
        &repo_root,
        &clean_name,
        options.custom_output_dir.as_deref(),
    )?;

    // 3. Acquire package source into paths.source_dir
    let (pkgname, version) = acquire_package_source(target, &paths)?;

    // 4. Locate sandbox/run.sh
    let run_script = repo_root.join("sandbox/run.sh");
    if !run_script.exists() {
        return Err(SandboxError::ExecutionFailed {
            phase: "locate_script".into(),
            exit_code: 1,
            details: format!("Could not find sandbox/run.sh at {}", run_script.display()),
        });
    }

    // Determine binary path for AUR_SENTRY_BIN
    let aur_sentry_bin = std::env::var("AUR_SENTRY_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let debug_bin = repo_root.join("target/debug/aur-sentry");
            let release_bin = repo_root.join("target/release/aur-sentry");
            if release_bin.exists() {
                release_bin
            } else if debug_bin.exists() {
                debug_bin
            } else {
                PathBuf::from("aur-sentry")
            }
        });

    // 5. Execute sandbox/run.sh
    let mut cmd = Command::new(&run_script);
    cmd.arg(&pkgname)
        .arg(&paths.source_dir)
        .arg(&paths.evidence_dir);

    cmd.env(
        "CONTAINER_RUNTIME",
        engine_info.binary_path.to_string_lossy().as_ref(),
    );
    cmd.env("SANDBOX_WORK", paths.work_dir.to_string_lossy().as_ref());
    cmd.env("SANDBOX_MEM", &options.memory_limit);
    cmd.env("SANDBOX_CPUS", &options.cpu_limit);
    cmd.env("SANDBOX_TIMEOUT", format!("{}s", options.timeout.as_secs()));
    cmd.env("AUR_SENTRY_BIN", aur_sentry_bin.to_string_lossy().as_ref());

    let status = cmd.status().map_err(|e| SandboxError::ExecutionFailed {
        phase: "container_spawn".into(),
        exit_code: -1,
        details: e.to_string(),
    })?;

    let makepkg_exit = status.code();

    // 6. Gather and assimilate evidence from paths.evidence_dir
    let telemetry_path = paths.evidence_dir.join("telemetry.log");
    let install_telemetry_path = paths.evidence_dir.join("install_telemetry.log");
    let static_findings_path = paths.evidence_dir.join("static_findings.json");
    let package_analysis_path = paths.evidence_dir.join("package_analysis.json");
    let external_intel_path = paths.evidence_dir.join("external_intel.json");

    let strace_unavailable = paths
        .evidence_dir
        .join("telemetry.unavailable.note")
        .exists();
    let strace_available = options.enable_strace && !strace_unavailable;

    let pkgbuild_file = paths.source_dir.join("PKGBUILD");
    let pkgbuild_text = std::fs::read_to_string(&pkgbuild_file).unwrap_or_default();
    let allowed_ips = declared_source_ips(&pkgbuild_text);

    let telemetry_text = if strace_available {
        std::fs::read_to_string(&telemetry_path).unwrap_or_default()
    } else {
        String::new()
    };

    let (network_events, filesystem_events) = if strace_available && !telemetry_text.is_empty() {
        parse_telemetry(&telemetry_text, &allowed_ips, "build")
    } else {
        (Vec::new(), Vec::new())
    };

    let attest_inputs = AttestInputs {
        package: pkgname.clone(),
        version: version.clone(),
        arch: "x86_64".into(),
        aur_commit: "".into(),
        pkgbuild_path: Some(&pkgbuild_file),
        install_path: None,
        static_findings_path: if static_findings_path.exists() {
            Some(&static_findings_path)
        } else {
            None
        },
        telemetry_path: if telemetry_path.exists() {
            Some(&telemetry_path)
        } else {
            None
        },
        install_telemetry_path: if install_telemetry_path.exists() {
            Some(&install_telemetry_path)
        } else {
            None
        },
        package_analysis_path: if package_analysis_path.exists() {
            Some(&package_analysis_path)
        } else {
            None
        },
        external_intelligence_path: if external_intel_path.exists() {
            Some(&external_intel_path)
        } else {
            None
        },
        strace_available,
        makepkg_exit,
        scanner_version: env!("CARGO_PKG_VERSION").into(),
        reproducibility: ReproducibilityStatus::NotAttempted,
    };

    let attestation = build_attestation(&attest_inputs);
    let duration_ms = start_time.elapsed().as_millis() as u64;

    Ok(SandboxAuditResult {
        package: pkgname,
        version,
        engine: engine_info,
        makepkg_exit,
        strace_available,
        reproducibility: ReproducibilityStatus::NotAttempted,
        network_events,
        filesystem_events,
        static_findings_count: attestation.static_findings.len(),
        dynamic_findings_count: attestation
            .static_findings
            .iter()
            .filter(|f| f.file.starts_with("telemetry"))
            .count(),
        attestation,
        evidence_directory: paths.evidence_dir,
        execution_duration_ms: duration_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_repo_root_detects_project() {
        let root = find_repo_root();
        assert!(root.join("Cargo.toml").exists());
        assert!(root.join("sandbox/run.sh").exists());
    }

    #[test]
    fn test_package_name_validation() {
        assert!(PKG_NAME_RE.is_match("google-chrome"));
        assert!(PKG_NAME_RE.is_match("yay-git"));
        assert!(PKG_NAME_RE.is_match("lib32-glibc"));
        assert!(!PKG_NAME_RE.is_match("../malicious/traversal"));
        assert!(!PKG_NAME_RE.is_match("foo;rm -rf /"));
    }

    #[test]
    fn test_prepare_sandbox_paths_anchored_in_generated() {
        let repo_root = find_repo_root();
        let paths = prepare_sandbox_paths(&repo_root, "test-pkg", None).unwrap();

        assert!(paths.root.starts_with(repo_root.join("generated")));
        assert!(paths.source_dir.starts_with(&paths.root));
        assert!(paths.evidence_dir.starts_with(&paths.root));
        assert!(paths.work_dir.starts_with(&paths.root));
        assert!(paths.source_dir.exists());
        assert!(paths.evidence_dir.exists());
        assert!(paths.work_dir.exists());
    }

    #[test]
    fn test_acquire_package_source_from_local_pkgbuild() {
        let repo_root = find_repo_root();
        let paths = prepare_sandbox_paths(&repo_root, "test-local", None).unwrap();

        let local_pkgbuild = paths.source_dir.join("PKGBUILD");
        std::fs::write(
            &local_pkgbuild,
            "pkgname=local-tool\npkgver=3.2.1\npkgrel=2\n",
        )
        .unwrap();

        let (pkg, ver) = acquire_package_source(local_pkgbuild.to_str().unwrap(), &paths).unwrap();
        assert_eq!(pkg, "local-tool");
        assert_eq!(ver, "3.2.1-2");
    }

    #[test]
    fn test_detect_container_engine_auto() {
        let res = detect_container_engine(EnginePreference::Auto);
        // On our Nix/Linux test system, podman is installed!
        assert!(res.is_ok(), "Expected container engine to be detected");
        let info = res.unwrap();
        assert!(
            info.engine_type == ContainerEngineType::Podman
                || info.engine_type == ContainerEngineType::Docker
        );
    }
}
