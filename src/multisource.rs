//! Multi-source package intelligence client: Arch official repositories, AUR RPC, and embedded fallback.

use crate::aur_client::AURClient;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PackageOrigin {
    OfficialCore,
    OfficialExtra,
    OfficialMultilib,
    Aur,
    VirtualSoname,
    VirtualProvides,
    Unresolved,
}

impl PackageOrigin {
    pub fn is_official(&self) -> bool {
        matches!(
            self,
            Self::OfficialCore | Self::OfficialExtra | Self::OfficialMultilib
        )
    }

    pub fn is_aur(&self) -> bool {
        matches!(self, Self::Aur)
    }

    pub fn repo_name(&self) -> &'static str {
        match self {
            Self::OfficialCore => "core",
            Self::OfficialExtra => "extra",
            Self::OfficialMultilib => "multilib",
            Self::Aur => "aur",
            Self::VirtualSoname => "soname",
            Self::VirtualProvides => "virtual",
            Self::Unresolved => "unresolved",
        }
    }
}

/// Static embedded catalog of standard Arch Linux packages across core, extra, and multilib.
/// Guarantees zero network calls during hermetic testing, Nix builds, and offline audits.
pub const EMBEDDED_OFFICIAL_PKGS: &[(&str, PackageOrigin)] = &[
    ("glibc", PackageOrigin::OfficialCore),
    ("linux", PackageOrigin::OfficialCore),
    ("linux-headers", PackageOrigin::OfficialCore),
    ("systemd", PackageOrigin::OfficialCore),
    ("systemd-libs", PackageOrigin::OfficialCore),
    ("systemd-sysvcompat", PackageOrigin::OfficialCore),
    ("openssl", PackageOrigin::OfficialCore),
    ("curl", PackageOrigin::OfficialCore),
    ("bash", PackageOrigin::OfficialExtra),
    ("coreutils", PackageOrigin::OfficialCore),
    ("gcc-libs", PackageOrigin::OfficialCore),
    ("gcc", PackageOrigin::OfficialExtra),
    ("binutils", PackageOrigin::OfficialCore),
    ("pacman", PackageOrigin::OfficialCore),
    ("archlinux-keyring", PackageOrigin::OfficialCore),
    ("tar", PackageOrigin::OfficialCore),
    ("sed", PackageOrigin::OfficialCore),
    ("gawk", PackageOrigin::OfficialCore),
    ("grep", PackageOrigin::OfficialCore),
    ("which", PackageOrigin::OfficialCore),
    ("zstd", PackageOrigin::OfficialCore),
    ("xz", PackageOrigin::OfficialCore),
    ("bzip2", PackageOrigin::OfficialCore),
    ("zlib", PackageOrigin::OfficialCore),
    ("sqlite", PackageOrigin::OfficialCore),
    ("ca-certificates", PackageOrigin::OfficialCore),
    ("shadow", PackageOrigin::OfficialCore),
    ("sudo", PackageOrigin::OfficialCore),
    ("dbus", PackageOrigin::OfficialCore),
    ("libseccomp", PackageOrigin::OfficialCore),
    ("libcap", PackageOrigin::OfficialCore),
    ("util-linux", PackageOrigin::OfficialCore),
    ("filesystem", PackageOrigin::OfficialCore),
    ("iana-etc", PackageOrigin::OfficialCore),
    ("iproute2", PackageOrigin::OfficialCore),
    ("iputils", PackageOrigin::OfficialCore),
    ("krb5", PackageOrigin::OfficialCore),
    ("less", PackageOrigin::OfficialCore),
    ("licenses", PackageOrigin::OfficialCore),
    ("logrotate", PackageOrigin::OfficialCore),
    ("man-db", PackageOrigin::OfficialCore),
    ("man-pages", PackageOrigin::OfficialCore),
    ("mdadm", PackageOrigin::OfficialCore),
    ("nano", PackageOrigin::OfficialCore),
    ("pambase", PackageOrigin::OfficialCore),
    ("pciutils", PackageOrigin::OfficialCore),
    ("procps-ng", PackageOrigin::OfficialCore),
    ("psmisc", PackageOrigin::OfficialCore),
    ("sysfsutils", PackageOrigin::OfficialCore),
    ("usbutils", PackageOrigin::OfficialCore),
    ("vi", PackageOrigin::OfficialCore),
    ("xfsprogs", PackageOrigin::OfficialCore),
    ("findutils", PackageOrigin::OfficialCore),
    ("diffutils", PackageOrigin::OfficialCore),
    ("file", PackageOrigin::OfficialCore),
    ("gzip", PackageOrigin::OfficialCore),
    ("readline", PackageOrigin::OfficialCore),
    ("ncurses", PackageOrigin::OfficialCore),
    ("libarchive", PackageOrigin::OfficialCore),
    ("libelf", PackageOrigin::OfficialCore),
    ("libevent", PackageOrigin::OfficialCore),
    ("libffi", PackageOrigin::OfficialCore),
    ("libxml2", PackageOrigin::OfficialCore),
    ("libnghttp2", PackageOrigin::OfficialCore),
    ("libpsl", PackageOrigin::OfficialCore),
    ("libssh2", PackageOrigin::OfficialCore),
    ("libtirpc", PackageOrigin::OfficialCore),
    ("libtool", PackageOrigin::OfficialCore),
    ("libusb", PackageOrigin::OfficialCore),
    // Extra
    ("python", PackageOrigin::OfficialExtra),
    ("python-setuptools", PackageOrigin::OfficialExtra),
    ("python-pip", PackageOrigin::OfficialExtra),
    ("python-pytest", PackageOrigin::OfficialExtra),
    ("python-wheel", PackageOrigin::OfficialExtra),
    ("python-build", PackageOrigin::OfficialExtra),
    ("python-installer", PackageOrigin::OfficialExtra),
    ("python-requests", PackageOrigin::OfficialExtra),
    ("python-urllib3", PackageOrigin::OfficialExtra),
    ("python-cryptography", PackageOrigin::OfficialExtra),
    ("git", PackageOrigin::OfficialExtra),
    ("cmake", PackageOrigin::OfficialExtra),
    ("ninja", PackageOrigin::OfficialExtra),
    ("meson", PackageOrigin::OfficialExtra),
    ("gtk3", PackageOrigin::OfficialExtra),
    ("gtk4", PackageOrigin::OfficialExtra),
    ("glib2", PackageOrigin::OfficialExtra),
    ("glib2-devel", PackageOrigin::OfficialExtra),
    ("alsa-lib", PackageOrigin::OfficialExtra),
    ("nss", PackageOrigin::OfficialExtra),
    ("nspr", PackageOrigin::OfficialExtra),
    ("libx11", PackageOrigin::OfficialExtra),
    ("libxss", PackageOrigin::OfficialExtra),
    ("libxext", PackageOrigin::OfficialExtra),
    ("libxrender", PackageOrigin::OfficialExtra),
    ("libxrandr", PackageOrigin::OfficialExtra),
    ("libxtst", PackageOrigin::OfficialExtra),
    ("libpulse", PackageOrigin::OfficialExtra),
    ("pipewire", PackageOrigin::OfficialExtra),
    ("pipewire-audio", PackageOrigin::OfficialExtra),
    ("mesa", PackageOrigin::OfficialExtra),
    ("vulkan-icd-loader", PackageOrigin::OfficialExtra),
    ("wayland", PackageOrigin::OfficialExtra),
    ("xorg-server", PackageOrigin::OfficialExtra),
    ("ffmpeg", PackageOrigin::OfficialExtra),
    ("libuv", PackageOrigin::OfficialExtra),
    ("rust", PackageOrigin::OfficialExtra),
    ("cargo", PackageOrigin::OfficialExtra),
    ("go", PackageOrigin::OfficialExtra),
    ("nodejs", PackageOrigin::OfficialExtra),
    ("npm", PackageOrigin::OfficialExtra),
    ("clang", PackageOrigin::OfficialExtra),
    ("llvm", PackageOrigin::OfficialExtra),
    ("ruby", PackageOrigin::OfficialExtra),
    ("perl", PackageOrigin::OfficialExtra),
    ("php", PackageOrigin::OfficialExtra),
    ("jdk-openjdk", PackageOrigin::OfficialExtra),
    ("jre-openjdk", PackageOrigin::OfficialExtra),
    ("boost", PackageOrigin::OfficialExtra),
    ("boost-libs", PackageOrigin::OfficialExtra),
    ("qt5-base", PackageOrigin::OfficialExtra),
    ("qt6-base", PackageOrigin::OfficialExtra),
    ("vlc", PackageOrigin::OfficialExtra),
    ("mpv", PackageOrigin::OfficialExtra),
    ("neovim", PackageOrigin::OfficialExtra),
    ("tmux", PackageOrigin::OfficialExtra),
    ("zsh", PackageOrigin::OfficialExtra),
    ("fish", PackageOrigin::OfficialExtra),
    ("htop", PackageOrigin::OfficialExtra),
    ("ripgrep", PackageOrigin::OfficialExtra),
    ("fd", PackageOrigin::OfficialExtra),
    ("bat", PackageOrigin::OfficialExtra),
    ("eza", PackageOrigin::OfficialExtra),
    ("jq", PackageOrigin::OfficialExtra),
    ("unzip", PackageOrigin::OfficialExtra),
    ("zip", PackageOrigin::OfficialExtra),
    ("p7zip", PackageOrigin::OfficialExtra),
    ("wget", PackageOrigin::OfficialExtra),
    ("cups", PackageOrigin::OfficialExtra),
    ("gnupg", PackageOrigin::OfficialExtra),
    ("openssh", PackageOrigin::OfficialExtra),
    ("strace", PackageOrigin::OfficialExtra),
    // Multilib
    ("lib32-glibc", PackageOrigin::OfficialMultilib),
    ("lib32-gcc-libs", PackageOrigin::OfficialMultilib),
    ("lib32-mesa", PackageOrigin::OfficialMultilib),
    ("lib32-alsa-lib", PackageOrigin::OfficialMultilib),
    ("lib32-systemd", PackageOrigin::OfficialMultilib),
    ("lib32-openssl", PackageOrigin::OfficialMultilib),
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageIntelligence {
    pub name: String,
    pub origin: PackageOrigin,
    pub version: Option<String>,
    pub maintainer: Option<String>,
    pub num_votes: Option<u32>,
    pub popularity: Option<f64>,
    pub out_of_date: bool,
    pub upstream_url: Option<String>,
    pub description: Option<String>,
    pub depends: Vec<String>,
    pub make_depends: Vec<String>,
    pub opt_depends: Vec<String>,
}

#[derive(Clone)]
pub struct MultiSourceClient {
    aur_client: Arc<AURClient>,
    cache: Arc<RwLock<HashMap<String, PackageIntelligence>>>,
    embedded_map: HashMap<String, PackageOrigin>,
    offline: bool,
    agent: ureq::Agent,
}

impl MultiSourceClient {
    pub fn new(offline: bool) -> Self {
        let mut embedded_map = HashMap::new();
        for &(pkg, origin) in EMBEDDED_OFFICIAL_PKGS {
            embedded_map.insert(pkg.to_string(), origin);
        }

        let config = ureq::config::Config::builder()
            .timeout_global(Some(std::time::Duration::from_secs(5)))
            .build();
        let agent = ureq::Agent::new_with_config(config);

        Self {
            aur_client: Arc::new(AURClient::new()),
            cache: Arc::new(RwLock::new(HashMap::new())),
            embedded_map,
            offline,
            agent,
        }
    }

    /// Check whether a package is recognized as an official package.
    pub fn is_official_package(&self, name: &str) -> bool {
        self.resolve_package(name).origin.is_official()
    }

    /// Resolve intelligence for a single package name.
    pub fn resolve_package(&self, name: &str) -> PackageIntelligence {
        let clean_name = name.trim();

        // 1. Check in-memory cache
        if let Ok(cache) = self.cache.read() {
            if let Some(cached) = cache.get(clean_name) {
                return cached.clone();
            }
        }

        // 2. Check virtual sonames (e.g., libalpm.so, libm.so.6)
        if clean_name.contains(".so") {
            let intel = PackageIntelligence {
                name: clean_name.to_string(),
                origin: PackageOrigin::VirtualSoname,
                version: None,
                maintainer: None,
                num_votes: None,
                popularity: None,
                out_of_date: false,
                upstream_url: None,
                description: Some("Shared object library soname dependency".to_string()),
                depends: Vec::new(),
                make_depends: Vec::new(),
                opt_depends: Vec::new(),
            };
            self.insert_cache(clean_name, intel.clone());
            return intel;
        }

        // 3. Virtual common system targets
        if matches!(clean_name, "sh" | "awk" | "java-runtime" | "java-environment") {
            let intel = PackageIntelligence {
                name: clean_name.to_string(),
                origin: PackageOrigin::VirtualProvides,
                version: None,
                maintainer: Some("Arch Linux System Provider".to_string()),
                num_votes: None,
                popularity: None,
                out_of_date: false,
                upstream_url: None,
                description: Some("Virtual package / system provider".to_string()),
                depends: Vec::new(),
                make_depends: Vec::new(),
                opt_depends: Vec::new(),
            };
            self.insert_cache(clean_name, intel.clone());
            return intel;
        }

        // 4. Check embedded official package catalog
        if let Some(&origin) = self.embedded_map.get(clean_name) {
            let intel = PackageIntelligence {
                name: clean_name.to_string(),
                origin,
                version: None,
                maintainer: Some("Arch Linux Developers".to_string()),
                num_votes: None,
                popularity: None,
                out_of_date: false,
                upstream_url: Some(format!("https://archlinux.org/packages/{}/{clean_name}/", origin.repo_name())),
                description: Some("Official Arch Linux package".to_string()),
                depends: Vec::new(),
                make_depends: Vec::new(),
                opt_depends: Vec::new(),
            };
            self.insert_cache(clean_name, intel.clone());
            return intel;
        }

        // 5. If running in offline mode, fallback to Unresolved
        if self.offline {
            let intel = PackageIntelligence {
                name: clean_name.to_string(),
                origin: PackageOrigin::Unresolved,
                version: None,
                maintainer: None,
                num_votes: None,
                popularity: None,
                out_of_date: false,
                upstream_url: None,
                description: None,
                depends: Vec::new(),
                make_depends: Vec::new(),
                opt_depends: Vec::new(),
            };
            self.insert_cache(clean_name, intel.clone());
            return intel;
        }

        // 6. Live query: Official Arch Linux Packages JSON Search API
        if let Some(intel) = self.query_arch_api(clean_name) {
            self.insert_cache(clean_name, intel.clone());
            return intel;
        }

        // 7. Live query: AUR RPC v5
        if let Some(pkg) = self.aur_client.get_package_info(clean_name) {
            let intel = PackageIntelligence {
                name: pkg.name,
                origin: PackageOrigin::Aur,
                version: Some(pkg.version),
                maintainer: pkg.maintainer,
                num_votes: pkg.num_votes,
                popularity: pkg.popularity,
                out_of_date: pkg.out_of_date.is_some(),
                upstream_url: Some(format!("https://aur.archlinux.org/packages/{clean_name}")),
                description: None,
                depends: Vec::new(),
                make_depends: Vec::new(),
                opt_depends: Vec::new(),
            };
            self.insert_cache(clean_name, intel.clone());
            return intel;
        }

        // 8. Package not found in official repos or AUR
        let intel = PackageIntelligence {
            name: clean_name.to_string(),
            origin: PackageOrigin::Unresolved,
            version: None,
            maintainer: None,
            num_votes: None,
            popularity: None,
            out_of_date: false,
            upstream_url: None,
            description: None,
            depends: Vec::new(),
            make_depends: Vec::new(),
            opt_depends: Vec::new(),
        };
        self.insert_cache(clean_name, intel.clone());
        intel
    }

    /// Batch resolve multiple package names.
    pub fn batch_resolve(&self, names: &[String]) -> HashMap<String, PackageIntelligence> {
        let mut results = HashMap::new();
        for name in names {
            results.insert(name.clone(), self.resolve_package(name));
        }
        results
    }

    fn insert_cache(&self, name: &str, intel: PackageIntelligence) {
        if let Ok(mut cache) = self.cache.write() {
            cache.insert(name.to_string(), intel);
        }
    }

    fn query_arch_api(&self, name: &str) -> Option<PackageIntelligence> {
        let url = format!("https://archlinux.org/packages/search/json/?name={name}");
        let mut resp = self.agent.get(&url).call().ok()?;
        let json_val: serde_json::Value = resp.body_mut().read_json().ok()?;

        let results = json_val.get("results")?.as_array()?;
        let first = results.first()?;
        let pkgname = first.get("pkgname")?.as_str()?;
        if pkgname != name {
            return None;
        }
        let repo = first
            .get("repo")
            .and_then(|r| r.as_str())
            .unwrap_or("extra")
            .to_lowercase();
        let version = first
            .get("pkgver")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let desc = first
            .get("pkgdesc")
            .and_then(|d| d.as_str())
            .map(|s| s.to_string());
        let upstream_url = first
            .get("url")
            .and_then(|u| u.as_str())
            .map(|s| s.to_string());

        let origin = match repo.as_str() {
            "core" => PackageOrigin::OfficialCore,
            "extra" => PackageOrigin::OfficialExtra,
            "multilib" => PackageOrigin::OfficialMultilib,
            _ => PackageOrigin::OfficialExtra,
        };

        Some(PackageIntelligence {
            name: name.to_string(),
            origin,
            version,
            maintainer: Some("Arch Linux Developers".to_string()),
            num_votes: None,
            popularity: None,
            out_of_date: false,
            upstream_url,
            description: desc,
            depends: Vec::new(),
            make_depends: Vec::new(),
            opt_depends: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_embedded_official_packages_resolved_offline() {
        let client = MultiSourceClient::new(true);

        let glibc = client.resolve_package("glibc");
        assert_eq!(glibc.origin, PackageOrigin::OfficialCore);
        assert!(glibc.origin.is_official());
        assert!(!glibc.origin.is_aur());
        assert_eq!(glibc.origin.repo_name(), "core");

        let python = client.resolve_package("python");
        assert_eq!(python.origin, PackageOrigin::OfficialExtra);
        assert!(python.origin.is_official());

        let lib32 = client.resolve_package("lib32-glibc");
        assert_eq!(lib32.origin, PackageOrigin::OfficialMultilib);
    }

    #[test]
    fn test_virtual_soname_resolution() {
        let client = MultiSourceClient::new(true);
        let so = client.resolve_package("libalpm.so");
        assert_eq!(so.origin, PackageOrigin::VirtualSoname);
        assert_eq!(so.origin.repo_name(), "soname");
    }

    #[test]
    fn test_virtual_provides_resolution() {
        let client = MultiSourceClient::new(true);
        let sh = client.resolve_package("sh");
        assert_eq!(sh.origin, PackageOrigin::VirtualProvides);
        assert_eq!(sh.origin.repo_name(), "virtual");
    }

    #[test]
    fn test_offline_unresolved_package() {
        let client = MultiSourceClient::new(true);
        let pkg = client.resolve_package("some-totally-nonexistent-package-xyz123");
        assert_eq!(pkg.origin, PackageOrigin::Unresolved);
        assert_eq!(pkg.origin.repo_name(), "unresolved");
        assert!(!pkg.origin.is_official());
        assert!(!pkg.origin.is_aur());
    }

    #[test]
    fn test_in_memory_cache_deduplication() {
        let client = MultiSourceClient::new(true);
        let p1 = client.resolve_package("git");
        let p2 = client.resolve_package("git");
        assert_eq!(p1.origin, p2.origin);
    }
}
