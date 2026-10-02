<div align="center">

# 🛡️ AUR Sentry

**Automated supply-chain malware watchdog & live threat radar for Arch Linux.**

[![CI](https://github.com/rebizzz/aur-sentry/actions/workflows/ci.yml/badge.svg)](https://github.com/rebizzz/aur-sentry/actions/workflows/ci.yml)
[![Autopilot](https://github.com/rebizzz/aur-sentry/actions/workflows/autopilot.yml/badge.svg)](https://github.com/rebizzz/aur-sentry/actions/workflows/autopilot.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Registry](https://img.shields.io/badge/registry-live-success.svg)](https://rebizzz.github.io/aur-sentry/)

*Every package inspected. Every verdict backed by cryptographic evidence.*

---

</div>

## ⚡ What is AUR Sentry?

**AUR Sentry** continuously scans and audits packages submitted to the **Arch User Repository (AUR)** to detect supply-chain attacks, backdoor scripts, obfuscated payloads, and malicious installers before they reach your system.

- 🔍 **Static & AST Analysis:** Detects 40+ attack patterns (reverse shells, credential theft, systemd tampering, and crypto miners).
- 🧠 **Shannon Entropy & De-Obfuscation:** Calculates token randomness ($H > 5.2$) and recursively unpacks base64/hex payloads in memory.
- 🪤 **Disposable Container Sandbox:** Executes untrusted builds in isolated rootless containers with planted canary honeypots.
- 🪝 **AUR Helper Hooks (`paru` / `yay`):** Automatically intercepts `makepkg` builds and halts malicious packages.
- 📡 **Live Threat Radar:** Continuous feeds updated every 2 hours via automated CI.

---

## 🚀 Quickstart

### 1. Build & Run
```bash
# Clone and build
git clone https://github.com/rebizzz/aur-sentry.git
cd aur-sentry
cargo build --release

# Or enter the reproducible Nix development environment
nix develop
```

### 2. Scan a Package
```bash
# Scan a remote AUR package before installing
./target/release/aur-sentry scan-pkg <package-name>

# Scan a local PKGBUILD or .install script
./target/release/aur-sentry scan-file ./PKGBUILD

# View live threat advisories right in your terminal
./target/release/aur-sentry radar
```

### 3. Protect `paru` / `yay` Automatically
Add a pre-build hook to your `~/.config/paru/paru.conf`:
```ini
[options]
PreBuildCommand = /usr/local/bin/safeaur check
```
*See [AUR Helper Guide](docs/guides/HOOKS.md) for full setup and strict mode.*

---

## 📡 Live Threat Radar & Feeds

- 📋 **Human-Readable Threat Radar:** [`generated/ADVISORIES.md`](generated/ADVISORIES.md)
- ⚙️ **Machine-Readable JSON Feed:** [`generated/advisories.json`](generated/advisories.json)
- 📰 **RSS / Atom Feed:** [`generated/advisories.xml`](generated/advisories.xml)
- 🌐 **Web Registry Dashboard:** [rebizzz.github.io/aur-sentry](https://rebizzz.github.io/aur-sentry/)

---

## 📚 Documentation & Guides

Explore human-friendly guides in the [`docs/`](docs/) directory:

- 🛡️ **[Detection Signatures & Rules](docs/guides/DETECTION_RULES.md)** — Attack vectors, obfuscation detection, and entropy rules.
- 🪝 **[Helper Hooks & safeaur](docs/guides/HOOKS.md)** — Setting up `safeaur` with `paru`, `yay`, and custom shell aliases.
- 📦 **[Container Sandbox & Honeypots](docs/guides/SANDBOX.md)** — Rootless container auditing and canary secret traps.
- 🏛️ **[System Architecture](ARCHITECTURE.md)** — The 100% free-tier zero-cloud serverless pipeline.

---

## 🤝 Contributing & Community

Contributions are warmly welcome! Please check our community documents:

- **[Contributing Guide](CONTRIBUTING.md)**: Setup, code style, testing, and proposing new detection rules.
- **[Code of Conduct](CODE_OF_CONDUCT.md)**: Community standards and expectations.
- **[Security Policy](.github/SECURITY.md)**: Responsible vulnerability disclosure.

---

## 📄 License

Licensed under the [MIT License](LICENSE) &copy; 2026 rebizzz.
