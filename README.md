# aur-sentry

Automated supply-chain malware watchdog and threat radar for the Arch User Repository (AUR). Written in Rust, running on 100% autopilot via GitHub Actions.

[![CI](https://github.com/rebizzz/aur-sentry/actions/workflows/ci.yml/badge.svg)](https://github.com/rebizzz/aur-sentry/actions/workflows/ci.yml)
[![Autopilot](https://github.com/rebizzz/aur-sentry/actions/workflows/autopilot.yml/badge.svg)](https://github.com/rebizzz/aur-sentry/actions/workflows/autopilot.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

---

## Live Threat Radar

The table below is generated automatically on schedule every 2 hours:

<!-- AUTOPILOT_TABLE_START -->
<details>
<summary>Active Threats (0)</summary>

*No active threats recorded in the radar.*
</details>
<!-- AUTOPILOT_TABLE_END -->

- Full JSON Feed: [`advisories.json`](advisories.json)
- RSS Feed: [`advisories.xml`](advisories.xml)

---

## Quickstart

### Build from source

```bash
cargo build --release
```

Or enter the dev shell:

```bash
nix develop
```

### Scan a package

```bash
# Scan a remote AUR package before installing
./target/release/aur-sentry scan-pkg <package-name>

# Scan a local PKGBUILD or .install script
./target/release/aur-sentry scan-file ./PKGBUILD
```

---

## paru / yay Hook

You can intercept builds automatically before `makepkg` runs.

Add to `~/.config/paru/paru.conf`:

```ini
[options]
PreBuildCommand = /usr/local/bin/safeaur check
```

`safeaur` checks the online threat radar cache and scans the live PKGBUILD. If an active threat is flagged, the build aborts before running build scripts on your system.

---

## What It Detects

The static analysis engine checks 40+ signatures across PKGBUILD and `.install` files:

- **[CRITICAL] Obfuscation**: `base64 -d`, `xxd -r`, octal/hex `printf`, `eval`, reversed strings (`rev | bash`).
- **[CRITICAL] Exfiltration**: Discord webhooks, Telegram bot C2, raw IP targets, DNS tunneling, netcat connections.
- **[CRITICAL] Reverse Shells**: Bash `/dev/tcp`, `mkfifo`, python socket one-liners.
- **[CRITICAL] Credential Theft**: Access to `~/.ssh`, `~/.gnupg`, browser profiles (`logins.json`, cookies), crypto wallets, cloud keys (`~/.aws`, `~/.kube`), `/etc/shadow`.
- **[CRITICAL] Persistence**: Modifying `/etc/systemd/system/`, crontabs, injecting `~/.bashrc` / `/etc/profile`, XDG autostart.
- **[HIGH] Packaging Abuse**: Unpinned `npm install` / `bun install` (dependency confusion), privileged `.install` hooks, `replaces=()` hijacking.
- **[HIGH] System Tampering**: SUID bits (`chmod +s`), `dd` writes to block devices, disabling firewalls/security daemons.
- **[CRITICAL] Cryptojacking**: XMRig, mining pool addresses, hardcoded wallet addresses.
- **[MEDIUM] Typosquatting**: Damerau-Levenshtein distance <= 1 against top AUR packages.

---

## Autopilot Mode

Runs via GitHub Actions every 2 hours:
1. Downloads the full AUR metadata dump (`packages-meta-ext-v1.json.gz`).
2. Filters packages modified in the recent window.
3. Rips through their `PKGBUILD` and `.install` files with the Rust engine.
4. Updates `advisories.json`, `advisories.xml`, and the README table above.
5. Commits and pushes with `[skip ci]`.

---

## License

[MIT](LICENSE) (c) rebizzz
