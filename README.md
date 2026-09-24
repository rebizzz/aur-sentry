# aur-sentry

Automated supply-chain malware watchdog and threat radar for the Arch User Repository (AUR). Written in Rust, running on 100% autopilot via GitHub Actions.

[![CI](https://github.com/rebizzz/aur-sentry/actions/workflows/ci.yml/badge.svg)](https://github.com/rebizzz/aur-sentry/actions/workflows/ci.yml)
[![Autopilot](https://github.com/rebizzz/aur-sentry/actions/workflows/autopilot.yml/badge.svg)](https://github.com/rebizzz/aur-sentry/actions/workflows/autopilot.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

---

## Live Threat Radar

The table below is generated automatically on schedule every 2 hours:

<!-- AUTOPILOT_TABLE_START -->
<details open>
<summary>Active Threats (16)</summary>

| Severity | Package | Version | Maintainer | Triggers | Link |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `[CRITICAL]` | `linuxqq-nt` | 6:3.2.34_53644-1 | logan_reed | `PKG_PROVIDES_COMMON`, `SUS_CHMOD_SUID`, `PKG_INSTALL_HOOK` | [AUR](https://aur.archlinux.org/packages/linuxqq-nt) |
| `[HIGH]` | `voltius-git` | 0.41.0.r0.g026603b-1 | ezhkov | `PKG_SKIP_HASH`, `PKG_NPM_INSTALL` | [AUR](https://aur.archlinux.org/packages/voltius-git) |
| `[HIGH]` | `signageos-cli` | 4.4.0-1 | prochac | `PKG_NPM_INSTALL` | [AUR](https://aur.archlinux.org/packages/signageos-cli) |
| `[HIGH]` | `repo-notes-git` | 20260922.1.r14.g095e3b9-1 | timmo001 | `PKG_SKIP_HASH`, `PKG_NPM_INSTALL`, `PKG_INSTALL_HOOK` | [AUR](https://aur.archlinux.org/packages/repo-notes-git) |
| `[HIGH]` | `factory-ai-droid-cli-rnoz-bin` | 0.226.2-1 | rNoz | `OBFUSCATED_DOLLAR_EXEC`, `PKG_INSTALL_HOOK`, `PKG_INSTALL_HOOK` | [AUR](https://aur.archlinux.org/packages/factory-ai-droid-cli-rnoz-bin) |
| `[HIGH]` | `zenith-gamestream` | 2026.730.002631-2 | y0no | `PKG_SKIP_HASH`, `PKG_INSTALL_HOOK`, `PKG_INSTALL_HOOK` | [AUR](https://aur.archlinux.org/packages/zenith-gamestream) |
| `[HIGH]` | `piclone-git` | r160.8b9c6c6-1 | linux-aarhus | `PKG_SKIP_HASH`, `PKG_INSTALL_HOOK` | [AUR](https://aur.archlinux.org/packages/piclone-git) |
| `[MEDIUM]` | `baresip-qt-gui-git` | 4.10.1-2 | CxOrg | `PKG_PROVIDES_COMMON`, `PKG_SKIP_HASH` | [AUR](https://aur.archlinux.org/packages/baresip-qt-gui-git) |
| `[MEDIUM]` | `spotifast-bin` | 0.10.0-1 | crmne | `PKG_REPLACE_DECL` | [AUR](https://aur.archlinux.org/packages/spotifast-bin) |
| `[MEDIUM]` | `mp3rgui` | 3.9.0-1 | m-igashi | `PKG_SKIP_HASH` | [AUR](https://aur.archlinux.org/packages/mp3rgui) |
| `[MEDIUM]` | `spotifast` | 0.10.0-1 | crmne | `PKG_REPLACE_DECL` | [AUR](https://aur.archlinux.org/packages/spotifast) |
| `[MEDIUM]` | `spotifast-git` | 0.10.0-1 | crmne | `PKG_REPLACE_DECL`, `PKG_SKIP_HASH` | [AUR](https://aur.archlinux.org/packages/spotifast-git) |
| `[MEDIUM]` | `snx-rs` | 6.4.1-1 | zdenek-biberle | `PKG_REPLACE_DECL` | [AUR](https://aur.archlinux.org/packages/snx-rs) |
| `[MEDIUM]` | `zen-twilight-bin` | 1.23t.2026.09.23-1 | Larvey | `PKG_SKIP_HASH`, `PKG_SKIP_HASH` | [AUR](https://aur.archlinux.org/packages/zen-twilight-bin) |
| `[MEDIUM]` | `freecad-weekly` | 26.3.0dev.09.23-1 | mar | `PKG_SKIP_HASH` | [AUR](https://aur.archlinux.org/packages/freecad-weekly) |
| `[MEDIUM]` | `flectar-mail-git` | 0.1.0alpha.5.r7.g9f062a8-2 | liveopt | `PKG_SKIP_HASH` | [AUR](https://aur.archlinux.org/packages/flectar-mail-git) |
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

- `[CRITICAL]` **Obfuscation**: `base64 -d`, `xxd -r`, octal/hex `printf`, `eval`, reversed strings (`rev | bash`).
- `[CRITICAL]` **Exfiltration**: Discord webhooks, Telegram bot C2, raw IP targets, DNS tunneling, netcat connections.
- `[CRITICAL]` **Reverse Shells**: Bash `/dev/tcp`, `mkfifo`, python socket one-liners.
- `[CRITICAL]` **Credential Theft**: Access to `~/.ssh`, `~/.gnupg`, browser profiles (`logins.json`, cookies), crypto wallets, cloud keys (`~/.aws`, `~/.kube`), `/etc/shadow`.
- `[CRITICAL]` **Persistence**: Modifying `/etc/systemd/system/`, crontabs, injecting `~/.bashrc` / `/etc/profile`, XDG autostart.
- `[HIGH]` **Packaging Abuse**: Unpinned `npm install` / `bun install` (dependency confusion), privileged `.install` hooks, `replaces=()` hijacking.
- `[HIGH]` **System Tampering**: SUID bits (`chmod +s`), `dd` writes to block devices, disabling firewalls/security daemons.
- `[CRITICAL]` **Cryptojacking**: XMRig, mining pool addresses, hardcoded wallet addresses.
- `[MEDIUM]` **Typosquatting**: Damerau-Levenshtein distance <= 1 against top AUR packages.

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
