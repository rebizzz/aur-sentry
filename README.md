# aur-sentry

Automated supply-chain malware watchdog and threat radar for the Arch User Repository (AUR). Written in Rust, running on 100% autopilot via GitHub Actions.

[![CI](https://github.com/rebizzz/aur-sentry/actions/workflows/ci.yml/badge.svg)](https://github.com/rebizzz/aur-sentry/actions/workflows/ci.yml)
[![Autopilot](https://github.com/rebizzz/aur-sentry/actions/workflows/autopilot.yml/badge.svg)](https://github.com/rebizzz/aur-sentry/actions/workflows/autopilot.yml)
[![Security Audit](https://github.com/rebizzz/aur-sentry/actions/workflows/security-audit.yml/badge.svg)](https://github.com/rebizzz/aur-sentry/actions/workflows/security-audit.yml)
[![CodeQL](https://github.com/rebizzz/aur-sentry/actions/workflows/codeql.yml/badge.svg)](https://github.com/rebizzz/aur-sentry/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

---

## Live Threat Radar

The table below is generated automatically on schedule every 2 hours:

<!-- AUTOPILOT_TABLE_START -->
<details open>
<summary>Active Threats (1)</summary>

| Severity | Package | Version | Maintainer | Triggers | Link |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `[HIGH]` | `paseo-desktop-git-bin` | 0.9.1.r50.gbbf8cce3f-2 | xpufx | `OBFUSCATED_DOLLAR_EXEC` | [AUR](https://aur.archlinux.org/packages/paseo-desktop-git-bin) |
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
- `[HIGH]` **Shannon Information Entropy**: Mathematical entropy analysis (H > 5.2 bits/byte) to catch packed, encrypted, or obfuscated payloads.
- `[CRITICAL]` **Recursive De-Obfuscator**: Extracts and decodes base64 strings in-memory, recursively scanning the unpacked payload for hidden C2 hooks.
- `[HIGH]` **Archive & ELF Inspection**: Streams in-memory tarball sources to detect UPX-packed binaries (`UPX!`), hidden scripts in asset dirs, and miner payloads.
- `[MEDIUM]` **Typosquatting**: Damerau-Levenshtein distance <= 1 against top AUR packages.

---

## Autopilot Mode

Runs via GitHub Actions every 2 hours:
1. Downloads the full AUR metadata dump (`packages-meta-ext-v1.json.gz`, ~120k packages).
2. Filters packages modified in the recent window.
3. Rips through `PKGBUILD` and `.install` files with the deep Rust analyzer suite.
4. Files automated GitHub Issue alerts for any `[CRITICAL]` threats.
5. Updates `advisories.json`, `advisories.xml`, and the README table above.
6. Commits and pushes with `[skip ci]`.

---

## License

[MIT](LICENSE) (c) rebizzz
