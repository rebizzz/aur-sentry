# 🛡️ AUR-Sentry

> **Automated supply-chain security watchdog & threat radar for the Arch User Repository (AUR).**  
> Running on 100% Autopilot via GitHub Actions.

[![CI](https://github.com/rebizzz/aur-sentry/actions/workflows/ci.yml/badge.svg)](https://github.com/rebizzz/aur-sentry/actions/workflows/ci.yml)
[![Autopilot Threat Radar](https://github.com/rebizzz/aur-sentry/actions/workflows/autopilot.yml/badge.svg)](https://github.com/rebizzz/aur-sentry/actions/workflows/autopilot.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![RSS Feed](https://img.shields.io/badge/RSS-Advisories_Feed-orange?logo=rss)](https://raw.githubusercontent.com/rebizzz/aur-sentry/main/advisories.xml)

---

## 🚨 Motivation: The AUR Supply-Chain Crisis

In recent months, the Arch User Repository (AUR) experienced several coordinated malware campaigns where hundreds of packages were compromised with malicious payloads—including obfuscated curl-pipe-to-bash scripts, Discord webhook token-stealers, and unauthorized crypto miners. Because Arch Linux packaging maintainers cannot realistically audit every change across 90,000+ packages, users running `yay` or `paru` are vulnerable to unvetted upstream updates.

**AUR-Sentry** solves this by operating as a continuous, set-and-forget **security radar** on 100% autopilot:
1. Regularly monitors newly pushed packages and commits on the AUR.
2. Runs static analysis heuristics over `PKGBUILD` and `.install` scripts.
3. Automatically publishes machine-readable threat advisories (`advisories.json`), an RSS alert stream (`advisories.xml`), and updates this radar board.
4. Provides a client-side hook (`safeaur`) that intercepts installs before your machine runs malicious build instructions.

---

## 📡 Live Threat Radar

The table below is updated automatically on schedule by GitHub Actions:

<!-- AUTOPILOT_TABLE_START -->

| Severity | Package | Version | Maintainer | Triggers | Link |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 🟡 **MEDIUM** | `9pro-git` | r111.2c1651b-1 | renehsz | `RULE_SKIP_HASH_REMOTE` | [AUR](https://aur.archlinux.org/packages/9pro-git) |
| 🟡 **MEDIUM** | `actflow-git` | r803.cbdbee0-1 | Richardn | `RULE_SKIP_HASH_REMOTE` | [AUR](https://aur.archlinux.org/packages/actflow-git) |
| 🟡 **MEDIUM** | `admixtools-git` | r61.b10ddcf-1 | techs | `RULE_SKIP_HASH_REMOTE` | [AUR](https://aur.archlinux.org/packages/admixtools-git) |
| 🟡 **MEDIUM** | `aerotools-git` | r77.7109ba7-1 | orphan | `RULE_SKIP_HASH_REMOTE` | [AUR](https://aur.archlinux.org/packages/aerotools-git) |
| 🟡 **MEDIUM** | `akonadi-calendar-tools-git` | 6.0.40_r1177.gbe4e54f-1 | IslandC0der | `RULE_SKIP_HASH_REMOTE` | [AUR](https://aur.archlinux.org/packages/akonadi-calendar-tools-git) |
| 🟡 **MEDIUM** | `amctl` | 1.0.1-1 | Hengtime787 | `RULE_SKIP_HASH_REMOTE` | [AUR](https://aur.archlinux.org/packages/amctl) |
| 🟡 **MEDIUM** | `amethyst-tools-git` | r316.83ef9c6-1 | capnhawkbill | `RULE_SKIP_HASH_REMOTE` | [AUR](https://aur.archlinux.org/packages/amethyst-tools-git) |
| 🟡 **MEDIUM** | `amneziawg-tools-git` | r517.5d6179a-2 | h8ray | `RULE_SKIP_HASH_REMOTE` | [AUR](https://aur.archlinux.org/packages/amneziawg-tools-git) |
| 🟡 **MEDIUM** | `amqp-qtools-git` | 0.5.0.6f42dfd-2 | languitar | `RULE_SKIP_HASH_REMOTE` | [AUR](https://aur.archlinux.org/packages/amqp-qtools-git) |
| 🟡 **MEDIUM** | `amtterm-git` | 1.7.r25.gfc5ee7a-1 | d10n | `RULE_SKIP_HASH_REMOTE` | [AUR](https://aur.archlinux.org/packages/amtterm-git) |
<!-- AUTOPILOT_TABLE_END -->

- 📄 Full machine-readable feed: [`advisories.json`](advisories.json)
- 🔔 RSS feed for webhooks / readers: [`advisories.xml`](advisories.xml)

---

## ⚡ Quickstart

### 1. Zero-Dependency Client (`safeaur`)

You can run `safeaur` directly without installing dependencies:

```bash
# Check if a package has an active security advisory or scan its live PKGBUILD
./bin/safeaur check <package-name>

# Scan a local PKGBUILD before building
./bin/safeaur scan ./PKGBUILD
```

### 2. Integration with `paru` / `yay`

You can integrate `safeaur` as a pre-build check. In `~/.config/paru/paru.conf`:

```ini
[options]
PreBuildCommand = /usr/local/bin/safeaur check
```

---

## 🔍 Heuristic Detection Matrix

AUR-Sentry inspects build scripts against high-confidence patterns observed in real-world attacks:

| Rule ID | Severity | Description |
| :--- | :--- | :--- |
| `RULE_OBFUSCATED_BASE64` | 🔴 **CRITICAL** | Base64 strings piped directly to `bash`, `sh`, or `python`. |
| `RULE_HEX_EXEC` | 🔴 **CRITICAL** | Hex-decoded payloads piped to shell execution (`xxd -r \| sh`). |
| `RULE_DISCORD_WEBHOOK` | 🔴 **CRITICAL** | Hardcoded Discord webhook URLs used for credential/token exfiltration. |
| `RULE_TELEGRAM_BOT_EXFIL` | 🔴 **CRITICAL** | C2 or credential drop endpoints using Telegram bot API. |
| `RULE_REVERSE_SHELL` | 🔴 **CRITICAL** | Classic reverse shell patterns (`/dev/tcp/...`, `nc -e`, `mkfifo`). |
| `RULE_RAW_IP_DOWNLOAD` | 🟠 **HIGH** | Unverified payloads fetched from raw IP addresses rather than domains. |
| `RULE_CURL_PIPE_EXEC` | 🟠 **HIGH** | Arbitrary remote scripts piped to shell (`curl ... \| bash`). |
| `RULE_PASTEBIN_DOWNLOAD` | 🟠 **HIGH** | Unpinned dynamic downloads from pastebin, hastebin, or transfer.sh. |
| `RULE_SENSITIVE_FS_ACCESS` | 🟠 **HIGH** | Tampering with `~/.ssh`, `/etc/shadow`, `/etc/sudoers`, or `/boot`. |
| `RULE_ROOT_PERSISTENCE` | 🟠 **HIGH** | Writes to `/etc/cron.*` or `/etc/systemd/system/` outside `$pkgdir`. |
| `RULE_TYPOSQUATTING` | 🟡 **MEDIUM** | Damerau-Levenshtein distance $\le 1$ against top 150 popular packages. |
| `RULE_SKIP_HASH_REMOTE` | 🟡 **MEDIUM** | Bypassing source integrity checks (`sha256sums=('SKIP')`). |

---

## 🛠️ Local Development & Testing

Run unit tests directly:

```bash
# Using Python standard library
python3 -m unittest discover -s tests -v

# Run the autopilot scanner locally
python3 -m src.main autopilot --limit 20
```

---

## 📜 License

[MIT](LICENSE) © [rebizzz](https://github.com/rebizzz)
