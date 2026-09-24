# 󰒃 aur-sentry

> **automated supply-chain malware watchdog & threat radar for the arch user repository.**  
> written in rust. runs on 100% autopilot. no maintainer toil.

[![CI](https://github.com/rebizzz/aur-sentry/actions/workflows/ci.yml/badge.svg)](https://github.com/rebizzz/aur-sentry/actions/workflows/ci.yml)
[![Autopilot Threat Radar](https://github.com/rebizzz/aur-sentry/actions/workflows/autopilot.yml/badge.svg)](https://github.com/rebizzz/aur-sentry/actions/workflows/autopilot.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![RSS Feed](https://img.shields.io/badge/rss-threat_feed-orange?logo=rss)](https://raw.githubusercontent.com/rebizzz/aur-sentry/main/advisories.xml)

---

## 󰚌 why this exists

the AUR has 90,000+ packages and practically zero gatekeeping. anyone can upload. anyone can adopt an orphaned package with 5,000 users.

in 2024–2026, coordinated automated campaigns hijacked over 1,500 AUR packages:
- **orphan takeovers**: bots auto-adopted abandoned packages with established userbases and injected second-stage downloaders.
- **dependency confusion**: `PKGBUILD`s running untracked `npm install` pulled malicious packages like `atomic-lockfile` and `js-digest` straight from public registries into build pipelines.
- **credential harvesting**: rust-based infostealers scraped `~/.ssh/id_*`, browser sessions (cookies, `logins.json`), cloud tokens (`~/.aws`, `~/.kube`), and crypto wallets, exfiltrating straight to discord webhooks and telegram bots.
- **`.install` hook persistence**: commands tucked into `post_install()` running as `root` via `pacman`, dropping systemd services and crontabs that survive updates.

AUR helpers like `paru` and `yay` give you a diff viewer, but realistically nobody reads 500 lines of shell on every single update. 

**aur-sentry** is an autonomous, set-and-forget watchdog. it scans newly modified AUR packages every 2 hours, rips through their `PKGBUILD` and `.install` scripts with a specialized rust static-analysis engine, and publishes a live machine-readable threat radar.

---

## 󰐻 live threat radar

auto-updated on schedule by github actions:

<!-- AUTOPILOT_TABLE_START -->
*No active high-severity threats currently recorded in the radar.*
<!-- AUTOPILOT_TABLE_END -->

- 󰏗 machine-readable JSON: [`advisories.json`](advisories.json)
- 󰇚 RSS feed for discord webhooks & readers: [`advisories.xml`](advisories.xml)

---

## 󰈸 detection matrix

aur-sentry doesn't just look for `curl | sh`. it hunts 40+ specific weaponized signatures:

| category | severity | what it catches |
| :--- | :--- | :--- |
| **obfuscation** | 🔴 `CRITICAL` | `base64 -d`, `xxd -r`, `printf '\x63\x75\x72\x6c'`, `printf '\143\165'`, `eval "$cmd"`, backwards strings piped to `rev \| bash`, nested `$()` variable chains |
| **exfiltration** | 🔴 `CRITICAL` | discord webhooks, telegram bot C2 tokens, raw IP downloads (`http://185.x.x.x`), ephemeral drops (`pastebin`, `0x0.st`, `transfer.sh`), DNS tunnel exfil, raw `nc`/`socat` connections |
| **reverse shells**| 🔴 `CRITICAL` | bash `/dev/tcp/ip/port`, `mkfifo /tmp/...`, inline python socket/subprocess shells |
| **credential theft** | 🔴 `CRITICAL` | targetting `~/.ssh`, `~/.gnupg`, firefox/chrome/brave profiles (`logins.json`, cookies), crypto wallets (monero, bitcoin, ledger, exodus), password stores (`1password`, `bitwarden`, `pass`), `/etc/shadow`, `/etc/sudoers` |
| **persistence** | 🔴 `CRITICAL` | dropping `/etc/systemd/system/*.service`, modifying crontabs, injecting `~/.bashrc` / `/etc/profile`, creating XDG `.desktop` autostart entries, udev rule drops |
| **packaging abuse** | 🟠 `HIGH` | unpinned `npm install` / `bun install` / `yarn install` (dependency confusion), `replaces=()` hijacking, checksum bypasses (`SKIP`), privileged `.install` hook abuse |
| **system tampering**| 🟠 `HIGH` | SUID bit modifications (`chmod +s`), `dd` writes to raw block devices, firewall flushing (`iptables`), out-of-tree kernel modules (`insmod`), killing security services (`apparmor`, `fail2ban`) |
| **cryptojacking** | 🔴 `CRITICAL` | XMRig binaries, mining pools (`stratum+tcp://`, `supportxmr`), hardcoded Monero wallet addresses |
| **typosquatting** | 🟡 `MEDIUM` | damerau-levenshtein distance $\le 1$ against top 150 AUR targets (e.g. `goolge-chrome`, `visualstudiocode`, `paruu`) |

---

## 󰄬 installation & setup

### 1. clone & build (rust)

```bash
git clone https://github.com/rebizzz/aur-sentry.git
cd aur-sentry
cargo build --release
```

or with nix:

```bash
nix develop
cargo build --release
```

### 2. verify any package on demand

```bash
# scan a package directly off the AUR
./target/release/aur-sentry scan-pkg discord-canary-bin

# scan a local PKGBUILD before building
./target/release/aur-sentry scan-file ./PKGBUILD
```

### 3. paru pre-build integration

drop `safeaur` into your PATH and tell `paru` to auto-verify packages before compilation.

in `~/.config/paru/paru.conf`:

```ini
[options]
PreBuildCommand = /usr/local/bin/safeaur check
```

now when you run `paru -S <package>`, `safeaur` checks the threat radar and runs a live heuristic scan on the PKGBUILD before anything touches your compiler.

---

## 󰒃 autopilot architecture

```
                 cron (every 2 hours)
                          │
                          ▼
       fetch full AUR metadata dump (gzip)
                          │
                          ▼
     filter packages modified in last 4 hours
                          │
                          ▼
   parallel fetch PKGBUILD + .install scripts
                          │
                          ▼
    rust heuristics engine (40+ attack rules)
                          │
         ┌────────────────┴────────────────┐
         ▼                                 ▼
   threats found?                      clean?
         │                                 │
         ▼                                 ▼
  append to advisories.json           skip / log
  update advisories.xml (RSS)
  update README threat radar table
         │
         ▼
  git commit & push [skip ci]
```

zero human intervention required. once pushed, GitHub Actions handles the rest.

---

## 󰨰 local testing

```bash
cargo test
```

all unit tests verify real attack payloads (base64 injection, discord exfil, reverse shells, raw IP curls, typosquatting, and benign package passes).

---

## 󰏗 license

[MIT](LICENSE) © [rebizzz](https://github.com/rebizzz)
