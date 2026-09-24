# aur-sentry

Automated supply-chain malware watchdog and threat radar for the Arch User Repository (AUR). Written in Rust, running on 100% autopilot via GitHub Actions.

[![CI](https://github.com/rebizzz/aur-sentry/actions/workflows/ci.yml/badge.svg)](https://github.com/rebizzz/aur-sentry/actions/workflows/ci.yml)
[![Autopilot](https://github.com/rebizzz/aur-sentry/actions/workflows/autopilot.yml/badge.svg)](https://github.com/rebizzz/aur-sentry/actions/workflows/autopilot.yml)
[![codecov](https://codecov.io/gh/rebizzz/aur-sentry/graph/badge.svg?token=)](https://codecov.io/gh/rebizzz/aur-sentry)
[![Security Audit](https://github.com/rebizzz/aur-sentry/actions/workflows/security-audit.yml/badge.svg)](https://github.com/rebizzz/aur-sentry/actions/workflows/security-audit.yml)
[![CodeQL](https://github.com/rebizzz/aur-sentry/actions/workflows/codeql.yml/badge.svg)](https://github.com/rebizzz/aur-sentry/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

---

## Live Threat Radar

Active threats and supply-chain vulnerabilities detected across the AUR are tracked live:

- **Threat Radar**: [`ADVISORIES.md`](ADVISORIES.md)
- **JSON Feed**: [`advisories.json`](advisories.json)
- **RSS Feed**: [`advisories.xml`](advisories.xml)

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

# Query live threat radar from the terminal
./target/release/aur-sentry radar
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

<table>
  <thead>
    <tr>
      <th align="left">Severity</th>
      <th align="left">Category</th>
      <th align="left">Signatures &amp; Detection Vectors</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code>[CRITICAL]</code></td>
      <td><strong>Obfuscation</strong></td>
      <td><code>base64 -d</code>, <code>xxd -r</code>, octal/hex <code>printf</code>, <code>eval</code>, reversed strings (<code>rev | bash</code>)</td>
    </tr>
    <tr>
      <td><code>[CRITICAL]</code></td>
      <td><strong>Exfiltration</strong></td>
      <td>Discord webhooks, Telegram bot C2, raw IP targets, DNS tunneling, netcat connections</td>
    </tr>
    <tr>
      <td><code>[CRITICAL]</code></td>
      <td><strong>Reverse Shells</strong></td>
      <td>Bash <code>/dev/tcp</code>, <code>mkfifo</code>, Python socket one-liners</td>
    </tr>
    <tr>
      <td><code>[CRITICAL]</code></td>
      <td><strong>Credential Theft</strong></td>
      <td>Access to <code>~/.ssh</code>, <code>~/.gnupg</code>, browser profiles (<code>logins.json</code>, cookies), crypto wallets, cloud keys (<code>~/.aws</code>, <code>~/.kube</code>), <code>/etc/shadow</code></td>
    </tr>
    <tr>
      <td><code>[CRITICAL]</code></td>
      <td><strong>Persistence</strong></td>
      <td>Modifying <code>/etc/systemd/system/</code>, crontabs, injecting <code>~/.bashrc</code> / <code>/etc/profile</code>, XDG autostart</td>
    </tr>
    <tr>
      <td><code>[HIGH]</code></td>
      <td><strong>Packaging Abuse</strong></td>
      <td>Unpinned <code>npm install</code> / <code>bun install</code> (dependency confusion), privileged <code>.install</code> hooks, <code>replaces=()</code> hijacking</td>
    </tr>
    <tr>
      <td><code>[HIGH]</code></td>
      <td><strong>System Tampering</strong></td>
      <td>SUID bits (<code>chmod +s</code>), <code>dd</code> writes to block devices, disabling firewalls/security daemons</td>
    </tr>
    <tr>
      <td><code>[CRITICAL]</code></td>
      <td><strong>Cryptojacking</strong></td>
      <td>XMRig, mining pool addresses, hardcoded wallet addresses</td>
    </tr>
    <tr>
      <td><code>[HIGH]</code></td>
      <td><strong>Shannon Entropy</strong></td>
      <td>Mathematical entropy analysis (<em>H</em> &gt; 5.2 bits/byte) to catch packed, encrypted, or obfuscated payloads</td>
    </tr>
    <tr>
      <td><code>[CRITICAL]</code></td>
      <td><strong>Recursive De-Obfuscator</strong></td>
      <td>Extracts and decodes base64 strings in-memory, recursively scanning unpacked payloads for hidden C2 hooks</td>
    </tr>
    <tr>
      <td><code>[HIGH]</code></td>
      <td><strong>Archive &amp; ELF Inspection</strong></td>
      <td>Streams in-memory tarball sources to detect UPX-packed binaries (<code>UPX!</code>), hidden scripts in asset dirs, and miner payloads</td>
    </tr>
    <tr>
      <td><code>[MEDIUM]</code></td>
      <td><strong>Typosquatting</strong></td>
      <td>Damerau-Levenshtein distance &le; 1 against top AUR packages</td>
    </tr>
  </tbody>
</table>

---

## Autopilot Mode

Runs via GitHub Actions every 2 hours:
1. Downloads the full AUR metadata dump (`packages-meta-ext-v1.json.gz`, ~120k packages).
2. Filters packages modified in the recent window.
3. Rips through `PKGBUILD` and `.install` files with the deep Rust analyzer suite.
4. Files automated GitHub Issue alerts for any `[CRITICAL]` threats.
5. Updates `advisories.json`, `advisories.xml`, and `ADVISORIES.md`.
6. Opens automated pull requests for threat radar and machine feed synchronizations.

---

## License

[MIT](LICENSE) (c) rebizzz
