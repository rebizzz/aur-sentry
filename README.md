<p align="center">
  <img src="assets/avatar.png" width="140" height="140" alt="AUR Sentry Logo" style="border-radius: 50%;" />
</p>

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

# Check the published attestation registry for a package before installing
./target/release/aur-sentry check <package-name>
```

### Verify a published attestation

Every scan attestation is signed keylessly via GitHub Actions OIDC (Sigstore,
free — see [`ARCHITECTURE.md`](ARCHITECTURE.md#pr-based-scan-flow--security-model)). Independently verify one
with [cosign](https://docs.sigstore.dev/cosign/installation/):

```bash
scripts/verify_attestation.sh <package> <version>
```

---

## paru / yay Hook

You can intercept builds automatically before `makepkg` runs.

Add to `~/.config/paru/paru.conf`:

```ini
[options]
PreBuildCommand = /usr/local/bin/safeaur check
```

Use `PreBuildCommand = /usr/local/bin/safeaur check --strict` instead if you want any
`SUSPICIOUS` verdict to block the build outright (see below) rather than prompt.

`safeaur check <package>` runs three checks, in order, before `makepkg` runs:

1. **Threat radar cache** — the local `advisories.json` cache. An active advisory aborts
   the build immediately.
2. **Attestation registry** — `data/attestations/<pkg>/<version>.json`, fetched live from
   `raw.githubusercontent.com` (no auth, no local scanner needed). Policy:
   - `VERIFIED` — continue silently.
   - `STALE` or no attestation on record — warn, but allow the build (the registry is new
     and still sparse, so an unscanned package is not treated as guilty).
   - `SUSPICIOUS` — warn loudly; prompts for confirmation on an interactive terminal, or
     blocks outright when run non-interactively or with `--strict`.
   - `MALICIOUS` — blocks unconditionally, no prompt.
3. **Live heuristic scan** — if the `aur-sentry` binary is available locally, it re-scans
   the live PKGBUILD/`.install` for known attack signatures.

Every step degrades gracefully: if the network, the registry, or the cache is unavailable,
`safeaur` warns and lets the build proceed rather than hanging or failing closed.

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

## Autopilot & PR-Based Dynamic Sandboxing

Runs via GitHub Actions every 2 hours:
1. **Metadata Dump & Static Scan:** Downloads the full AUR metadata dump (`packages-meta-ext-v1.json.gz`, ~120k packages) and filters packages modified in the recent window. High-performance static analysis scans `PKGBUILD` and `.install` scripts for attack patterns.
2. **Threat Radar Synchronization:** Updates live threat radar (`ADVISORIES.md`) and machine feeds (`advisories.json`, `advisories.xml`) via an automated pull request.
3. **Triage & Scratch Scan PRs:** Triage prioritizes new, modified, stale, or flagged packages (capped at 20 per cycle). For each candidate, a scratch branch and PR (`scan/<pkg>-<aurcommit7>`) is created with an isolated snapshot of the package files in `scans/<pkg>/`.
4. **Untrusted Sandbox Container Execution:** `scan.yml` runs on an untrusted runner with read-only permissions (`contents: read`). The package builds (`makepkg`) and installs (`pacman -U`) in disposable containers with planted canary secrets. Telemetry is streamed to host-captured stderr, preventing tampering or token theft.
5. **Trusted Finalize & Attestation Signing:** A separate, trusted runner (`finalize` job) downloads raw telemetry, computes the deterministic verdict with `aur-sentry attest`, keylessly signs the attestation via GitHub Actions OIDC (Sigstore), commits `data/attestations/<pkg>/<version>.json` (plus `.sig` and `.cert`) to `main`, updates advisory feeds if suspicious/malicious, posts a verdict checklist comment to the PR, closes the PR, and deletes the scratch branch.

---

## License

[MIT](LICENSE) (c) rebizzz
