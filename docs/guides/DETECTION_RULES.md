# Detection Rules & Threat Signatures

`aur-sentry` uses a multi-layered static and structural analysis engine designed specifically for `PKGBUILD` and Arch Linux `.install` scriptlets.

---

## 1. Attack Vectors & Heuristic Signatures

| Severity | Category | Description & Patterns |
|:---|:---|:---|
| **CRITICAL** | **Obfuscation** | Packed or encoded commands (`base64 -d`, `xxd -r`, hex `printf`, `eval`, `rev \| bash`). |
| **CRITICAL** | **Data Exfiltration** | Outbound telemetry sent to Discord webhooks, Telegram bot APIs, raw IP destinations, and DNS tunnels. |
| **CRITICAL** | **Reverse Shells** | Remote interactive socket connections via `/dev/tcp`, `mkfifo`, netcat (`nc`), or Python sockets. |
| **CRITICAL** | **Credential Theft** | Unauthorized attempts to read `~/.ssh/`, `~/.gnupg/`, browser profiles (passwords/cookies), crypto wallets, and cloud configs (`~/.aws`, `~/.kube`). |
| **CRITICAL** | **Persistence** | Infiltration into system startup via `/etc/systemd/system/`, crontabs, `~/.bashrc`, `/etc/profile.d/`, and autostart entries. |
| **HIGH** | **Packaging Abuse** | Unpinned `npm install` / `bun install` (dependency confusion), privileged `.install` scriptlets, `replaces=()` hijacking. |
| **HIGH** | **System Tampering** | Setting SUID bits (`chmod +s`), raw block device writes via `dd`, modifying `sudoers`, disabling firewalls. |
| **CRITICAL** | **Cryptojacking** | Bundled XMRig miners, crypto mining pools, and hardcoded wallet payout addresses. |
| **MEDIUM** | **Typosquatting** | Damerau-Levenshtein distance &le; 1 against top official and AUR packages. |

---

## 2. Advanced Heuristics

### Shannon Entropy Analysis
Mathematical entropy analysis calculates byte-level randomness ($H > 5.2$ bits/byte) across script tokens to flag encrypted blobs, packed shellcodes, and obfuscated variables that evade standard regex matching.

### Recursive In-Memory De-Obfuscator
When an encoded base64 payload is detected, the engine decodes it in memory and recursively scans the unpacked string against the full threat database to catch hidden C2 hooks and shell calls.

### Structural Pipeline Parsing (`shellparse`)
Rather than dumb string matching, `shellparse` inspects Unix pipeline stages to differentiate safe operations (e.g. `curl -o filename url`) from high-risk fetch-and-execute chains (e.g. `curl ... | bash` or `wget -O - ... | sh`).
