# AUR Helper Integration (paru & yay)

AUR Sentry includes `safeaur`, an automated pre-build hook script that checks packages against live threat advisories and published attestations before `makepkg` executes.

---

## 1. Quick Setup for `paru`

Edit `~/.config/paru/paru.conf` and add the following option under `[options]`:

```ini
[options]
PreBuildCommand = /usr/local/bin/safeaur check
```

> **Strict Mode:** If you want any `SUSPICIOUS` verdict to block the build outright rather than prompting interactively:
> ```ini
> PreBuildCommand = /usr/local/bin/safeaur check --strict
> ```

---

## 2. Quick Setup for `yay`

You can wrap build scripts or alias yay to execute `safeaur` checks:

```bash
alias yay-safe='safeaur check "$@" && yay "$@"'
```

---

## 3. How the Verification Hook Works

When you run an AUR build, `safeaur check <package>` verifies three layers in order:

1. **Threat Radar Cache:** Checks `generated/advisories.json`. If an active advisory exists for this package, the build aborts immediately.
2. **Keyless Attestation Registry:** Fetches cryptographic verification attestations straight from GitHub Pages / raw feed:
   - `VERIFIED`: Builds proceed silently without interruption.
   - `SUSPICIOUS`: Warns loudly with finding details and prompts for user confirmation.
   - `MALICIOUS`: Blocks the build unconditionally.
   - `UNKNOWN` / `STALE`: Warns that no recent attestation is recorded, but allows the build to continue.
3. **Local Heuristic Engine:** If the `aur-sentry` binary is installed locally, it performs a real-time static scan of the package's `PKGBUILD` and `.install` scripts.
