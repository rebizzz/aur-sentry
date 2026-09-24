# AUR Sentry 2.0 — Architecture (Free-Tier Edition)

> AUR is where packages are submitted. AUR Sentry is where their trust is established.

This document adapts the "AUR Sentry 2.0" vision to run entirely on free infrastructure:
**no AWS, no paid compute, no paid database.** Every component maps to a GitHub-native
(or otherwise free) equivalent. Cost target: **$0/month**.

## Substitution table (vision → free implementation)

| Vision component            | Paid original         | Free substitute                                             |
|------------------------------|------------------------|---------------------------------------------------------------|
| Disposable sandbox            | AWS Fargate task       | GitHub Actions job on a GitHub-hosted runner (fresh VM per job, destroyed after) |
| Job queue / scheduler         | SQS + EventBridge      | GitHub Actions `workflow_dispatch` + scheduled `cron` + `repository_dispatch` |
| Control-plane DB              | RDS PostgreSQL         | JSON/NDJSON files committed to a `data/` branch (already the pattern used by `advisories.json`) |
| Raw evidence storage          | S3                     | GitHub Actions artifacts (90-day retention) + committed summarized evidence in-repo |
| Registry web UI               | Custom web app + infra | GitHub Pages (static site) reading the committed JSON |
| Public API                    | Custom API service     | Raw GitHub-hosted JSON files served over `raw.githubusercontent.com` / Pages, same URLs act as the API |
| Attestation signing           | KMS / custom PKI       | `cosign` keyless signing via GitHub OIDC (Sigstore public-good instance, free) — landed in Phase 3 |
| GitHub issues                 | —                      | unchanged — stays as the human notification layer |
| Reproducibility builds        | Second AWS task        | A second, independent GitHub Actions job (different runner, run later) |

Trade-offs accepted for $0 cost:
- GitHub-hosted runners give ~2-core/7GB VMs, 6-hour job cap, and no persistent state between jobs — fine for one-package-at-a-time disposable analysis, not for always-on services.
- No inbound network isolation controls beyond what the runner's egress firewall (or a GH Actions network-restriction step) provides. Canary secrets + egress logging are the practical mitigation instead of a locked-down VPC.
- Scale is bounded by GitHub Actions' free minutes for public repos (unlimited for public repos on standard runners) — this is why AUR-wide scanning stays static-first and only escalates to dynamic sandboxing for new/changed/high-risk packages (see triage below).

## Pipeline (mapped from the original 40-step vision)

```
AUR (metadata dump, every 2h)
   -> Snapshotter          (records package identity: commit, PKGBUILD sha256, SRCINFO)
   -> Static Analyzer       (existing Rust regex/AST engine -> structured `Behavior` evidence)
   -> Triage                (unchanged/low-risk -> stop; new/changed/high-risk -> queue dynamic job)
   -> Dynamic Sandbox (GH Actions job, ephemeral runner)
        - build phase (makepkg) with canary secrets planted, process/network/fs telemetry
        - install phase (pacman -U) in a second container, same telemetry
        - package/ELF analysis of build output
        - external intelligence: OSV.dev vulnerability-database correlation (see below)
   -> Evidence Engine        (merge static + dynamic + package analysis into one evidence doc)
   -> Verdict Engine          (deterministic rules, no ML/LLM judgment)
   -> Attestation             (signed JSON: package identity + evidence + verdict)
   -> Registry                (commit to data/attestations/<pkg>/<version>.json, publish via Pages)
   -> Notifications           (GitHub issue only for SUSPICIOUS/MALICIOUS)
```

## Verdict states

`VERIFIED | SUSPICIOUS | MALICIOUS | INCONCLUSIVE | BUILD_FAILED | ANALYSIS_FAILED | STALE | UNSUPPORTED`

`STALE` fires automatically whenever the AUR commit for a package no longer matches the
commit recorded in the latest attestation — this is what prevents "verified yesterday,
malicious commit pushed today, still shows verified."

## External intelligence (OSV.dev)

The original vision describes external signals (vulnerability databases, known-malware hash
matches) as "another evidence source" — never something that decides a verdict on its own.
`scripts/dynamic_sandbox.sh` implements the free, realistic slice of this: a single batched
query to `https://api.osv.dev/v1/querybatch` (no API key, generous free-tier limits) per
package scan, written to `external_intel.json` and stored on `Attestation.external_intelligence`
via `aur-sentry attest --external-intel <path>`.

**Honest scope and limitation:** OSV.dev has no "Arch" or "AUR" ecosystem (verified against
the OSV schema docs — there is no fabricated ecosystem here). That means there is no reliable,
general way to query OSV for an AUR package's own dependency graph, since most AUR
`depends()`/`makedepends()` entries are system libraries (`glibc`, `gtk3`, ...) that OSV simply
doesn't track. What the sandbox actually queries:

- Every `depends()`/`makedepends()` name from `.SRCINFO` (version constraints stripped) against
  OSV's `PyPI`, `npm`, and `crates.io` ecosystems, on the chance the same name also happens to
  be a package there. This is a **name-collision guess**, not an identity match — low-yield,
  and for most AUR packages this finds nothing at all. That's expected, not a bug.
- If PKGBUILD's `url=` points at a `github.com` repo, its Go-module form
  (`github.com/owner/repo`) is queried against OSV's `Go` ecosystem. Unlike the above, this
  **is** an exact identity match (Go module names are literally their GitHub path), so it's the
  one genuinely reliable signal this step produces — and it only fires for Go-based AUR
  packages.

`external_intelligence` is **informational only**: like `reproducibility` (Phase 3), it never
feeds `verdict_from_findings` (`src/attest.rs::parse_external_intelligence`). This was a
deliberate, conservative choice for this pass — an OSV name-collision match is a much weaker
signal than a directly-observed fact about the build itself (canary access, setuid files,
undeclared network egress), so it's surfaced as evidence for a human/downstream consumer to
weigh rather than folded into the automated verdict.

## Attestation schema

See `schemas/attestation.schema.json`. Core Rust types live in `src/attestation.rs`
(`Verdict`, `Behavior`, `Evidence`, `Attestation`).

## Phased rollout — status

1. **Phase 1 — landed.** Attestation schema (`schemas/attestation.schema.json`) + Rust types
   (`src/attestation.rs`), static-analysis findings reshaped into structured `Behavior`
   evidence, the GH Actions dynamic-sandbox workflow, the registry site skeleton.
2. **Phase 2 — landed.** Triage scheduler (`scripts/triage_dispatch.sh`, run from
   `autopilot.yml`) escalates NEW / MAINTAINER_CHANGED / COMMIT_CHANGED / STALE / HIGH_RISK
   packages to the dynamic sandbox via `repository_dispatch`, capped at 20 dispatches/run.
   Canary-secret planting + strace-based exfiltration detection in
   `scripts/dynamic_sandbox.sh`. Package-content/ELF analysis (file counts, ELF arch/stripped/
   PIE, setuid/setgid + world-writable detection) feeds the same findings list that drives
   `verdict_from_findings` — a setuid binary or world-writable file actually flips the verdict.
3. **Phase 3 — landed.**
   - Reproducibility: two independent real `makepkg` builds, file-list + hash diff. Kept
     **informational only** (never feeds the verdict) per the vision's explicit caution.
   - Sigstore/cosign signing: `dynamic-sandbox.yml` signs every attestation JSON keylessly via
     GitHub Actions OIDC (`sigstore/cosign-installer` + `cosign sign-blob --yes`, free, no
     stored secrets/KMS), publishing sibling `<version>.json.sig` / `.cert` files. `signature`
     on `Attestation` stays `None` — signing the file's own final bytes, then folding the
     result back in, would invalidate what was just signed. Verify any published attestation:

     ```sh
     scripts/verify_attestation.sh <package> <version>
     # equivalent to:
     cosign verify-blob \
       --certificate  <version>.json.cert \
       --signature    <version>.json.sig \
       --certificate-identity-regexp '^https://github.com/rebizzz/aur-sentry/.github/workflows/dynamic-sandbox.yml@refs/heads/main$' \
       --certificate-oidc-issuer https://token.actions.githubusercontent.com \
       <version>.json
     ```
   - Public JSON "API": `raw.githubusercontent.com/.../data/attestations/<pkg>/<version>.json`
     and `docs/data/manifest.json`, served for free via the repo/Pages — no separate API service.
   - External intelligence (OSV.dev), informational only — see the section above for the honest
     scope/limitation.
4. **Phase 4 — landed.** `aur-sentry check <pkg>` (`src/main.rs`) hits the published registry
   and prints a plain-language checklist + verdict, exit-code-gateable (`aur-sentry check <pkg>
   && makepkg`). `bin/safeaur`'s `PreBuildCommand` hook now also consults the registry (policy:
   VERIFIED silent, STALE/unknown warn-and-allow, SUSPICIOUS warn/prompt or `--strict` block,
   MALICIOUS unconditional block) before falling back to its local heuristic scan.
5. **Notifications — landed.** `scripts/file_dynamic_threat_issue.sh`, run from
   `dynamic-sandbox.yml` after each attestation commit, files/updates a GitHub issue for
   SUSPICIOUS/MALICIOUS verdicts only (mirrors the existing `file_threat_issue.sh` pattern used
   by the static-scan autopilot). VERIFIED/INCONCLUSIVE/etc. stay silent — the registry is the
   primary output.

## Known gaps (not yet built, tracked here rather than a separate doc)

- **Static analyzer is still regex/keyword-based**, not the AST-aware shell-semantics engine the
  original vision describes (section 6: distinguishing `curl url | bash` from a benign
  `curl url` fetch by real control/data flow, not string matching). This is a substantial,
  separate rewrite of `src/analyzer.rs`/`src/scanner.rs` that every implementation pass so far
  has deliberately left untouched to avoid destabilizing the existing 40+-signature scanner.
- **No separate install-phase container.** The vision calls for building the package in one
  disposable environment, then installing the resulting `.pkg.tar.*` fresh in a *second* clean
  container specifically to observe `.install` script behavior (`post_install`/`post_upgrade`)
  in isolation from build-time behavior. Today's pipeline observes build-time telemetry
  (`makepkg`) and separately extracts+inspects the package's *contents*, but does not run
  `pacman -U` in a second sandbox to observe `.install` scripts executing.
- **No per-package history/diff view** in the registry UI (vision section 21) — the registry
  shows the latest attestation per package, not a timeline of prior scans or a PKGBUILD diff
  between versions.
- **No homepage aggregate stats/active-threats banner** (vision section 33) — `docs/index.html`
  lists packages individually; there's no "118,492 verified / 1,102 suspicious" summary rollup.
- **Confidence/coverage is not tracked separately from verdict** (vision section 35) — a
  `VERIFIED` result doesn't currently carry an explicit "analysis coverage: 94%" alongside it,
  though `UNSUPPORTED`/`ANALYSIS_FAILED`/`INCONCLUSIVE` verdict states exist for the cases where
  something couldn't be checked at all.

This file is the living plan; update it as phases land instead of writing new planning docs.
