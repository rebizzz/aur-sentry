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
| Attestation signing           | KMS / custom PKI       | `cosign` keyless signing via GitHub OIDC (Sigstore, free) or an ed25519 keypair stored as a repo secret |
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

## Attestation schema

See `schemas/attestation.schema.json`. Core Rust types live in `src/attestation.rs`
(`Verdict`, `Behavior`, `Evidence`, `Attestation`).

## Phased rollout

1. **Phase 1 (this increment):** attestation schema + Rust types, static-analysis findings
   reshaped into structured `Behavior` evidence, first GH Actions dynamic-sandbox workflow,
   skeleton registry site.
2. **Phase 2:** triage priority queue driving which packages get dynamic analysis each cycle;
   canary-secret exfiltration detection; ELF/package-content analysis.
3. **Phase 3:** reproducibility (second independent build + diff); Sigstore/cosign signing of
   attestations; public JSON "API" served straight from the repo/Pages.
4. **Phase 4:** `aur-sentry check <pkg>` CLI hitting the published registry; `paru`/`yay`
   `PreBuildCommand` hook upgraded to consult it instead of only the local static scanner.

This file is the living plan; update it as phases land instead of writing new planning docs.
