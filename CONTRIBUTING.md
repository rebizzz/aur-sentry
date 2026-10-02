# Contributing to AUR Sentry

Thank you for your interest in contributing to **AUR Sentry**! We welcome bug reports, rule proposals, performance improvements, documentation updates, and UI enhancements.

## Code of Conduct

All contributors and participants are expected to adhere to our [Code of Conduct](CODE_OF_CONDUCT.md). Please read it to understand our community expectations.

---

## Getting Started

### Development Environment

AUR Sentry uses Nix flakes for a reproducible development environment with Rust and necessary build dependencies:

```bash
# Enter the Nix development shell
nix develop

# Build the project
cargo build

# Run unit and integration tests
cargo test

# Check formatting and clippy lints
cargo fmt --check
cargo clippy -- -D warnings
```

If you do not use Nix, ensure you have the standard Rust toolchain installed via [rustup](https://rustup.rs/) (Rust 1.80+ / 2024 edition) along with `pkg-config` and `openssl`.

---

## Project Structure

- `src/`: Core Rust CLI and static malware analysis engine.
  - `src/analyzer.rs`: Pattern matching, AST heuristics, and risk scoring for PKGBUILDs and install scripts.
  - `src/scanner.rs`: Package scanning coordination and batch analysis.
  - `src/findings.rs`: Threat definitions, severity ratings, and finding data structures.
  - `src/attestation.rs` & `src/attest.rs`: Cryptographic attestation generation and signing.
  - `src/shellparse.rs`: Bash syntax parsing and token inspection.
  - `src/ui.rs`: Terminal output formatting, progress bars, and colored diagnostics.
- `docs/`: Static web registry hosted on GitHub Pages (`index.html`, `package.html`, `style.css`, `registry.js`).
- `sandbox/`: Disposable containerized environment for dynamic runtime auditing (`build.sh`, `install.sh`, `host_analyze.sh`).
- `data/attestations/`: Signed attestations and audit records.
- `schemas/`: JSON schemas for attestation structures.

---

## Proposing New Threat & Malware Detection Rules

If you identify a new attack vector or malware technique targeting AUR packages:
1. Propose the rule via our [Rule Proposal Issue Template](.github/ISSUE_TEMPLATE/rule_proposal.yml).
2. Include example malicious patterns (e.g. obfuscated payload, reverse shell trick, credential access) and test PKGBUILD samples.
3. Ensure the rule has high signal-to-noise ratio to minimize false positives on legitimate packages.
4. Add corresponding test cases in `src/analyzer.rs` or `tests/`.

---

## Pull Request Guidelines

1. **Branching**: Create a feature branch from `main` (e.g., `feat/obfuscation-detector`, `fix/shellparse-comments`).
2. **Conventional Commits**: Format commit messages according to the Conventional Commits specification:
   - `feat(analyzer): add curl-pipe-sh detection rule`
   - `fix(scanner): prevent unwrap on malformed utf-8 packages`
   - `docs(registry): modernize filter badge contrast`
   - `perf(engine): optimize regex precompilation`
3. **Tests & Lints**:
   - Ensure all tests pass: `cargo test`
   - Ensure clippy is happy: `cargo clippy -- -D warnings`
   - Ensure code is formatted: `cargo fmt`
4. **Documentation**: Update relevant documentation, architecture docs, or schemas if your PR introduces new options or changes data structures.

---

## Security Vulnerabilities

Please **do not** submit public pull requests or issues for zero-day security vulnerabilities in AUR Sentry itself. See [.github/SECURITY.md](.github/SECURITY.md) for instructions on confidential disclosure.
