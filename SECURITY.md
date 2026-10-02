# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| < 0.2.0 | :x:                |

## Reporting a Vulnerability

The AUR-Sentry team takes the security of our supply-chain malware detection pipeline and sandbox environments seriously.

If you believe you have discovered a security vulnerability or bypass in AUR-Sentry:

1. **Do not create a public GitHub issue.**
2. Please report it privately using [GitHub Security Advisories](https://github.com/rebizzz/aur-sentry/security/advisories/new) or contact the maintainer directly.
3. Include details of the finding:
   - Reproduction steps or proof-of-concept PKGBUILD / payload
   - Component affected (e.g. static scanner, dynamic sandbox, attestation logic)
   - Estimated impact (e.g. evasion, false-negative, privilege escalation in runner)

### Response Timeline
- **Acknowledgement**: Within 48 hours.
- **Triage & Assessment**: Within 5 business days.
- **Fix & Disclosure**: Coordinated release with CVE assignment if applicable.
