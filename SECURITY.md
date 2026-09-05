# SAACP Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅        |

## Reporting a Vulnerability

SAACP is a security-critical protocol implementation. If you discover a
vulnerability in the Rust implementation, please report it responsibly.

### How to report

Email: **security@saacp.dev**

Please include:
- A description of the vulnerability
- Steps to reproduce (or a proof-of-concept if possible)
- The affected version/commit hash
- Any suggested mitigation (optional)

### What to expect

- **Acknowledgment** within 48 hours of receipt
- **Initial assessment** within 5 business days
- **Fix timeline** communicated once severity is determined
- **Public disclosure** coordinated with the reporter

### Scope

In scope:
- Cryptographic implementation flaws (key derivation, AEAD, handshake)
- Gate pipeline bypasses or incorrect authorization decisions
- Memory safety issues (despite `#![forbid(unsafe_code)]`)
- Denial-of-service vectors in the daemon or sidecar
- Supply-chain attacks via dependencies

Out of scope:
- Social engineering attacks against operators
- Attacks requiring physical access to the host
- Vulnerabilities in third-party dependencies (report to the upstream project)

## Security Fixes

All security fixes are:
1. Regression-tested with a dedicated test that fails before the fix and passes after
2. Documented in the [CHANGELOG.md](CHANGELOG.md) with the CVE or advisory number
3. Tagged in git with a `security/` prefix in the commit message

## Known Limitations

See [opusreview.md](opusreview.md) for a comprehensive security audit including:
- Threat model and risk assessment (R1-R16)
- Gap analysis with severity ratings
- Prioritized mitigation strategies (M1-M24)

The most critical items are tracked in the mitigation table in opusreview.md §"Mitigation Strategies".
