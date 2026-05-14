# Security Policy

Seclusor is a security-sensitive project that handles encryption and secret material. We take security issues seriously.

## Reporting a Vulnerability

**Please do not report security vulnerabilities via public GitHub issues.**

Instead, please report them privately to:

- **Email**: security@3leaps.net
- **Preferred contact**: @3leapsdave on GitHub (with "Security Issue" in the subject)

When reporting, please include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested mitigation

We will acknowledge receipt within 48 hours and aim to provide a timeline for remediation.

## Supported Versions

We provide security updates for the latest stable release and the active
in-development release branch/PR line. Security fixes use private coordination
until disclosure is appropriate.

## Security-Sensitive Pull Requests

Do not put exploit details, plaintext secrets, private keys, or operational
credentials in public PR text, commit messages, logs, fixtures, screenshots, or
CI artifacts.

For crypto, key-management, and FFI changes:

- Run `make pr-final` before pushing a PR branch.
- Request normal correctness review (`devrev`).
- Request security review (`secrev`) before merge.
- Verify errors, logs, and FFI return values do not disclose plaintext, key
  material, passphrases, or raw ciphertext payloads.

## Upstream Dependencies

This project depends heavily on [`filippo.io/age`](https://age-encryption.org/). We monitor that project for security updates and will address any relevant vulnerabilities promptly.

## Disclosure Policy

We follow responsible disclosure:

- We work with reporters to understand and fix the issue.
- We publish patches as soon as reasonably possible.
- We credit reporters in the release notes (unless anonymity is requested).

Thank you for helping keep Seclusor and its users secure.
