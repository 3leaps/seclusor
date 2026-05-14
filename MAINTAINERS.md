# Maintainers

This repository is security-sensitive (encryption + secrets management).

## Primary Maintainer

- Dave Thompson (`@3leapsdave`)

## Review Policy

- All code changes land through feature branches and pull requests.
- Human review is required before merge to `main`.
- Authors should run `make pr-final` before pushing a PR branch.
- Crypto, key-management, and FFI changes require security review
  (`secrev`) in addition to normal correctness review (`devrev`).
- Release tags, protected-branch pushes, and direct-to-main operations require
  explicit maintainer approval.
