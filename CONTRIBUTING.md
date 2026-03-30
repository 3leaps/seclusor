# Contributing to seclusor

Thanks for helping build **seclusor** — git-trackable secrets management with age encryption.

This repo aims to be:

- **library-first** (Rust crates provide all domain logic; CLI and FFI are thin consumers),
- **cross-platform** (Linux x64/arm64, macOS arm64, Windows x64/arm64),
- **license-clean** (dual MIT OR Apache-2.0, no copyleft dependencies),
- **binding-friendly** (Go and TypeScript via FFI).

## Quick start (contributors)

1. Install Rust (stable) and the repo toolchain:

- `rustup toolchain install stable`
- `rustup component add rustfmt clippy`

2. Run the full local quality loop:

- `cargo fmt --all`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo test --workspace --all-features`

Or use the Makefile:

- `make check-all` — runs fmt, clippy, test, deny, version-check

> CI is the source of truth; see `.github/workflows/ci.yml`.

## Branching model

All feature work happens on branches and lands via pull requests.

### Branch naming

- `feat/<scope>/<slug>` — new features (e.g., `feat/crypto/ed25519-signing`)
- `fix/<slug>` — bug fixes
- `docs/<slug>` — documentation changes
- `chore/<slug>` — build, CI, dependency updates

### Workflow

1. Create a branch from `main`
2. Develop, commit, push to origin
3. Open a PR against `main` (`gh pr create`)
4. CI runs automatically on the PR
5. Address review feedback
6. Merge (squash for single-concern PRs, merge commit for multi-commit features)

### Direct-to-main exceptions

These small, mechanical operations go directly to `main` during releases:

- Version bump commit (`chore(release): bump vX.Y.Z`)
- Go bindings PR merge (automated by workflow)
- Tag creation

## Pull requests

PRs should be small, focused, and include tests.

**PR checklist**

- [ ] Tests added or updated
- [ ] `cargo fmt` clean
- [ ] `cargo clippy` clean (with `--all-features`)
- [ ] `cargo deny check licenses` clean
- [ ] Docs updated (if behavior changed)
- [ ] FFI changes reviewed for memory safety and binding parity

## Commit style

Follow [3leaps commit style](https://crucible.3leaps.dev/repository/commit-style):

```
<type>(<scope>): <subject>

<body>

Co-Authored-By: <Model> <noreply@3leaps.net>
Role: <role>
Committer-of-Record: @3leapsdave
```

Types: `feat`, `fix`, `docs`, `chore`, `test`, `refactor`

## Dependency and licensing policy

- Allowed: MIT / Apache-2.0 / BSD / ISC / 0BSD / Zlib / Unicode-DFS-2016
- Disallowed: GPL / AGPL
- Avoid: LGPL unless explicitly reviewed and documented

If you propose a new dependency:

- Explain why it is needed
- Prefer `default-features = false`
- Consider a feature-gated option instead of a hard dependency
- Run `cargo deny check` to verify license compliance

## Security

This repository handles encryption and secrets management. When modifying
crypto or key management code:

- No plaintext in error messages or logs
- Key material never written to repo root (pathguard)
- Identity file permissions checked (0600 on Unix)
- Size limits enforced before allocation

If you find a security issue, **do not open a public issue**; follow the
security policy for private disclosure.

## Maintainers

See MAINTAINERS.md for contacts and governance.

Maintainers may request:

- API/FFI adjustments to preserve stability (ADR-0008)
- Schema versioning updates
- Additional cross-platform tests
