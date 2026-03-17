# Release Notes

**Content policy**: This file contains the most recent 3 releases (reverse chronological). Older releases are archived in `docs/releases/vX.Y.Z.md`.

## v0.1.1 (March 2026)

**Post-MVP hardening** — Ed25519 signing, Go bindings Phase 1, and CI/security improvements.

- **Ed25519 signing** added to `seclusor-crypto` behind the `signing` feature flag. Rust-native only; Go/TypeScript signing bindings planned for v0.1.2.
- **Go bindings Phase 1**: platform-specific CGo files and a `go-bindings.yml` CI workflow that builds and commits cross-platform prebuilt static libraries before each release tag.
- **`secrets run` test harness**: integration tests covering argument parsing, secret injection, and edge cases.
- **Security**: GHA artifact actions pinned to patched v4 releases (GHSA-cxww-7g56-2vh6).

See `docs/releases/v0.1.1.md` for full notes.

## v0.1.0 (March 2026)

**Initial MVP release** — Rust rewrite of the seclusor secrets management library.

- Library-first design with strong Rust core and bindings for Go + TypeScript
- Age encryption with bundle and inline codecs
- Secure `seclusor run` for secret injection without CLI exposure
- Comprehensive security model and app notes (including git storage risk guidance)
- Embedded `seclusor docs` command

See `docs/releases/v0.1.0.md` for full notes.

_(This file is kept short per project convention.)_
