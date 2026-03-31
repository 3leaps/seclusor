# Release Notes

**Content policy**: This file contains the most recent 3 releases (reverse chronological). Older releases are archived in `docs/releases/vX.Y.Z.md`.

## v0.1.3 (March 2026)

**Error redaction, credential recovery, and description metadata** — Plugs a secret-leak vector in JSON error messages, adds actionable credential repair flows, and exposes credential descriptions cleanly in the CLI.

- **Security**: serde JSON errors across CLI, FFI, and TypeScript bindings no longer echo plaintext values from malformed input
- **Credential recovery**: `secrets unset` now falls back to raw JSON manipulation when a file contains malformed credential entries, enabling CLI-only repair without viewing secrets
- **Better error guidance**: credential validation errors report the key name, expected shape, and a `secrets set` hint — never the value
- **Description metadata**: `secrets set --description`, `secrets get --show-description`, and `secrets list --verbose` now expose credential descriptions with shared normalization and validation

See `docs/releases/v0.1.3.md` for full notes.

## v0.1.2 (March 2026)

**Signing parity and public repo polish** — Completes Go signing bindings and tightens the public-facing docs and license policy output.

- Go bindings for Ed25519 signing (completing the signing surface)
- Signing parity tests between Rust and Go
- Documentation updates reflecting shipped Go signing support
- License-policy cleanup in `deny.toml` for quieter `cargo deny` output

See `docs/releases/v0.1.2.md` for full notes.

## v0.1.1 (March 2026)

**Post-MVP hardening** — Ed25519 signing primitives, Go bindings infrastructure, and security fixes.

- **Ed25519 signing** added to `seclusor-crypto` behind the `signing` feature flag. Rust-native only; Go/TypeScript signing bindings planned for v0.1.2.
- **Go bindings Phase 1**: platform-specific CGo files and a `go-bindings.yml` CI workflow that builds and commits cross-platform prebuilt static libraries before each release tag.
- **`secrets run` test harness**: integration tests covering argument parsing, secret injection, and edge cases.
- **Security**: GHA artifact actions pinned to patched v4 releases (GHSA-cxww-7g56-2vh6).

See `docs/releases/v0.1.1.md` for full notes.

_(Older releases archived in `docs/releases/`. This file is kept short per project convention.)_
