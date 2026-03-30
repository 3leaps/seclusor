# Changelog

**Content policy**: This file contains the most recent 10 releases (reverse chronological). Older releases are archived in `docs/releases/vX.Y.Z.md`.

All notable changes to seclusor will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to Semantic Versioning.

## [0.1.2] - 2026-03-19

### Added

- Go bindings for Ed25519 signing workflows (D12)
- Signing parity tests between Rust and Go implementations
- The Go `seclusor` bindings now expose `GenerateSigningKeypair`, `Sign`, `Verify`, `SigningPublicKeyFromSecretKey`, and `WipeBytes`
- Full test coverage ensuring Rust and Go agree on key, signature, and error semantics

### Changed

- Public repo polish pass trimmed stale license allowances from `deny.toml`
- Updated top-level documentation and release notes to reflect shipped Go signing support in v0.1.2

See `docs/releases/v0.1.2.md` for full notes.

## [Unreleased]

### Security

- Patched a JSON error-reporting path so secret material is not echoed to console output or surfaced through binding error state when malformed input triggers serde parsing failures

## [0.1.1] - 2026-03-17

### Added

- Ed25519 signing primitives in `seclusor-crypto` behind the `signing` feature flag: `generate_signing_keypair`, `sign`, `verify`, `signing_public_key`, and canonical byte conversion functions
- Ed25519 key types: `SigningKeypair`, `SigningSecretKey` (zeroized on drop, no `Debug`/`Clone`/serde), `SigningPublicKey`, `Signature`
- Four content-free signing error variants: `InvalidSecretKeyBytes`, `InvalidPublicKeyBytes`, `InvalidSignatureBytes`, `SignatureVerificationFailed`
- Go bindings Phase 1: platform-specific CGo files (`cgo_<os>_<arch>.go`) for dual local/CI library path resolution, matching the ipcprims/sysprims pattern
- `go-bindings.yml` CI workflow: cross-compiles `seclusor-ffi` static libraries for all supported platforms and opens a PR with prebuilt artifacts before each release tag
- Integration test harness for the `seclusor secrets run` subcommand
- ADR-0011 (Ed25519 signing placement and scoping) and DDR-0002 (Ed25519 signing byte contract)

### Security

- Pinned `actions/upload-artifact` to `v4.6.2` and `actions/download-artifact` to `v4.3.0` to address GHSA-cxww-7g56-2vh6 (zip-slip in artifact actions)

### Notes

- Ed25519 signing is Rust-native only in v0.1.1. Go and TypeScript signing bindings are intentionally deferred to v0.1.2 (tracked as D11B) to allow a deliberate FFI design pass before binding the signing contract to the stable v0.1.x ABI.

See `docs/releases/v0.1.1.md` for detailed release notes.

## [0.1.0] - 2026-03-13

### Added

- Complete Rust rewrite as library-first project with six-crate workspace
- Two storage codecs (bundle + inline) with conversion support
- Secure CLI including `secrets run` for safe secret injection
- First-class Go and TypeScript bindings via FFI/NAPI
- Embedded documentation system (`seclusor docs`)
- Comprehensive security documentation, app notes, and responsible disclosure policy
- Release engineering, SBOM, and signing infrastructure

### Security

- Enforced fail-closed validation, size limits, and stdout purity
- Hardened secret input channels per SDR-0002
- Added key rekeying, compromise response, and integrity guidance

See `docs/releases/v0.1.0.md` for detailed release notes.

_(Older entries archived in `docs/releases/`)_
