# Changelog

**Content policy**: This file contains the most recent 10 releases (reverse chronological). Older releases are archived in `docs/releases/vX.Y.Z.md`.

All notable changes to seclusor will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to Semantic Versioning.

## [0.1.5] - 2026-04-02

### Added

- `secrets blob encrypt` and `secrets blob decrypt` commands for opaque file encryption (SC-010). Encrypt any file (shell scripts, configs, binary tokens) using age identity/recipient keys — no JSON parsing or schema validation
- 10 MB default size limit with `--allow-large` override (guardrail, not security boundary)
- Atomic writes on blob decrypt via `tempfile::NamedTempFile` + `persist()` to avoid partial output on failure
- Decrypt output created with 0600 permissions on Unix (decrypted content is assumed sensitive)

### Changed

- Release workflow checksum generation now uses `find` instead of `ls` (fixes shellcheck SC2012)

### Security

- Blob decrypt uses unique temp files with exclusive creation (no symlink or pre-existing file risk)
- Blob file size limit enforced at read time via bounded reader (no TOCTOU gap)

See `docs/releases/v0.1.5.md` for full notes.

## [0.1.4] - 2026-04-02

### Added

- Passphrase-protected identity files: generate and use age identity files encrypted with scrypt passphrases (SC-008). Four input channels: interactive prompt (`--passphrase`), environment variable (`--passphrase-env`), file (`--passphrase-file`), stdin (`--passphrase-stdin`).
- Library API for passphrase-protected identities in `seclusor-keyring`: `generate_identity_file_with_passphrase`, `load_identity_file_with_passphrase`, `load_identity_file_auto`, `is_passphrase_protected_identity`
- Help text on all CLI arguments across all commands (SC-007 Part A)
- Identity and recipients documentation guide (`docs/guides/identity-and-recipients.md`) explaining the conceptual model, file format, permissions, passphrase protection, and team workflows (SC-007 Part B)
- Homebrew formula and Scoop manifest for seclusor
- `update-homebrew-formula` and `update-scoop-manifest` Makefile targets wired into `release-upload`
- `release-upload-all` target for uploading platform binaries alongside provenance

### Changed

- Release assets now use org-standard bare binary naming (`seclusor-darwin-arm64`, `seclusor-linux-amd64`, etc.) instead of versioned archives (DDR-0003)
- `release-upload` now uploads provenance only (checksums, signatures, keys, notes); use `release-upload-all` for full assets
- CLI help text for `--value` and `--ref` explains the distinction and portability guidance (SC-007, carried from v0.1.3 cycle)
- `InlineEncrypted` error message no longer references passphrase (deferred until CLI support existed; now delivered in this release)
- Security guide updated: removed premature `secrets rekey` CLI example, added identity protection section

### Security

- Passphrase-protected identity files enforce 0600 permissions on Unix, same as plaintext identities. Passphrase files (`--passphrase-file`) additionally enforce current-user ownership
- Passphrases held as `SecretString` (zeroized on drop) at all CLI boundaries; never stored as plain `String`
- Protected identity file size capped at 8 KiB before decryption attempt
- Malformed armor in protected identity files fails closed (no plaintext fallback)

See `docs/releases/v0.1.4.md` for full notes.

## [0.1.3] - 2026-03-30

### Security

- Redacted all serde JSON error messages across CLI, FFI, and TypeScript bindings so malformed input never leaks secret material to console output or binding error state
- Defense-in-depth fallback sanitizer catches `invalid type:` and `invalid value:` error segments generically, independent of serde_json token formatting

### Added

- Lenient `secrets unset` recovery: when a secrets file contains malformed credentials (e.g., bare strings instead of credential objects), `unset` now falls back to raw JSON manipulation to remove the targeted entry without requiring the file to fully deserialize
- Credential format validation errors now include the key name, expected object shape, and a `secrets set` CLI hint — without revealing the malformed value
- Custom `Credential` deserializer rejects non-object entries (strings, arrays, numbers, booleans) with redaction-safe, actionable error messages
- Credential descriptions on the CLI: `secrets set --description`, `secrets get --show-description`, and `secrets list --verbose`
- Shared description normalization and validation for file, project, and credential descriptions, with schema updates to mirror the runtime contract

### Changed

- Quickstart documentation updated to clarify the init → set → encrypt → run workflow and the expected credential JSON shape
- Description validation now counts Unicode characters rather than UTF-8 bytes, matching the JSON schema contract

See `docs/releases/v0.1.3.md` for full notes.

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
