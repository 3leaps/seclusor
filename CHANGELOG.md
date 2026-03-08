# Changelog

All notable changes to seclusor will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to Semantic Versioning.

## [Unreleased]

### Added

- D8: GitHub Actions workflows for CI, SBOM generation, and draft release assembly.
- D8: CLI stdout-purity integration tests for success-path stderr/stdout behavior.
- D8: Release operator checklist for tag-to-publish verification.

## [0.1.0] - 2026-03-08

### Added

- D0: Rust workspace scaffold, quality-gate Makefile, and repository baseline.
- D1: `seclusor-core` domain model, strict validation, env export/import utilities.
- D2: `seclusor-crypto` age-based encryption/decryption with defensive size limits.
- D3: `seclusor-codec` bundle/inline codecs with conversion paths and hardening.
- D4: `seclusor-keyring` identity generation, recipient management, and rekey APIs.
- D5: CLI parity for secrets and keys workflows, including `run`, bundle/inline, and env flows.
- D6: `seclusor-ffi` C-ABI and Go bindings with handle APIs and JSON-over-FFI patterns.
- D7: TypeScript N-API bindings with typed loader, integration tests, and size/redaction hardening.

### Security

- Enforced fail-closed credential shape handling across export paths.
- Hardened file and inline size checks before allocation across codec/ffi/bindings paths.
- Removed/blocked unsafe secret-input channels in CLI per SDR-0002.

### Notes

- Server mode and control-plane features remain deferred to `v0.1.1+`.
