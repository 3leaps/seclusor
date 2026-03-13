# Changelog

**Content policy**: This file contains the most recent 10 releases (reverse chronological). Older releases are archived in `docs/releases/vX.Y.Z.md`.

All notable changes to seclusor will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to Semantic Versioning.

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

## [Unreleased]

_(No changes yet)_

_(Older entries archived in `docs/releases/`)_
