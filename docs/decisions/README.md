# Decision Records

This directory will hold ADRs/SDRs/DDRs for the Rust rewrite.

Carried-forward decisions from a prior internal Go implementation (unpublished),
imported and Rust-adapted:

- `ADR-0001-repository-root-detection.md`
- `ADR-0002-age-as-default-encryption-backend.md`
- `ADR-0003-storage-codecs-bundle-and-inline.md`
- `ADR-0004-sqlite-driver-and-replication.md` (proposed; Rust TBD)
- `ADR-0005-api-contract-schema-first.md`
- `ADR-0006-dry-core-cli-server-and-stdout-purity.md`
- `SDR-0001-server-unseal-and-key-management.md` (server mode deferred)

New decisions planned for the Rust rewrite:

- `ADR-0007-rust-crate-decomposition.md` (draft)
- ADR-0008: FFI design (opaque handles vs JSON-over-FFI)
- ADR-0009: Error model (Rust + FFI code mapping)
- ADR-0010: Secret injection models (exec/eval/env-file/library/daemon)
- DDR-0001: Go/TS delivery strategy (in-repo vs adjacent repos)
