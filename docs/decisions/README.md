# Decision Records

This directory holds ADRs/SDRs/DDRs for the Rust rewrite.

## Accepted ADRs

- `ADR-0001-repository-root-detection.md`
- `ADR-0002-age-as-default-encryption-backend.md`
- `ADR-0003-storage-codecs-bundle-and-inline.md`
- `ADR-0005-api-contract-schema-first.md`
- `ADR-0006-dry-core-cli-server-and-stdout-purity.md`
- `ADR-0008-ffi-contract-json-over-ffi-and-opaque-handles.md`
- `ADR-0011-ed25519-signing-in-seclusor-crypto.md`

## Accepted SDRs

- `SDR-0001-server-unseal-and-key-management.md` (server mode deferred)
- `SDR-0002-secret-input-channels-and-cli-arg-policy.md`

## Accepted DDRs

- `DDR-0001-go-ts-delivery-strategy.md` (in-repo delivery, Option A)
- `DDR-0002-ed25519-signing-contract.md`
- `DDR-0003-release-asset-naming-convention.md`
- `DDR-0004-canonical-signing-payload.md` (v0.2.0 SC-016 prereq)

## Proposed / Draft

- `ADR-0004-sqlite-driver-and-replication.md` (proposed; Rust TBD)
- `ADR-0007-rust-crate-decomposition.md` (draft)
- `ADR-0009` (planned): Error model (Rust + FFI code mapping)
- `ADR-0010` (planned): Secret injection models (exec/eval/env-file/library/daemon)
- `DDR-0005` (planned): Trusted-time threat model (SC-017 design artifact)
