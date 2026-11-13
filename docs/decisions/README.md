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
- `ADR-0012-recipients-metadata-schema-v1-1-0.md`
- `ADR-0013-value-free-control-plane-and-mcp-boundary.md`

## Accepted SDRs

- `SDR-0001-server-unseal-and-key-management.md` (standalone server mode retired per ADR-0013; key-custody and rotation posture retained)
- `SDR-0002-secret-input-channels-and-cli-arg-policy.md`
- `SDR-0003-rustsec-2026-0173-advisory-acceptance.md` (EPR-0001 §3 record of decision; `proc-macro-error2` build-time residual)
- `SDR-0004-rustsec-2026-0374-advisory-acceptance.md` (EPR-0001 §3 record of decision; `basic-toml` build-time residual)

## Accepted DDRs

- `DDR-0001-go-ts-delivery-strategy.md` (in-repo delivery, Option A; active for v0.2.x, proposed v0.3.0 cutover in DDR-0006)
- `DDR-0002-ed25519-signing-contract.md`
- `DDR-0003-release-asset-naming-convention.md`
- `DDR-0004-canonical-signing-payload.md`

## Proposed / Draft

- `ADR-0007-rust-crate-decomposition.md` (draft)
- `ADR-0009` (planned): Error model (Rust + FFI code mapping)
- `ADR-0010` (planned): Secret injection models (exec/eval/env-file/library)
- `DDR-0005` (planned): Trusted-time threat model
- `DDR-0006-rust-go-twin-and-conformance-strategy.md` (proposed; target cutover v0.3.0)

## Retired / Not Planned

- `ADR-0004-sqlite-driver-and-replication.md` (retired — not planned; superseded by ADR-0013)
