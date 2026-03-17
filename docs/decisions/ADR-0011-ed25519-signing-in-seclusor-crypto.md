# ADR-0011: Ed25519 Signing in seclusor-crypto

Status: Accepted  
Date: 2026-03-17  
Owner: entarch

## Context

seclusor already owns the cryptographic boundary for Rust consumers. Two known
consumers need Ed25519 signatures in addition to age-based encryption:

- `lanyte-attest` unseals Ed25519 keys encrypted with age and signs session
  tokens.
- user repositories want signing capability alongside encryption without taking
  on a second raw crypto abstraction.

At the same time, the in-flight work that will ship as `v0.1.1` is carrying the
first general language-bindings rollout for seclusor on top of the FFI design
captured in [ADR-0008](ADR-0008-ffi-contract-json-over-ffi-and-opaque-handles.md).
That means two things at once:

- other FFI/bindings work is explicitly in scope for `v0.1.1`
- any new signing-specific FFI symbols would still become part of the stable
  `v0.1.x` ABI surface once introduced

The decision here is therefore not to postpone FFI generally, but to postpone
**signing FFI specifically** until the signing contract has shipped in Rust and
the bindings shape can be reviewed as a deliberate second pass.

We therefore need to decide:

- where Ed25519 signing belongs in the crate graph
- which backend to standardize on
- whether signing ships over FFI in `v0.1.1`

## Decision

For `v0.1.1`, add Ed25519 signing to `seclusor-crypto` as a feature-gated,
Rust-native capability.

Specifically:

- `seclusor-crypto` owns Ed25519 key generation, sign/verify, and canonical byte
  conversions.
- The feature is gated behind `seclusor-crypto/signing` and remains off by
  default.
- The backend is `ed25519-dalek`.
- Signing remains out of `seclusor-ffi`, Go, and TypeScript in `v0.1.1`.
- `seclusor-keyring` does not take on signing-key discovery or file-management
  responsibilities in this item.
- File-format handling for signing keys is deferred; D11 is file-I/O-free.

## Rationale

### Why `seclusor-crypto`

- It is already the cryptographic boundary in the workspace under
  [ADR-0007](ADR-0007-rust-crate-decomposition.md).
- Rust consumers need signing primitives now.
- Keeping signing with encryption centralizes secret-handling posture, byte
  contracts, and error hygiene in one crate.

### Why a feature gate

- Encryption-only consumers keep the current dependency surface.
- The signing code is additive and can be exercised separately in CI.

### Why `ed25519-dalek`

- Pure Rust, widely used, and suitable for seclusor's supported targets.
- Good fit with the existing Curve25519-oriented crypto stack.
- Permissive license posture.

### Why no signing FFI in `v0.1.1`

- `v0.1.1` is already carrying the first broad FFI/bindings rollout for other
  seclusor surfaces.
- To keep that rollout moving, signing is intentionally excluded from the first
  bindings pass rather than blocking the broader language-support work.
- ADR-0008 makes new signing exports expensive to revise inside `v0.1.x`.
- The immediate motivating consumer is Rust-native.
- A second pass is expected to add signing bindings once the contract and
  external shape are reviewed deliberately; current planning targets `v0.1.2`
  unless implementation findings require a different follow-up.

## Consequences

- `v0.1.1` intentionally creates a temporary parity gap: Rust gets signing,
  Go/TypeScript do not.
- `v0.1.1` still proceeds with the broader non-signing FFI/bindings work.
- That gap is tracked explicitly as D11B rather than left implicit.
- Future signing exposure through FFI must be reviewed as a separate design pass
  against ADR-0008 constraints.
- Future signing-key file management, if needed, remains available as a separate
  `seclusor-keyring` extension item.

## Follow-Up

- D11 implements Rust-native signing in `seclusor-crypto`.
- D11B covers cross-language signing parity, shared conformance fixtures, and
  any signing-specific FFI design.
- Revisit this ADR when D11B is executed; current planning targets `v0.1.2`
  for signing bindings polish and completion unless implementation findings
  require a different release boundary.

## Notes

The normative signing byte and error contract lives in
[DDR-0002](DDR-0002-ed25519-signing-contract.md). If FFI signing or interchange
artifacts are introduced later, they must preserve that contract unless a future
decision record explicitly supersedes it.
