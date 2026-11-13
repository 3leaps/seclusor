# DDR-0006: Dual Native Implementation (Rust + Pure Go) and Language Binding Strategy

Status: Proposed (target cutover: v0.3.0; supersedes DDR-0001 at cutover)  
Date: 2026-11-13  
Owner: entarch

## Context

[DDR-0001](DDR-0001-go-ts-delivery-strategy.md) adopted in-repo C FFI bindings
(`bindings/go/seclusor` via CGo + prebuilt platform static libraries over
`seclusor-ffi`, and `bindings/typescript` via a Node-API `napi-rs` native addon)
so Go and TypeScript consumers shared a single Rust implementation.

In practice, CGo static-library delivery for Go carries significant operational
and supply-chain friction:

- Go consumers inherit CGo toolchains, platform-specific static archive matrices
  (`darwin-amd64`, `darwin-arm64`, `linux-amd64`, `linux-arm64`,
  `windows-amd64`), compiler bitcode/symbol compatibility constraints across Go
  minor releases, and dual release-tag choreography (`vX.Y.Z` plus
  `bindings/go/seclusor/vX.Y.Z`).
- Cross-compilation (`CGO_ENABLED=0`), static binary hardening, and reproducible
  downstream Go builds are impeded by CGo linkage.
- `seclusor`'s core cryptographic primitives (`age` X25519/scrypt encryption and
  Ed25519 canonical payload signing) already have mature, audited, pure-Go
  equivalents (`filippo.io/age` and Go standard library `crypto/ed25519`).

Locked parallel native implementations in **Rust** and **pure Go (`CGO_ENABLED=0`)**
within one repository — governed by one contract, one shared language-neutral
conformance vector suite, and one version tag, with TypeScript (`napi-rs`) and
Python (`PyO3` / `maturin`, when needed) bindings linked directly against the
Rust crates — eliminate CGo friction for Go consumers while preserving
behavioral parity.

## Decision

Transition `seclusor` from `DDR-0001` CGo Go bindings to a **dual native Rust +
pure-Go implementation** at the `v0.3.0` minor boundary:

1. **Parallel native implementations (Rust + pure Go):**
   - **Rust (`crates/seclusor-*`):** Remains the primary CLI (`seclusor`),
     library workspace, and FFI host tree.
   - **Pure Go (root `go.mod`, `github.com/3leaps/seclusor`):** Implements the
     `seclusor` contract natively in pure Go (`CGO_ENABLED=0`) using
     `filippo.io/age` (plus `filippo.io/age/armor`) and standard library
     `crypto/ed25519` / `crypto/sha256`.
2. **Shared language-neutral conformance suite (`conformance/`):**
   - Both the Rust and pure-Go implementations are gated in CI against a single
     shared `conformance/` vector suite covering:
     - `bundle` and `inline` `age` round-trip interoperability (Rust-encrypted
       vectors decrypted by Go and vice versa)
     - [DDR-0004](DDR-0004-canonical-signing-payload.md) typed-byte canonical
       signing payload (`seclusor.signature.v1\x00` domain-separated binary
       framing — not JCS) and Ed25519 signature generation/verification parity,
       with SHA-256 used for envelope asset digests and key fingerprints
     - schema validation, key/project slug rules, redaction invariants, and
       recipient-drift detection
     - deterministic error-code parity across malformed, tampered, and
       mismatched-recipient inputs
3. **Single version and tag (`vX.Y.Z`):**
   - At `v0.3.0`, root `go.mod` (`github.com/3leaps/seclusor`) replaces the
     legacy nested `bindings/go/seclusor` module, retiring the secondary
     `bindings/go/seclusor/vX.Y.Z` tag choreography and prebuilt Go static
     archive step. (`v0.2.x` patch releases retain the existing nested module
     for compatibility until `v0.3.0`.)
4. **Python and TypeScript via Rust FFI when needed:**
   - **TypeScript** (`bindings/typescript` via `napi-rs`) and **Python**
     (`PyO3` / `maturin`, when consumer demand warrants) bindings are produced
     from the Rust tree and graded against the same `conformance/` vectors.
   - `seclusor-ffi` ([ADR-0008](ADR-0008-ffi-contract-json-over-ffi-and-opaque-handles.md))
     remains available for C ABI / non-Go FFI consumers as needed, without
     constraining pure-Go builds.
5. **Declared per-tree capability extensions:**
   - Core at-rest codecs, recipient validation, and signature verification must
     stay locked in parity across Rust and pure Go. Any capability intentionally
     scoped to one runtime during bootstrap (for example interactive CLI TUI or
     external `age-plugin-*` subprocess orchestration prior to Go parity) must
     be declared in contract metadata with explicit `unsupported` conformance
     expectations rather than silent divergence.

## Consequences

- Go consumers import `github.com/3leaps/seclusor` with `CGO_ENABLED=0`, zero
  static C archives, standard cross-compilation, and single-tag releases.
- Cross-implementation drift is prevented structurally by bidirectional
  `conformance/` fixtures rather than single-source CGo wrapping.
- `DDR-0001` remains in force for `v0.2.x` patch maintenance and is superseded
  upon the `v0.3.0` cutover.

## Related Decisions

- Supersedes (at `v0.3.0`): [DDR-0001](DDR-0001-go-ts-delivery-strategy.md)
- [ADR-0002](ADR-0002-age-as-default-encryption-backend.md)
- [ADR-0008](ADR-0008-ffi-contract-json-over-ffi-and-opaque-handles.md)
- [ADR-0011](ADR-0011-ed25519-signing-in-seclusor-crypto.md)
- [DDR-0002](DDR-0002-ed25519-signing-contract.md)
- [DDR-0004](DDR-0004-canonical-signing-payload.md)
