# ADR-0007: Rust Crate Decomposition (Library-First, Transports as Adapters)

Status: Draft  
Date: 2026-02-28  
Owner: entarch

## Context

seclusor is a security-sensitive secrets/encryption library with multiple
consumers:

- Rust workspace dependents (notably **lanyte-attest / CRT-012**)
- a first-class CLI
- future server/daemon transports
- Go and TypeScript libraries via bindings

We must maximize DRY and ensure meaningful functionality is invokable via:

- Rust libraries (direct)
- bindings (Go/TS)
- CLI/server transports that call the same core logic

ADR-0006 establishes the DRY-core + stdout-purity rule. This ADR defines the
Rust crate boundaries that encode that architecture.

## Decision

### Workspace layout

Use a library-first workspace where CLI and FFI are leaf nodes:

```
crates/
  seclusor-core
  seclusor-crypto
  seclusor-codec
  seclusor-keyring
  seclusor-ffi
  seclusor            (CLI)
bindings/
  go/seclusor
  typescript
```

### Dependency direction (inward only)

Library crates MUST NOT depend on transport crates:

- `seclusor-core` has no internal deps.
- `seclusor-crypto` depends on `seclusor-core`.
- `seclusor-codec` depends on `seclusor-core` + `seclusor-crypto`.
- `seclusor-keyring` depends on `seclusor-core` + `seclusor-crypto`.
- `seclusor-ffi` depends on the library crates (exports C-ABI).
- `seclusor` (CLI) depends on the library crates (arg parsing + IO only).

### Responsibilities (boundary contracts)

- `seclusor-core`: domain types, validation rules, constants, redaction policy,
  env export/import shapes.
- `seclusor-crypto`: crypto boundary (age wrapper), size limits, identity parsing
  (no file IO beyond parsing provided buffers/paths as library API dictates).
- `seclusor-codec`: bundle/inline codecs, format detection, conversions.
- `seclusor-keyring`: identity generation and recipient discovery/management.
- `seclusor-ffi`: stable ABI boundary; no bespoke domain logic.
- `seclusor` (CLI): transport only; enforces stdout purity and exit codes.

### Critical path for lanyte

To unblock lanyte-attest as a Rust crate consumer:

1. `seclusor-core` (errors/constants and minimal types)
2. `seclusor-crypto` (passphrase decrypt/encrypt APIs with size limits)
3. `seclusor-keyring` (identity generation and recipient management)

FFI/bindings are not required for CRT-012, but the crate boundaries must keep
them feasible without refactors.

## Consequences

- DRY: transports remain thin and cannot fork crypto/validation behavior.
- Parity: Go/TS bindings map to stable library semantics, not reimplemented code.
- Security review scope is clearer: secret handling concentrates in library crates.

## Follow-ups

- ADR-0008: FFI contract (handles vs JSON-over-FFI) and stability rules.
- ADR-0009: Error model (Rust errors + FFI result code mapping).
- ADR-0010: Secret injection models (exec/eval/env-file/library/daemon) and posture.
