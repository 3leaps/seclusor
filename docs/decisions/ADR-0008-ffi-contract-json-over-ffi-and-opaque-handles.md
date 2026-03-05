# ADR-0008: FFI Contract (Opaque Handles + JSON-over-FFI) and v0.1.x Stability

Status: Draft
Date: 2026-03-04
Owner: entarch

## Context

seclusor is a Rust library-first project with Go and TypeScript consumers.
Bindings must be thin adapters over the same semantics as the Rust crates
(ADR-0006), and schema-first external contracts apply (ADR-0005).

We need an FFI contract that:

- is safe across the C ABI boundary (memory ownership, panic containment)
- avoids re-implementing domain logic in Go/TS
- supports complex structured results without a brittle field-by-field ABI
- can be packaged across platforms (DDR-0001)

The workspace plan (D6) also needs a clear stability rule for downstream
consumers once Go bindings ship.

## Decision

Adopt a hybrid FFI shape:

- **Opaque handles** for stateful objects / cached state.
- **JSON-over-FFI** for complex inputs/outputs.
- **Result codes + thread-local last error** for diagnostics.
- **Panic-safe boundary**: do not unwind across FFI.

### Stability policy (v0.1.x)

Once v0.1.0 ships with Go bindings, treat `seclusor-ffi` as a stable ABI surface
for the v0.1.x line:

- No breaking changes to exported C symbols, signatures, result codes, or
  ownership rules within v0.1.x.
- Any breaking FFI change requires v0.2.0 (or later) and coordinated downstream
  updates.

This is a *time-bound commitment* tied to the v0.1.0 MVP push (D6).

## Contract Rules

### Ownership and lifetimes

- Any `char*` returned by seclusor MUST be freed by the caller via
  `seclusor_free_string()`.
- Any opaque handle returned by seclusor MUST be freed by the caller via the
  corresponding `*_free()` function.
- Callers MUST NOT free handles or strings by other means.

### Threading

- `seclusor_last_error()` is **thread-local**; callers must read it from the
  same OS thread that observed the failing return code.

### Errors and secrecy

- Return a `SeclusorResult` code for control flow.
- Provide a diagnostic string via `seclusor_last_error()`.
- Error strings MUST NOT include plaintext secrets, passphrases, key material,
  or decrypted payloads.

### JSON-over-FFI payloads

- JSON returned over FFI is treated as an external contract.
- For v0.1.x, JSON shapes returned by stable APIs MUST be backward compatible.
- Prefer additive evolution (new fields) over breaking changes.

### Opaque handles

- Handles are intentionally not introspectable from C/Go/TS.
- Handles may encapsulate Rust types and invariants.

## Rationale

- JSON-over-FFI reduces ABI brittleness for complex domain objects.
- Opaque handles keep long-lived state and invariants on the Rust side.
- Result codes + last error support C/Go/TS idioms while keeping stdout purity.
- A v0.1.x stability commitment prevents downstream churn during MVP adoption.

## Consequences

- We must be conservative about adding/removing/changing exported symbols.
- Any needed FFI refactor after v0.1.0 likely implies a v0.2.0 boundary.
- ADR-0009 (error model) should define the long-term mapping and compatibility
  story for `SeclusorResult`. Deferred to v0.1.1 — the current mapping is
  compiler-enforced via exhaustive `From` impls and the v0.1.x stability
  commitment here covers result code values. Formalizing the mapping after D6
  keyring APIs settle avoids premature documentation.

## Implementation Notes

- The current `crates/seclusor-ffi/src/lib.rs` follows this hybrid approach
  (handles + JSON returns + thread-local last error + `catch_unwind`).
- Build/release workflows should sync `crates/seclusor-ffi/seclusor.h` and
  prebuilt artifacts into language bindings (see `Makefile` targets).
