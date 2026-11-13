# ADR-0006: DRY Core for Library + CLI/Server + Bindings, and Stdout Purity

Status: Accepted (carried forward; Rust-adapted; standalone server mode retired per ADR-0013)  
Date: 2026-02-28 (updated 2026-11-13)

## Context

seclusor must provide meaningful functionality as:

- a Rust library
- a CLI (bootstrap, validate, export env, inject secrets safely)
- Go and TypeScript libraries via bindings (or native twin implementations)
- _(historical: future server/daemon transports were initially considered and later retired in [ADR-0013](ADR-0013-value-free-control-plane-and-mcp-boundary.md))_

All transports must implement the same semantics (validation, filtering,
redaction rules, size limits, and secret handling policies) while differing only
in transport concerns (args/env parsing, IO, request/response rendering).

CLI output must support automation:

- machine-readable output on stdout when requested
- logs and diagnostics on stderr

## Decision

### DRY core, transport-agnostic semantics

- Implement transport-agnostic logic in Rust library crates (core/crypto/codec/keyring).
- CLI commands and FFI/binding exports are thin adapters over the same library APIs _(standalone server handlers retired per [ADR-0013](ADR-0013-value-free-control-plane-and-mcp-boundary.md))_.
- Transport layers must not re-implement filtering/redaction/validation rules.

### Stdout purity (CLI)

- Data output goes to stdout.
- Logs/diagnostics/prompts go to stderr.
- Structured/JSON logging (when enabled) goes to stderr — never stdout, even
  though it is structured data. Stdout is exclusively for programmatic command
  output.
- `--format json` outputs JSON to stdout and nothing else.
- Secret-bearing CLI argument policy is defined in
  [SDR-0002](SDR-0002-secret-input-channels-and-cli-arg-policy.md).
- Stdout purity must be verified by integration tests that assert, in default
  (non-verbose) mode, stderr is empty on successful commands and stdout
  contains no diagnostics.

### Context path logging (design requirement)

When diagnostic logging is enabled (e.g., `--verbose`, `SECLUSOR_LOG_LEVEL`),
the CLI and library crates must log the actual resolved filesystem path for
every significant file access:

- Secrets document loaded/written
- Identity file read
- Recipient file read
- Bundle ciphertext input/output
- Convert input/output

This supports debugging "which file did it actually resolve?" without requiring
the user to strace or instrument their own tooling. All path logging goes to
stderr via the `tracing` crate (deferred alongside structured logging
infrastructure; standalone server mode was later retired in
[ADR-0013](ADR-0013-value-free-control-plane-and-mcp-boundary.md)).

## Rationale

- Prevents drift between library/CLI/bindings behaviors.
- Makes dogfooding feasible: the CLI exercises the same domain logic that other
  transports expose.
- Reduces accidental secret leakage via logs or mixed stdout output.
- Ensures downstream Rust consumers can link directly to seclusor crates without a CLI hop.

## Consequences

- Library crates must not depend on transport code (CLI/FFI).
- Transport layers must avoid stdout writes outside the data payload.
- Error messages surfaced across FFI and CLI must be safe (no plaintext secrets).
- Transport adapters must not introduce secret-bearing CLI argument paths that
  violate [SDR-0002](SDR-0002-secret-input-channels-and-cli-arg-policy.md).
- Stdout purity must have integration test coverage before v0.1.0 release.
- Context path logging implementation requires `tracing` dependency wired
  through all library crates (v0.1.1).

## Notes

This decision is carried forward from a prior internal Go implementation
(unpublished) and expanded to explicitly cover “library-first + bindings” as
first-class transports for the Rust rewrite. Standalone `seclusor` server/daemon
mode (`serve`) was retired in
[ADR-0013](ADR-0013-value-free-control-plane-and-mcp-boundary.md); the DRY core
and CLI stdout-purity rules in this record remain normative across library
crates, CLI commands, and language bindings/twins.
