# ADR-0006: DRY Core for Library + CLI/Server + Bindings, and Stdout Purity

Status: Accepted (carried forward; Rust-adapted)  
Date: 2026-02-28

## Context

seclusor must provide meaningful functionality as:

- a Rust library (direct dependency for lanyte-attest / CRT-012)
- a CLI (bootstrap, validate, export env, inject secrets safely)
- future server/daemon transports (serve, UDS agent, etc.)
- Go and TypeScript libraries via bindings

All transports must implement the same semantics (validation, filtering,
redaction rules, size limits, and secret handling policies) while differing only
in transport concerns (args/env parsing, IO, request/response rendering).

CLI output must support automation:

- machine-readable output on stdout when requested
- logs and diagnostics on stderr

## Decision

### DRY core, transport-agnostic semantics

- Implement transport-agnostic logic in Rust library crates (core/crypto/codec/keyring).
- CLI commands, server handlers, and FFI exports are thin adapters over the same library APIs.
- Transport layers must not re-implement filtering/redaction/validation rules.

### Stdout purity (CLI)

- Data output goes to stdout.
- Logs/diagnostics/prompts go to stderr.
- `--format json` outputs JSON to stdout and nothing else.

## Rationale

- Prevents drift between library/CLI/server/bindings behaviors.
- Makes dogfooding feasible: the CLI exercises the same domain logic that other
  transports expose.
- Reduces accidental secret leakage via logs or mixed stdout output.
- Ensures lanyte-attest can link directly to seclusor crates without a CLI hop.

## Consequences

- Library crates must not depend on transport code (CLI/FFI/server).
- Transport layers must avoid stdout writes outside the data payload.
- Error messages surfaced across FFI and CLI must be safe (no plaintext secrets).

## Notes

This decision is carried forward from a prior internal Go implementation
(unpublished) and expanded to explicitly
cover “library-first + bindings” as first-class transports for the Rust rewrite.
