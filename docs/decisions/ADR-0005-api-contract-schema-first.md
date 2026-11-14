# ADR-0005: API Contract Is Schema-First

Status: Accepted (carried forward; Rust-adapted; standalone server mode retired per ADR-0013)  
Date: 2026-02-28 (updated 2026-11-13)

## Context

seclusor has multiple consumers:

- Rust library dependents
- CLI users
- Go and TypeScript bindings
- _(historical: a potential future server mode was initially considered and later retired in [ADR-0013](ADR-0013-value-free-control-plane-and-mcp-boundary.md))_

We need a single source of truth (SSOT) for:

- document formats (secrets, config, env export shapes)

## Decision

We are schema-first for external contracts:

- **v0.1.0+**: JSON Schema is the SSOT for file/document formats (secrets, signature envelopes, and config).
- _(historical: OpenAPI for a standalone HTTP server mode was reserved here and retired in [ADR-0013](ADR-0013-value-free-control-plane-and-mcp-boundary.md).)_

Posture:

- Generated or derived types are treated as a boundary, but runtime input
  validation remains mandatory (sizes, required fields, and semantic constraints).

## Rationale

- Contract-first makes multi-client development reliable (CLI, scripts, bindings).
- Schema tooling supports docs, linting, and compatibility checks.
- Avoids drift between hand-written models and published schemas.

## Consequences

- Schema changes are made by editing the schema artifact first.
- CI should validate schema artifacts (lint + consistency checks).

## Notes

This decision is carried forward from a prior internal Go implementation
(unpublished).
The Rust rewrite adopts JSON Schema as the SSOT for file and document formats;
standalone server-mode HTTP APIs were later retired in
[ADR-0013](ADR-0013-value-free-control-plane-and-mcp-boundary.md).
