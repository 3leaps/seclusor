# ADR-0005: API Contract Is Schema-First

Status: Accepted (carried forward; Rust-adapted)  
Date: 2026-02-28

## Context

seclusor has multiple consumers:

- Rust library dependents (e.g. lanyte-attest)
- CLI users
- Go and TypeScript bindings
- potential future server mode (control plane + data plane)

We need a single source of truth (SSOT) for:

- document formats (secrets, config, env export shapes)
- request/response schemas (when HTTP APIs exist)
- authentication requirements (when HTTP APIs exist)

## Decision

We are schema-first for external contracts:

- **v0.1.0**: JSON Schema is the SSOT for file/document formats (secrets and config).
- **Future server mode**: OpenAPI becomes the SSOT for HTTP API contracts when introduced.

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
The Rust rewrite expands schema-first to include JSON Schema for file formats in
v0.1.0, while reserving OpenAPI for later server-mode APIs.
