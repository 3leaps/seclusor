# ADR-0002: age as Default Encryption Backend

Status: Accepted (carried forward)  
Date: 2026-02-28

## Context

seclusor encrypts secrets intended to be tracked in git, while supporting:

- offline use
- multi-recipient (team + CI) encryption
- simple, hard-to-misuse cryptographic APIs
- cross-platform operation without external binaries

## Decision

Use **age** as the default encryption backend.

Supported keying modes:

- **X25519 recipients (preferred)**: encrypt to one or more recipients; decrypt
  with corresponding identity file(s)
- **scrypt passphrase (supported)**: encrypt/decrypt with a passphrase via age
  scrypt

Rust implementation:

- Prefer the Rust `age` crate as the implementation backend.

## Rationale

- Modern design focused on file encryption workflows.
- Multi-recipient encryption is first-class.
- Simple API reduces misuse risk.
- Permissive licensing.

## Consequences

- Key/identity lifecycle (distribution, rotation, revocation) becomes a
  documented operational concern.
- If we need compatibility with other encryption schemes, it is an explicit
  migration/import feature.

## Notes

This decision is carried forward from a prior internal Go implementation
(unpublished) and adapted to Rust.
