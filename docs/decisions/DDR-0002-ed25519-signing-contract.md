# DDR-0002: Ed25519 Signing Contract

Status: Accepted  
Date: 2026-03-17  
Owner: entarch

## Context

D11 needs a short, normative contract that Rust implementation work can follow
now and that D11B can inherit later for FFI, Go, and TypeScript parity.

This contract is programmatic first. JSON Schema is not canonical here unless a
later item standardizes an interchange artifact.

## Decision

The `v0.1.1` signing contract is:

| Element       | Contract     |
| ------------- | ------------ |
| Algorithm     | Ed25519      |
| Mode          | Plain only   |
| Secret key    | 32-byte seed |
| Public key    | 32 bytes     |
| Signature     | 64 bytes     |
| Message input | Opaque bytes |

The implementation boundary is also fixed:

- `SigningSecretKey` stores the canonical 32-byte seed, not backend-owned key
  state
- No PEM, PKCS#8, OpenSSH, or auto-detected file formats
- No X25519/Ed25519 key conversion
- No secret-key `Debug`, `Display`, or serde by default
- No key bytes, message bytes, or signature bytes in error strings

The error surface must distinguish these cases:

- `InvalidSecretKeyBytes` for non-32-byte secret-key input
- `InvalidPublicKeyBytes`
- `InvalidSignatureBytes` for non-64-byte signature input
- `SignatureVerificationFailed` for signatures that fail verification,
  including semantically invalid 64-byte signatures surfaced only at verify
  time

Notes on the fixed-width contract:

- Any 32-byte value is structurally acceptable as an Ed25519 seed.
- `InvalidPublicKeyBytes` remains the only parse-time structural validation case
  beyond fixed width.

## Consequences

- D11 and D11B have one stable byte contract to align to.
- Future bindings or interchange artifacts should adapt to this contract rather
  than redefining it.
- If the contract ever changes, it should be done explicitly in a superseding
  decision record.

## Notes

This DDR captures the signing contract only. Crate placement, feature gating,
backend choice, and release scoping live in
[ADR-0011](ADR-0011-ed25519-signing-in-seclusor-crypto.md).
