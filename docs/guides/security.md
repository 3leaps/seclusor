# Security Model

Seclusor defaults are fail-closed for malformed secrets data and dangerous key paths.

## Core guardrails

- strict schema and credential-shape validation
- size limits enforced before or during reads to prevent unbounded allocation
- redaction-by-default for `secrets get`
- stdout purity: data on stdout, diagnostics on stderr
- secret key material blocked from CLI args by policy (see SDR-0002)

## Recommended operational practices

- keep identity files outside repository roots
- use dedicated key storage paths with restrictive permissions
- review release artifacts and signatures before publish
