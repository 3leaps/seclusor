# ADR-0003: Storage Codecs (Bundle + Inline)

Status: Accepted (carried forward)  
Date: 2026-02-28

## Context

seclusor targets “git-trackable” workflows.

Two desirable properties are in tension:

- minimize metadata leakage (opaque ciphertext)
- make diffs/merges ergonomic (human-readable documents)

## Decision

Support two storage codecs:

1. **Bundle** (ship first):
   - whole-file opaque encryption with age
   - best default safety profile (lowest leakage)

2. **Inline** (SOPS-style; supported):
   - structured document (YAML/JSON) where secret values are encrypted per-field
   - key names and metadata remain plaintext
   - values become `sec:age:v1:<base64>`
   - best UX for git diffs/merges

Provide conversion between the two.

## Consequences

- Inline form leaks which keys exist and how they change (even when values
  remain protected).
- Bundle form requires a decrypt step to inspect or edit.
- Both forms rely on the same cryptographic backend and identity lifecycle.

## Notes

This decision is carried forward from a prior internal Go implementation
(unpublished) and remains a core differentiator for the Rust rewrite.
