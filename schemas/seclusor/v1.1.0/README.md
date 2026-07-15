# seclusor Schema v1.1.0

Additive secrets-document schema revision for whole-document recipient metadata.

## Changes from v1.0.0

- `schema_version` enum value: `"v1.1.0"`
- Optional top-level `recipients` array of age X25519 public keys
  (`^age1[0-9a-z]+$`, sorted, unique, max 64)

## Compatibility

- Runtime validation accepts both v1.0.0 (no `recipients`) and v1.1.0 documents.
- Documents that carry `recipients` **must** declare `schema_version: "v1.1.0"`.
- Older binaries reject documents with the `recipients` field (`deny_unknown_fields`) — fail-closed, safe direction.
- See ADR-0012 for rewrite-on-establish and carrier integrity posture.
