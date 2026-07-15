# ADR-0012: Document Recipients Metadata (Schema v1.1.0)

Status: Accepted  
Date: 2026-07-14

## Context

Write-side operations on encrypted secrets files need a **canonical recipient
set** per document. Age X25519 headers do not carry the operator’s chosen
public keys, so recipient stanzas cannot be used as a preservation source.
Seclusor-maintained recipient metadata is required (hybrid resolution: explicit
flags → document metadata → fail closed).

Schema evolution is schema-first per ADR-0005.

## Decision

### Carrier

Add an optional top-level field to the secrets document:

```text
recipients: [<age1 public key>, ...]   # sorted, deduped, non-empty when present
```

One carrier for both codecs:

| Codec  | Integrity of `recipients`                                       |
| ------ | --------------------------------------------------------------- |
| Bundle | Field rides **inside** ciphertext → authenticated by encryption |
| Inline | Plaintext-visible JSON → git-tracked history (public keys only) |

Sidecar recipient files (e.g. `<file>.recipients`) are **rejected**.

### Schema version

- Additive optional field ⇒ schema **v1.1.0** (`schemas/seclusor/v1.1.0/`).
- **v1.0.0 remains frozen** and valid for documents without `recipients`.
- Runtime validators accept both v1.0.0 and v1.1.0 documents (cross-version
  acceptance).
- A document that carries `recipients` with `schema_version: "v1.0.0"` is
  **invalid** under both schemas.

### Rewrite-on-establish

When an establishing encrypting write persists `recipients` into a former
v1.0.0 document, it **must** also rewrite declared `schema_version` to
`v1.1.0`. Establishing writes that leave untouched encrypted fields on inline
documents are refused (establishment coverage rule); those cases route to the
dedicated rekey command.

### Compatibility

- Documents with `recipients` will not parse on older binaries
  (`deny_unknown_fields`) — fail-closed, safe direction.
- Documents without the field remain valid on both old and new binaries.
- CHANGELOG / app note must document this when the write path ships.

### Integrity posture (honest)

- **Bundle:** metadata authenticated by encryption.
- **Inline:** not cryptographically authenticated; integrity relies on git
  history plus tripwires (stanza-count, equality checks). Detect-and-warn on
  read; fail closed on encrypting write when divergence is detected.

## Consequences

- `SecretsFile` gains `recipients: Option<Vec<String>>`.
- Validation enforces sorted, unique, bounded, structurally valid age keys.
- Library consumers (including existing read loaders) must accept v1.1.0 docs
  with no behavior change beyond acceptance.
- Recipient **mutation** remains out of band for value-write commands
  (dedicated rekey only).

## References

- ADR-0005 schema-first API contract
- Rekey CLI command (dedicated recipient-set rewrite)
