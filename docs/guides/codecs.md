# Storage Codecs

Seclusor supports two storage codecs. The choice has important security and usability tradeoffs.

- **`bundle`**: Whole-file age encryption (`.age`). Opaque ciphertext.
- **`inline`**: Per-value encryption inside a JSON document. Structure remains readable.

## Bundle (Recommended for most cases)

Best when security is the primary concern. No metadata leakage. Ideal for git, distribution, and runtime use.

Use for: high-sensitivity secrets, glassbreak credentials, production bundles.

## Inline

Best when you need good git diffs, code review, and partial visibility of structure.

**Warning**: Reveals which keys exist and when they change. Only suitable for low-sensitivity data.

See [App Note 01: Git Storage](../appnotes/01-git-armored-storage.md) for detailed risk guidance.

## Convert

```bash
seclusor secrets convert --input secrets.json --output secrets.age --from inline --to bundle --identity-file ./identity.txt --recipient age1...
seclusor secrets convert --input secrets.age --output secrets-inline.json --from bundle --to inline --identity-file ./identity.txt --recipient age1...
```

Use `seclusor secrets convert` to switch formats. Conversion requires an identity (to decrypt the source) and a recipient (to re-encrypt the target).

## Scenarios

For end-to-end workflows using each codec:

- [Bundle Credentials](scenarios/bundle-credentials.md) — full init → encrypt → run workflow
- [Inline Credentials](scenarios/inline-credentials.md) — inline encrypt with git workflow
