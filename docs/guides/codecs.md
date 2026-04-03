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
seclusor secrets convert --file secrets.json --to-codec bundle --recipient age1...
seclusor secrets convert --file secrets.age --to-codec inline --recipient age1...
```

Use `seclusor secrets convert` to switch formats.

## Scenarios

For end-to-end workflows using each codec:

- [Bundle Credentials](scenarios/bundle-credentials.md) — full init → encrypt → run workflow
- [Inline Credentials](scenarios/inline-credentials.md) — inline encrypt with git workflow
