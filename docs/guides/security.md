# Security Model

Seclusor is a security-sensitive library and tool for managing encrypted secrets with age. Defaults are fail-closed for malformed data, dangerous paths, and unsafe operations.

## Core Guardrails

- Strict schema and credential-shape validation
- Size limits enforced before allocation (16 MiB decrypt, 1 MiB inline)
- Redaction-by-default for `secrets get` (requires `--reveal`)
- Stdout purity: data on stdout, diagnostics and prompts on stderr
- Secret key material blocked from CLI arguments (see SDR-0002)
- Ciphertext prefix validation (`sec:age:v1:`)
- Identity file permission checks (0600 on Unix)

## Key Rotation and Rekeying

Rekeying allows you to change the recipient set on existing armored files without decrypting the plaintext values.

```bash
# Rekey a bundle to new recipients
seclusor secrets rekey --file secrets.age --identity-file old.txt --recipient age1...new1 --recipient age1...new2
```

See `docs/guides/key-management.md` for full rekeying workflow, especially for glassbreak credential archives.

## Compromise Response

If an identity or recipient key is believed compromised:

1. Immediately stop using the affected identity.
2. Generate new identities and recipients.
3. Rekey all affected armored files (bundle or inline).
4. Update any systems using the old keys.
5. Audit git history if files were stored in version control (see App Note 01).

Old ciphertexts remain decryptable by the compromised key until rekeyed.

## File Integrity and Signatures

**Current status**: Seclusor does not currently sign armored files or provide built-in fingerprinting.

- Bundle files are protected by age's authenticated encryption (ChaCha20-Poly1305).
- For additional integrity guarantees on high-value archives, consider signing the armored file with minisign, age signatures (future), or storing a separate manifest with hashes.
- Future enhancement: Add optional signature verification on bundle load.

## Responsible Disclosure

We take security issues seriously.

**Report security concerns** to the maintainers via:

- Email: security@3leaps.net (preferred for sensitive reports)
- GitHub: Open a private security advisory (if available) or contact @3leapsdave directly.

Please do **not** open public issues for potential vulnerabilities.

See `SECURITY.md` for full details.

## Operational Practices

- Keep identity files outside repository roots.
- Use dedicated, permission-restricted paths for keys (`0600`).
- Regularly run `cargo audit` and monitor upstream `filippo.io/age` releases.
- Review release artifacts and signatures before distribution.

For key management workflows see [Key Management](key-management.md).  
For storage risk guidance see [App Note 01: Git Storage](../appnotes/01-git-armored-storage.md).
