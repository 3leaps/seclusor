# Security Model

Seclusor is a security-sensitive library and tool for managing encrypted secrets with age (**alpha** — subject to change). Defaults are fail-closed for malformed data, dangerous paths, and unsafe operations.

## Core Guardrails

- Strict schema and credential-shape validation
- Size limits enforced before allocation (16 MiB decrypt, 1 MiB inline)
- Redaction-by-default for `secrets get` (requires `--reveal`)
- Stdout purity: data on stdout, diagnostics and prompts on stderr
- Secret key material blocked from CLI arguments (see SDR-0002)
- Ciphertext prefix validation (`sec:age:v1:`)
- Identity file permission checks (0600 on Unix)

## Key Rotation and Rekeying

Rekeying allows you to change the recipient set on existing armored files
without decrypting the plaintext values. Rekeying functions are available
as a library API (`seclusor-keyring`); a CLI subcommand is planned.

See `docs/guides/key-management.md` for the full rekeying workflow.

## Identity Protection

Passphrase-protected identity files encrypt the secret key at rest using
age scrypt mode. This is the recommended default for non-ephemeral
environments — the same principle as SSH keys with passphrases.

```bash
# Generate a passphrase-protected identity
seclusor keys age identity generate --output ~/.config/seclusor/identity.txt --passphrase
```

For high-sensitivity keys (root keys, long-term signing keys, emergency
break-glass accounts), always use passphrase-protected identities and
store them outside of version control. See the
[identity and recipients guide](identity-and-recipients.md) for full
details on passphrase input channels and migration.

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

See `SECURITY.md` (at repository root) for the full responsible disclosure policy and contact instructions.

Please report potential vulnerabilities privately to `security@3leaps.net` or @3leapsdave. Do **not** open public GitHub issues for security concerns.

## Operational Practices

- Keep identity files outside repository roots.
- Use dedicated, permission-restricted paths for keys (`0600`).
- Regularly run `cargo audit` and monitor upstream `filippo.io/age` releases.
- Review release artifacts and signatures before distribution.

For key management workflows see [Key Management](key-management.md).  
For storage risk guidance see [App Note 01: Git Storage of Armored Secrets](../appnotes/01-git-armored-storage.md).  
For CI/automation security patterns see [CI/Automation Scenario](scenarios/ci-automation.md).
