# Workflow Scenarios

Each scenario is a self-contained, end-to-end guide that walks you from
credential creation to runtime use. Pick the one that fits your situation.

## Choosing your encryption mode

```
What are you encrypting?
├── A credentials file (JSON with multiple named secrets)
│   ├── Need git-friendly diffs and structure visibility? → inline
│   └── Maximum security / opaque ciphertext? → bundle (recommended)
└── An arbitrary file (script, cert, config, binary token)
    └── blob
```

- **Bundle** encrypts the entire secrets document as a single opaque `.age`
  file. No metadata leakage. Best for most use cases.
  See [Bundle Credentials](bundle-credentials.md).

- **Inline** encrypts each value individually as `sec:age:v1:` markers
  inside a readable JSON document. Structure and key names remain visible.
  Best for git diffs and code review of low-sensitivity data.
  See [Inline Credentials](inline-credentials.md).

- **Blob** encrypts any file (shell scripts, TLS certs, SSH configs, binary
  tokens) as raw bytes with no parsing or schema.
  See [Blob Encryption](blob-encryption.md).

For a detailed comparison of bundle vs inline tradeoffs, see
[Storage Codecs](../codecs.md).

## Identity setup

Before encrypting or decrypting, you need an age identity (private key) and
its corresponding recipient (public key).

### Path A: Passphrase-protected identity (recommended)

Best for developer workstations, shared infrastructure, and compliance
environments where the identity file might be exposed.

```bash
seclusor keys age identity generate \
  --output ~/.config/seclusor/identity.txt \
  --passphrase
# Note the age1... recipient printed to stdout — save it
```

You will be prompted for the passphrase whenever you decrypt.

### Path B: Plaintext identity

Best for automated pipelines with hardware-secured storage or ephemeral
environments where passphrase management adds friction without security
benefit.

```bash
seclusor keys age identity generate \
  --output ~/.config/seclusor/identity.txt
# Note the age1... recipient printed to stdout — save it
```

### Path C: Scoped identities

Use separate identities per environment (dev, staging, production) to limit
blast radius if one is compromised. Generate one identity per environment
and manage recipients accordingly.

```bash
seclusor keys age identity generate --output ~/.config/seclusor/identity-dev.txt --passphrase
seclusor keys age identity generate --output ~/.config/seclusor/identity-prod.txt --passphrase
```

For full details on identities, recipients, permissions, and passphrase
channels, see [Identity Files and Recipients](../identity-and-recipients.md).

## Scenarios

| Scenario                                    | When to use                                      |
| ------------------------------------------- | ------------------------------------------------ |
| [Bundle Credentials](bundle-credentials.md) | Structured secrets (JSON) with maximum security  |
| [Inline Credentials](inline-credentials.md) | Structured secrets with git-friendly diffs       |
| [Blob Encryption](blob-encryption.md)       | Encrypt any file (scripts, certs, configs)       |
| [CI/Automation](ci-automation.md)           | Non-interactive pipelines (GitHub Actions, etc.) |
| [Team Recipients](team-recipients.md)       | Multi-recipient encryption for teams             |
| [Quick Reference](quick-reference.md)       | "I want to..." command lookup table              |
