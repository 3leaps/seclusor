# Security Model

Seclusor is a security-sensitive library and tool for managing encrypted secrets with age (**alpha** — subject to change). Defaults are fail-closed for malformed data, dangerous paths, and unsafe operations.

## Core Guardrails

- Strict schema and credential-shape validation
- Size limits enforced before allocation (16 MiB decrypt, 1 MiB inline)
- Redaction-by-default for `secrets get` (requires `--reveal`)
- Hidden-by-default terminal input for `secrets set --value-stdin` so typed
  secrets do not appear on screen; visible terminal entry requires
  `--echo-value`, while pipes remain unchanged
- Stdout purity: data on stdout, diagnostics and prompts on stderr
- Secret key material blocked from CLI arguments (see SDR-0002)
- Ciphertext prefix validation (`sec:age:v1:`)
- Identity file permission checks (0600 on Unix)
- Asset signature verification is fail-closed by default: callers must provide
  an expected public key or fingerprint unless they explicitly opt into
  embedded-key self-consistency checks.

## Key Rotation and Rekeying

Rekeying changes the recipient set on existing bundle or inline-encrypted
documents without writing a plaintext working copy to disk. Use
`seclusor secrets rekey` from the CLI, or the rekeying APIs in
`seclusor-keyring`. Ordinary `secrets set` / `import-env` preserve an
established recipient set and refuse ambiguous membership changes.

When schema v1.1.0 recipient metadata is present, write paths compare the
write-target recipient set to document metadata and **fail closed** on
divergence (`+age1…` / `-age1…` lines). Intentional membership changes require
`--allow-recipient-mismatch` on the same command (recipient-set only). The
guard reports a set difference; it does not classify “re-grant” vs intentional
add. On legacy v1.0.0 documents (no recorded recipient set) the comparison is
indeterminate. Seclusor establishes metadata only when the operation covers
every inline encrypted field or writes a bundle; a partial inline write instead
refuses and directs you to `secrets rekey`. After rekey, name durable recipient
sources explicitly with `--write-recipients PATH` so a later write does not
restore a retired recipient from a stale list.

Documents that establish top-level `recipients` metadata use schema v1.1.0.
Older strict readers fail closed on those documents; documents without
`recipients` remain compatible with older binaries.

See `docs/guides/key-management.md` for the full rekeying workflow and
[App Note 04](../appnotes/04-encrypted-write-operations.md) for write-path
residuals (including inline metadata integrity and same-count membership
limits).

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

### `secrets run` and passphrase channels

Prefer **`--passphrase-file`** or **`--passphrase-stdin`** when launching
commands with `secrets run`. The `--passphrase-env` channel is supported for
CI, but:

- the named variable is excluded from the **child** environment (v0.2.1+);
- the passphrase still resides in the **parent** `seclusor` process environment
  for the lifetime of that invocation;
- `--allow` / `--deny` filter injected store keys only — they never controlled
  ambient environment pass-through.

Do not treat `--passphrase-env` as equivalent to file or stdin channels.

There is one narrow recovery exception on v0.2.1 and later. An identity created
with a CRLF-terminated passphrase file on v0.2.1 or earlier may require the
retained carriage-return byte. Supply that exact legacy value through
`--passphrase-env` only long enough to unlock the identity, generate a
replacement identity using normalized file or stdin input, rekey encrypted data
to the replacement recipient, retire the legacy identity, and unset the
variable. Do not use this environment recovery workflow with `secrets run` on
v0.2.0 or earlier, where the named variable can reach the child process.

## Compromise Response

If an identity or recipient key is believed compromised:

1. Immediately stop using the affected identity.
2. **Upgrade to a patched seclusor** before rotating when a security release is
   available (recipient divergence is fail-closed on current releases).
3. Generate new identities and recipients.
4. Rekey all affected armored files (bundle or inline), refreshing durable
   recipient lists with `--write-recipients` (or rewrite and verify them by
   hand) **before any further encrypted write**.
5. Update any systems using the old keys.
6. Audit git history if files were stored in version control (see App Note 01).
7. If a process may have seen an identity passphrase via the environment,
   treat credentials that process could reach as compromised, not only those
   it was deliberately given.

Old ciphertexts remain decryptable by the compromised key until rekeyed.
Removing an identity file locally is not revocation while stores remain
encrypted to that recipient.

## File Integrity and Signatures

- Bundle files are protected by age's authenticated encryption (ChaCha20-Poly1305).
- Seclusor can sign arbitrary release assets with detached
  `seclusor.signature.v1` JSON envelopes via `seclusor assets sign`.
- Verification streams the candidate asset, checks its SHA-256 digest against
  the envelope, validates the embedded Ed25519 public key and fingerprint, and
  then verifies the signature over the DDR-0004 canonical payload.
- Verification requires `--public-key` or `--fingerprint` by default.
  `--trust-embedded-key` proves only that the asset and envelope are
  self-consistent under the embedded key.
- `claimed_at` is signed metadata for operator context. It is not trusted time
  evidence; trusted timestamping is a separate future feature.

## Responsible Disclosure

See `SECURITY.md` (at repository root) for the full responsible disclosure policy and contact instructions.

Please report potential vulnerabilities privately to `security@3leaps.net` or @3leapsdave. Do **not** open public GitHub issues for security concerns.

## Operational Practices

- Keep identity files outside repository roots.
- Use dedicated, permission-restricted paths for keys (`0600` and current-user
  ownership on Unix).
- Regularly run `cargo audit` and monitor upstream `filippo.io/age` releases.
- Review release artifacts and signatures before distribution.

For key management workflows see [Key Management](key-management.md).  
For storage risk guidance see [App Note 01: Git Storage of Armored Secrets](../appnotes/01-git-armored-storage.md).  
For CI/automation security patterns see [CI/Automation Scenario](scenarios/ci-automation.md).
