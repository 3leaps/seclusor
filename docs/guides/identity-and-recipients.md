# Identity Files and Recipients

Seclusor uses [age](https://age-encryption.org/) encryption, which has two
complementary concepts: **identities** (private keys for decryption) and
**recipients** (public keys for encryption).

## Identities

An identity file contains one or more age secret keys. It is the private
half of an age keypair — anyone who has the identity file can decrypt
secrets encrypted to the corresponding recipient.

```
# created: 2026-03-30T12:00:00Z
# public key: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
AGE-SECRET-KEY-1QFWZNC...
```

### Generating an identity

```bash
# Passphrase-protected (recommended for non-ephemeral environments):
seclusor keys age identity generate --output ~/.config/seclusor/identity.txt --passphrase

# Plaintext (for automated pipelines with hardware-secured storage):
seclusor keys age identity generate --output ~/.config/seclusor/identity.txt
```

Both forms print the corresponding recipient (public key) to stdout.
Share the recipient freely; keep the identity file private.

### File permissions

On **Unix** (Linux, macOS), identity files must have mode `0600` (read/write
for owner only) **and** be owned by the current user. Seclusor enforces both
checks before loading — wrong mode or ownership fails with a clear error
that never includes key material. Generated identity files are created with
`0600` atomically.

On **Windows**, there is no equivalent mode/ownership preflight. Protect
identity files using NTFS ACLs or by storing them in a user-only directory.

### File size limit

Identity files are limited to 1 MB. This is a safety check against
accidentally passing a large file.

### Path restrictions

Seclusor refuses to write identity files under the repository root
(pathguard). This prevents accidentally committing private keys. Store
identity files outside your repository — `~/.config/seclusor/` is a
good default.

### Passphrase-protected identities

A passphrase-protected identity file encrypts the secret key at rest using
age's scrypt passphrase mode. The public key remains visible in a header
comment so you can encrypt without decrypting the identity. This is the
equivalent of an SSH key with a passphrase.

```
# This is a passphrase-protected seclusor identity file.
# Public key: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
# To use this identity, you will be prompted for a passphrase.
-----BEGIN AGE ENCRYPTED FILE-----
<scrypt-encrypted identity>
-----END AGE ENCRYPTED FILE-----
```

When you use a protected identity, seclusor detects the format
automatically and prompts for the passphrase. For non-interactive
environments (CI, automation), provide the passphrase via:

| Channel              | Flag                     | Use case                       |
| -------------------- | ------------------------ | ------------------------------ |
| Interactive prompt   | `--passphrase`           | Developer workstation          |
| Environment variable | `--passphrase-env VAR`   | CI/automation                  |
| File                 | `--passphrase-file PATH` | Local dev (0600, owned by you) |
| Stdin pipe           | `--passphrase-stdin`     | Automation chaining            |

Only one passphrase channel can be used per command. If a protected identity
is detected and no channel is specified, seclusor auto-prompts if a terminal
is available.

**When to use each**:

- **Passphrase-protected**: shared infrastructure, backups, laptops,
  compliance environments — anywhere the identity file might be exposed
- **Plaintext**: automated pipelines with hardware-secured storage,
  ephemeral environments where passphrase management adds friction
  without security benefit

**Migrating to passphrase-protected**: generate a new protected identity,
add the new recipient to your recipient set, and rekey existing bundles.
The old plaintext identity can then be securely deleted.

### Selecting an identity

Decryption commands accept **exactly one** of these selectors (Clap conflict;
not silent precedence):

| Flag                              | Meaning                                                          |
| --------------------------------- | ---------------------------------------------------------------- |
| `--identity-file <path>`          | Explicit path to an identity file (repeatable)                   |
| `--identity-public-key <age1...>` | Look up the identity file whose header advertises this recipient |

`--identity-public-key` is validated as a well-formed age recipient (`age1...`)
at argument parse time. Secret identity material (`AGE-SECRET-KEY-...`) is
never accepted on the CLI.

#### Public-key discovery (bounded)

Lookup uses **public header metadata only** (`# public key: age1...` /
`# Public key: age1...`, case-insensitive). It does **not** decrypt candidate
identity files while searching. After a unique path match, only that file is
loaded (with the usual permission/ownership preflight and optional passphrase
channels). After load, seclusor verifies that a loaded identity actually
derives the requested public key (header comments are untrusted).

Search roots are **bounded** and non-recursive. Seclusor never walks `$HOME`,
`$PATH`, or arbitrary environment-driven trees.

For each config root:

1. `<config>/identities/` — any non-hidden **regular file** (not a symlink)
2. `<config>/` itself — only compatibility filenames:
   `identity`, `identity.txt`, `identity*.txt`, `*.identity` (case-insensitive)

**Config root resolution** (primary first):

1. Absolute `$XDG_CONFIG_HOME/seclusor` when set (relative values are ignored)
2. Platform primary:
   - **macOS**: `~/Library/Application Support/seclusor`
   - **Linux / other Unix**: `~/.config/seclusor`
   - **Windows**: `%APPDATA%\seclusor` (fallback: `%USERPROFILE%\.config\seclusor`)
3. **macOS compatibility root** (only when absolute `XDG_CONFIG_HOME` is
   **unset**): `~/.config/seclusor`

On macOS, setting an absolute `XDG_CONFIG_HOME` **replaces** Application
Support as the discovery root — it is not additive, and the
`~/.config/seclusor` compatibility root is also suppressed in that case.

**Symlinks**: discovery **skips** symlinks (`DirEntry` file-type check does
not follow links). Explicit `--identity-file` still opens the path you pass
(and thus may follow a symlink). If you symlink an identity into a discovery
root, `--identity-public-key` will not find it; use `--identity-file` or place
a regular file in a documented root.

**Ambiguity / no match**: two files advertising the same public key is a hard
error listing both paths; zero matches is a hard error. There is no
decrypt-everything fallback.

```bash
# Explicit path
seclusor secrets list --file secrets.age --identity-file ~/.config/seclusor/identity.txt

# Public-key lookup (file must live under a discovery root with a public-key comment)
seclusor secrets list --file secrets.age --identity-public-key age1...your-recipient...
```

## Recipients

A recipient is an age public key, formatted as `age1...`. It is the public
half of an age keypair — anyone can encrypt to a recipient, but only the
holder of the corresponding identity can decrypt.

### Providing recipients

Recipients can come from three sources:

| Source          | Flag                  | Example                                   |
| --------------- | --------------------- | ----------------------------------------- |
| Directly        | `--recipient`         | `--recipient age1ql3z7hjy...`             |
| From a file     | `--recipient-file`    | `--recipient-file recipients.txt`         |
| From an env var | `--recipient-env-var` | `--recipient-env-var SECLUSOR_RECIPIENTS` |

Multiple `--recipient` flags can be specified for multi-recipient encryption.
Any holder of any listed identity can decrypt the result.

Recipient files use the same format as identity files: one key per line,
`#` comments, blank lines ignored.

### Finding your recipient

When you generate an identity, the corresponding recipient is printed to
stdout. You can also extract it from an existing identity file:

```bash
grep -i '^# public key:' ~/.config/seclusor/identity.txt
```

## How they work together

```
                    ┌──────────────┐
  encrypt ─────►   │   recipient  │   (public key: age1...)
                    │  (age1...)   │
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
                    │  ciphertext  │   (encrypted secret)
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
  decrypt ─────►   │   identity   │   (private key: AGE-SECRET-KEY-...)
                    │  (secret)    │
                    └──────────────┘
```

- **Encrypting** (`bundle encrypt`, `inline encrypt`): requires one or more
  `--recipient` flags. No identity needed.
- **Decrypting / encrypted reads** (`get`, `list`, `validate`, `export-env`,
  `run`, `bundle decrypt`, `inline decrypt`): require `--identity-file` or
  `--identity-public-key` when the input is a bundle (and for full inline
  decryption). See [CLI reference](cli-reference.md) for validate modes.
- **Converting** (`convert`): requires both — identity to decrypt the
  source, recipient to re-encrypt in the target format.

## Multi-recipient encryption

Encrypt to multiple recipients so that any of their identities can decrypt:

```bash
seclusor secrets bundle encrypt \
  --input secrets.json \
  --output secrets.age \
  --recipient age1ql3z7hjy...alice... \
  --recipient age1xyz...bob...
```

Both Alice and Bob can decrypt `secrets.age` with their respective identity
files. To change who can decrypt, re-encrypt with a different recipient set
(rekeying — `seclusor secrets rekey`, and library APIs).

## Common workflows

### Single developer

```bash
# One-time setup
seclusor keys age identity generate --output ~/.config/seclusor/identity.txt
# Note the age1... recipient printed to stdout

# Encrypt
seclusor secrets bundle encrypt \
  --input secrets.json --output secrets.age \
  --recipient age1...your-recipient...

# Decrypt and use
seclusor secrets run \
  --file secrets.age \
  --identity-file ~/.config/seclusor/identity.txt \
  --project myapp \
  -- ./my-command
```

### Team sharing

Each team member generates their own identity. Collect all recipients into
a shared file:

```
# recipients.txt — commit this to the repo
# alice
age1ql3z7hjy...
# bob
age1xyz...
```

Encrypt for the team:

```bash
seclusor secrets bundle encrypt \
  --input secrets.json --output secrets.age \
  --recipient-file recipients.txt
```

Any team member can decrypt with their own identity file.

## Platform notes

| Platform | Permission enforcement | Notes                                |
| -------- | ---------------------- | ------------------------------------ |
| Linux    | `0600` enforced        | `chmod 600 identity.txt`             |
| macOS    | `0600` enforced        | Same as Linux                        |
| Windows  | Not enforced           | Use NTFS ACLs or user-only directory |

## Troubleshooting protected identities

When decrypting with a passphrase-protected identity:

- **`wrong passphrase or corrupted identity file`** means seclusor could
  not unlock the identity file with the supplied passphrase.
- **`decryption failed`** means the identity unlocked successfully, but
  it does not match the ciphertext's recipient set.

In migration workflows, this usually means you are trying an old identity
against ciphertext encrypted for a new recipient.

## See also

- [Workflow Scenarios](scenarios/index.md) — end-to-end guides for common use cases
- [Team Recipients](scenarios/team-recipients.md) — multi-recipient team workflows
- [CI/Automation](scenarios/ci-automation.md) — passphrase channels in non-interactive pipelines
- [Security model](security.md) — threat model, safety defaults, and
  secret handling
- [CLI reference](cli-reference.md) — full command and flag documentation
- [Key management guide](key-management.md) — rekeying and recipient rotation
- [App Note 01](../appnotes/01-git-armored-storage.md) — storing encrypted
  files in git
