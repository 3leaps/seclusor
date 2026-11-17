# Blob Encryption

Encrypt any file — shell scripts, TLS certificates, SSH configs, binary
tokens, or anything else — as opaque age ciphertext. Blob encryption
operates on raw bytes with no parsing or schema.

**When to use**: The file is not a structured JSON secrets document. You
just need to encrypt and later decrypt an arbitrary file.

**Prerequisites**: An age identity and recipient.
See [identity setup](index.md#identity-setup) if you haven't generated one.

## 1. Encrypt a file

```bash
seclusor secrets blob encrypt \
  --input deploy-key.pem \
  --output deploy-key.pem.age \
  --recipient age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
```

The `.age` output is opaque ciphertext written atomically (`0600` permissions on
Unix). The original file format, name, and contents are not visible. If the
output path already exists, `blob encrypt` refuses to overwrite it unless
`--force` is supplied.

## 2. Transfer or store

The encrypted file can be:

- Committed to git (low/medium sensitivity — see
  [App Note 01](../../appnotes/01-git-armored-storage.md))
- Uploaded to cloud storage (S3, GCS, R2)
- Copied between machines via scp, rsync, or any file transfer

## 3. Decrypt

```bash
seclusor secrets blob decrypt \
  --input deploy-key.pem.age \
  --output deploy-key.pem \
  --identity-file ~/.config/seclusor/identity.txt
```

The decrypted output is written with `0600` permissions on Unix.

## 4. Verify a blob in memory

To verify that an identity can decrypt and authenticate a `.age` blob without
writing plaintext to disk:

```bash
seclusor secrets blob verify \
  --input deploy-key.pem.age \
  --identity-file ~/.config/seclusor/identity.txt
```

`blob verify` prints the opening recipient public key (`age1...`) on `stdout`
and exits `0` on success.

## 5. Rotate recipients (`blob rekey`)

To re-encrypt a blob to a new recipient set in memory (with a fresh file key and
no plaintext written to disk):

```bash
seclusor secrets blob rekey \
  --input deploy-key.pem.age \
  --identity-file ~/.config/seclusor/old-identity.txt \
  --prior-recipient age1oldrecipient... \
  --recipient-file ~/.config/seclusor/recipients.txt \
  --verify-identity-file ~/.config/seclusor/new-identity.txt \
  --write-recipients ~/.config/seclusor/recipients.txt \
  --allow-recipient-mismatch
```

- **Recipient comparison**: Blobs do not store recipient metadata inside the
  file. Pass `--prior-recipient` or `--prior-recipient-file` to assert the
  current set; `blob rekey` checks the asserted count against the age header
  stanza count and verifies that the opening identity is in the asserted prior
  set (it cannot detect same-count recipient swaps in the age header). If no
  `--prior-recipient*` is supplied, `--allow-recipient-mismatch` is required to
  accept indeterminate comparison.
- **Self-lockout protection**: Before replacing the target file, `blob rekey`
  decrypts and authenticates the newly encrypted ciphertext in memory using a
  loaded or `--verify-identity-*` private key in the target set (unless
  `--allow-self-lockout` is explicitly passed).
- **Important**: Rekeying a blob only protects future reads of the replaced
  file. Any party that held a compromised identity and its passphrase could
  already decrypt historical ciphertext copies; rotate the underlying secret
  values or credentials inside the blob at their provider as well.
- **Memory residual**: Decrypted plaintext is held in zeroizing process memory
  buffers during `blob rekey`, `blob rekey-batch`, and `blob verify` (not
  `mlock`ed against OS swap or core dumps; upstream `age` `StreamWriter` holds
  an internal 64 KiB chunk buffer in heap memory during encryption; and JSON
  bundle-refusal probing can leave `serde_json` string-unescape scratch in freed
  heap memory if an input contains JSON escape sequences).

## 6. Batch rotation across multiple blobs (`blob rekey-batch`)

When rotating recipients across a directory of `.age` blobs, use
`blob rekey-batch` so a passphrase-protected identity is unlocked once for the
entire batch. Plan mode is the default and writes nothing:

```bash
# 1. Plan (read-only; inspect affected vs skipped files):
seclusor secrets blob rekey-batch \
  --dir ./packs --glob '*.age' \
  --identity-file ~/.config/seclusor/old-identity.txt \
  --prior-recipient-file ~/.config/seclusor/old-recipients.txt \
  --recipient-file ~/.config/seclusor/new-recipients.txt \
  --verify-identity-file ~/.config/seclusor/new-identity.txt \
  --allow-recipient-mismatch --json

# 2. Apply with a two-phase 0600 resume journal:
seclusor secrets blob rekey-batch \
  --dir ./packs --glob '*.age' --apply \
  --state ./rekey-state.json \
  --identity-file ~/.config/seclusor/old-identity.txt \
  --prior-recipient-file ~/.config/seclusor/old-recipients.txt \
  --recipient-file ~/.config/seclusor/new-recipients.txt \
  --verify-identity-file ~/.config/seclusor/new-identity.txt \
  --write-recipients ~/.config/seclusor/new-recipients.txt \
  --allow-recipient-mismatch --json
```

- **Selection**: Pass explicit `FILE...` paths and/or `--dir <DIR>` with
  `--glob <PATTERN>` (default `*.age`). Subdirectories are ignored unless
  `--recursive` is set. Symlinks, hidden files, `.seclusor-*` temp files, and
  `.bak-*` backup files are skipped.
- **Two-phase state journal (`--state`)**: Written as a private `0600` file
  recording `sha256_before` and `sha256_after` before each replacement and
  updating to `rekeyed` after commit. Re-running with `--state` marks files
  matching `sha256_after` as `already-done` without mislabeling `not-openable`
  files.
- **Backups (`--backup`)**: Opt-in `.bak-<UTC>Z` (`0600`) copy before replacement.
  Backups retain the prior ciphertext and remain readable by prior identities;
  delete them once the batch is verified.

## Size limits

Blob encryption has a **10 MB soft limit** by default. For larger files,
pass `--allow-large`:

```bash
seclusor secrets blob encrypt \
  --input large-backup.tar.gz \
  --output large-backup.tar.gz.age \
  --recipient age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p \
  --allow-large
```

The decrypt side also requires `--allow-large` for files that exceed the
limit.

## Multi-machine sync pattern

A common pattern for distributing encrypted files across machines:

```bash
# On the source machine:
seclusor secrets blob encrypt \
  --input service-account.json \
  --output service-account.json.age \
  --recipient age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p

# Transfer (e.g., push to cloud storage):
aws s3 cp service-account.json.age s3://my-secrets-bucket/

# On the target machine:
aws s3 cp s3://my-secrets-bucket/service-account.json.age .
seclusor secrets blob decrypt \
  --input service-account.json.age \
  --output service-account.json \
  --identity-file ~/.config/seclusor/identity.txt
```

## See also

- [Bundle Credentials](bundle-credentials.md) — for structured JSON secrets
- [CI/Automation](ci-automation.md) — decrypting blobs in pipelines
- [App Note 02: Runtime & Deployment Patterns](../../appnotes/02-runtime-deployment-patterns.md) — secure storage and runtime models
