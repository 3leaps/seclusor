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

The `.age` output is opaque ciphertext. The original file format, name, and
contents are not visible.

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
