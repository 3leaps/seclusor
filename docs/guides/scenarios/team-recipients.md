# Team Recipients

Encrypt secrets for multiple team members so that any of their identities
can decrypt. Each member generates their own identity; public keys are
collected into a shared recipients file.

**Prerequisites**: Each team member must have their own age identity.
See [identity setup](index.md#identity-setup).

## 1. Each member generates an identity

Each team member runs:

```bash
seclusor keys age identity generate \
  --output ~/.config/seclusor/identity.txt \
  --passphrase
# Prints the age1... recipient (public key) to stdout
```

Each member shares **only** their `age1...` public key — never the identity
file.

## 2. Collect recipients

Create a shared recipients file and commit it to the repository:

```
# recipients.txt — safe to commit (public keys only)
# alice
age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
# bob
age1yrczveqayxcaz9xgmjg58ck97lplhxp0rzu0x90s9hrhqfd6g82qpxdky5
# ci-runner
age1fx3wu4as3yqrha790dkxrq3lk34cgjq0ndsmmjjekzh52gqua2psjn07u9
```

## 3. Encrypt for the team

Use `--recipient-file` to encrypt for all recipients at once:

```bash
seclusor secrets bundle encrypt \
  --input secrets.json \
  --output secrets.age \
  --recipient-file recipients.txt
```

Or with inline encryption:

```bash
seclusor secrets inline encrypt \
  --input secrets.json \
  --output secrets-inline.json \
  --recipient-file recipients.txt
```

Any team member (or the CI runner) can decrypt with their own identity.

## 4. Decrypt with individual identity

Each member decrypts using their own identity file:

```bash
# Alice:
seclusor secrets run \
  --file secrets.age \
  --identity-file ~/.config/seclusor/identity.txt \
  --project myapp \
  -- ./my-command

# Bob:
seclusor secrets run \
  --file secrets.age \
  --identity-file ~/.config/seclusor/identity.txt \
  --project myapp \
  -- ./my-command
```

## 5. Member rotation

When a team member leaves or a key is compromised:

1. Remove their recipient line from `recipients.txt`.
2. Re-encrypt the secrets file with the updated recipient set:

```bash
# Decrypt with any current member's identity:
seclusor secrets bundle decrypt \
  --input secrets.age \
  --output secrets.json \
  --identity-file ~/.config/seclusor/identity.txt

# Re-encrypt for remaining members:
seclusor secrets bundle encrypt \
  --input secrets.json \
  --output secrets.age \
  --recipient-file recipients.txt

# Clean up plaintext:
rm secrets.json
```

> **Note**: A CLI `rekey` subcommand that performs this without exposing
> plaintext to disk is planned (SC-009). The library-level rekey API
> (`seclusor-keyring`) is available now.

## 6. Adding a new member

1. New member generates their identity and shares their `age1...` recipient.
2. Add the recipient to `recipients.txt`.
3. Re-encrypt with the updated file (same steps as rotation above).

## See also

- [Identity Files and Recipients](../identity-and-recipients.md) — full details on multi-recipient encryption
- [Key Management](../key-management.md) — rekeying and recipient rotation
- [CI/Automation](ci-automation.md) — using team recipients in pipelines
- [Security Model](../security.md) — compromise response procedures
