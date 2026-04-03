# Key Management

## Generate an identity file

```bash
seclusor keys age identity generate --output ~/.config/seclusor/identity.txt
```

The command prints the public recipient to stdout.

## Recipients

Encryption accepts recipients from:

- `--recipient` (repeatable)
- `--recipient-file`
- `--recipient-env-var`

## Rekeying

Rekeying rotates the recipient set on armored files **without decrypting the plaintext values** to disk.

### Rekey a bundle file

```bash
seclusor secrets rekey \
  --file secrets.age \
  --identity-file ~/.config/seclusor/old-identity.txt \
  --recipient age1newrecipient1... \
  --recipient age1newrecipient2...
```

### Rekey an inline document

```bash
seclusor secrets rekey \
  --file secrets.json \
  --identity-file old.txt \
  --recipient age1new...
```

### Glassbreak / High-Value Credential Archives

For critical archives (root keys, master passphrases):

1. Create new identities/recipients in a clean environment.
2. Rekey the archive using the new recipients.
3. Verify the new bundle can be decrypted with the new identity and **cannot** be decrypted with the old one.
4. Securely destroy or archive the old identity.
5. Update all consuming systems.

See [Security Model](../guides/security.md) for compromise response guidance.

## Scenarios

For end-to-end team key management workflows, see
[Team Recipients](scenarios/team-recipients.md).
