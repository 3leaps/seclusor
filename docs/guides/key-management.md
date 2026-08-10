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

When schema v1.1.0 recipient metadata is present, `rekey` compares the current
and target sets. A change fails closed and prints each public-key delta as
`+age1...` or `-age1...`; inspect that list before repeating the command with
`--allow-recipient-mismatch`. The flag accepts only the displayed recipient
change—it does not suppress other validation or cryptographic failures.

For a legacy v1.0.0 document, there is no recipient metadata to compare.
Seclusor prints an explicit indeterminate notice and establishes metadata from
the target set. It does not infer recipient identities from the age header,
because X25519 stanzas do not reveal them.

If none of the identities loaded for rekey corresponds to the target set,
seclusor warns about possible operator self-lockout. This warning is expected
when rotating with only the old identity loaded; verify the result with a new
identity before retiring the old one.

### Glassbreak / High-Value Credential Archives

For critical archives (root keys, master passphrases):

1. Create new identities/recipients in a clean environment.
2. Rekey the archive using the new recipients and inspect the displayed
   `+`/`-` delta before allowing it.
3. Rewrite every durable recipient source (for example `recipients.txt`) to
   exactly the new set **before any later `set` or `import-env` command**.
4. Verify the new bundle can be decrypted with the new identity and **cannot**
   be decrypted with the old one.
5. Securely destroy or archive the old identity.
6. Update all consuming systems.

A stale recipient file is fail-closed at the next encrypted value write and
prints its delta against document metadata. Do not treat the mismatch override
as a substitute for updating the durable recipient source.

See [Security Model](../guides/security.md) for compromise response guidance.

## Scenarios

For end-to-end team key management workflows, see
[Team Recipients](scenarios/team-recipients.md).
