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

Rekey operations rotate recipient sets without changing plaintext content.
