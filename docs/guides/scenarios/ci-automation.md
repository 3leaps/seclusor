# CI/Automation

Use seclusor in non-interactive environments like GitHub Actions, GitLab CI,
or other automation pipelines. The key challenge is providing the identity
file and passphrase without interactive prompts.

**Prerequisites**: An age identity (passphrase-protected recommended) and
an encrypted secrets file (bundle, inline, or blob). See
[identity setup](index.md#identity-setup).

## Passphrase channels

When using a passphrase-protected identity in automation, choose the
appropriate channel:

| Channel              | Flag                     | When to use                            |
| -------------------- | ------------------------ | -------------------------------------- |
| Environment variable | `--passphrase-env VAR`   | CI secrets (GitHub Actions, GitLab CI) |
| File                 | `--passphrase-file PATH` | Docker secrets, mounted volumes        |
| Stdin pipe           | `--passphrase-stdin`     | Pipe from a secret manager CLI         |
| Interactive prompt   | `--passphrase`           | Never in CI (requires a terminal)      |

Only one passphrase channel can be used per command. Passphrases are never
accepted as bare CLI argument values.

## GitHub Actions example

Store two secrets in your GitHub repository settings:

- `SECLUSOR_IDENTITY` — the contents of your identity file
- `SECLUSOR_PASSPHRASE` — the passphrase (if identity is protected)

```yaml
name: Deploy
on: push

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install seclusor
        run: |
          curl -fsSL https://github.com/3leaps/seclusor/releases/latest/download/seclusor-x86_64-unknown-linux-gnu.tar.gz \
            | tar xz -C /usr/local/bin

      - name: Write identity file
        run: |
          mkdir -p ~/.config/seclusor
          echo "${{ secrets.SECLUSOR_IDENTITY }}" > ~/.config/seclusor/identity.txt
          chmod 600 ~/.config/seclusor/identity.txt

      - name: Run with secrets
        env:
          SECLUSOR_PASSPHRASE: ${{ secrets.SECLUSOR_PASSPHRASE }}
        run: |
          seclusor secrets run \
            --file secrets.age \
            --identity-file ~/.config/seclusor/identity.txt \
            --passphrase-env SECLUSOR_PASSPHRASE \
            --project myapp \
            --allow MYAPP_* \
            -- ./deploy.sh
```

## GitLab CI example

Store the same values as CI/CD variables (masked, protected):

```yaml
deploy:
  stage: deploy
  before_script:
    - mkdir -p ~/.config/seclusor
    - echo "$SECLUSOR_IDENTITY" > ~/.config/seclusor/identity.txt
    - chmod 600 ~/.config/seclusor/identity.txt
  script:
    - seclusor secrets run
      --file secrets.age
      --identity-file ~/.config/seclusor/identity.txt
      --passphrase-env SECLUSOR_PASSPHRASE
      --project myapp
      --allow MYAPP_*
      -- ./deploy.sh
```

## Plaintext identity (no passphrase)

If your identity file is not passphrase-protected, omit the passphrase
flags entirely:

```bash
seclusor secrets run \
  --file secrets.age \
  --identity-file ~/.config/seclusor/identity.txt \
  --project myapp \
  -- ./deploy.sh
```

This is simpler but means anyone with access to the identity file can
decrypt. Appropriate when the file is stored in hardware-secured or
ephemeral storage (e.g., a CI runner's encrypted disk that is wiped
after each job).

## Decrypting blobs in CI

For non-JSON files (scripts, certificates), use `blob decrypt`:

```bash
seclusor secrets blob decrypt \
  --input deploy-key.pem.age \
  --output deploy-key.pem \
  --identity-file ~/.config/seclusor/identity.txt \
  --passphrase-env SECLUSOR_PASSPHRASE
chmod 600 deploy-key.pem
```

## See also

- [Bundle Credentials](bundle-credentials.md) — creating the bundle to use in CI
- [Blob Encryption](blob-encryption.md) — encrypting non-JSON files
- [Identity Files and Recipients](../identity-and-recipients.md) — passphrase channel details
- [Security Model](../security.md) — operational practices and compromise response
