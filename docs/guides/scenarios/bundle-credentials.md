# Bundle Credentials

Encrypt a structured secrets file as an opaque `.age` bundle and inject
credentials at runtime. This is the recommended path for most use cases.

**Prerequisites**: An age identity and recipient.
See [identity setup](index.md#identity-setup) if you haven't generated one.

## 1. Initialize a secrets file

```bash
seclusor secrets init --file secrets.json --project myapp --env-prefix MYAPP_
```

This creates a JSON document with a project named `myapp`. The `--env-prefix`
controls how keys are prefixed when exported to environment variables.

## 2. Add credentials

```bash
seclusor secrets set \
  --file secrets.json \
  --project myapp \
  --key DB_PASSWORD \
  --value "placeholder-synthetic-password-xyz789" \
  --description "primary application database password"

seclusor secrets set \
  --file secrets.json \
  --project myapp \
  --key API_TOKEN \
  --value "placeholder-synthetic-token-abc123" \
  --description "third-party API token"
```

> **Tip**: `--value` appears in shell history. For sensitive values, pipe from
> a secret manager or password prompt instead of passing them directly on the
> command line.

## 3. Verify contents

```bash
# List keys and descriptions (values are never shown by list):
seclusor secrets list --file secrets.json --project myapp --verbose

# Read a specific value (redacted by default):
seclusor secrets get --file secrets.json --project myapp --key DB_PASSWORD

# Reveal the plaintext (requires --reveal):
seclusor secrets get --file secrets.json --project myapp --key DB_PASSWORD --reveal
```

## 4. Encrypt as a bundle

```bash
seclusor secrets bundle encrypt \
  --input secrets.json \
  --output secrets.age \
  --recipient age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
```

The `.age` file is a single opaque ciphertext. No key names, project
metadata, or structure is visible.

## 5. Delete the plaintext

Once the bundle is encrypted and verified, delete the plaintext JSON:

```bash
rm secrets.json
```

The bundle is now the source of truth.

## 6. Use at runtime

### Inject into a child process

```bash
seclusor secrets run \
  --file secrets.age \
  --identity-file ~/.config/seclusor/identity.txt \
  --project myapp \
  --allow MYAPP_* \
  -- env | grep MYAPP_
```

Secrets are injected into the child process environment. They never appear
in CLI arguments, shell history, or process lists.

### Read a single value

```bash
seclusor secrets get \
  --file secrets.age \
  --identity-file ~/.config/seclusor/identity.txt \
  --project myapp \
  --key DB_PASSWORD \
  --reveal
```

### Export as environment variables

```bash
seclusor secrets export-env \
  --file secrets.age \
  --identity-file ~/.config/seclusor/identity.txt \
  --project myapp \
  --format export
```

## 7. Decrypt the bundle (when needed)

To edit credentials, decrypt back to JSON:

```bash
seclusor secrets bundle decrypt \
  --input secrets.age \
  --output secrets.json \
  --identity-file ~/.config/seclusor/identity.txt
```

Edit with `secrets set`, then re-encrypt and delete the plaintext.

## See also

- [Inline Credentials](inline-credentials.md) — if you need git-friendly diffs
- [CI/Automation](ci-automation.md) — using bundles in non-interactive pipelines
- [Team Recipients](team-recipients.md) — encrypting for multiple team members
- [Storage Codecs](../codecs.md) — bundle vs inline tradeoffs
