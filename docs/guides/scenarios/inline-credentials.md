# Inline Credentials

Encrypt individual values inside a readable JSON document using
`sec:age:v1:` markers. The document structure (key names, project slugs)
remains visible; only the secret values are encrypted.

**When to use**: You need git-friendly diffs, code review visibility, or
partial structure inspection. Only suitable for low-sensitivity data — the
inline codec reveals which keys exist and when they change.

**Prerequisites**: An age identity and recipient.
See [identity setup](index.md#identity-setup) if you haven't generated one.

## 1. Initialize and populate

```bash
seclusor secrets init --file secrets.json --project myapp --env-prefix MYAPP_

seclusor secrets set \
  --file secrets.json \
  --project myapp \
  --key DEPLOY_HOOK_URL \
  --value "placeholder-synthetic-webhook-url-9f3a" \
  --description "deployment notification webhook"

seclusor secrets set \
  --file secrets.json \
  --project myapp \
  --key CONFIG_TOKEN \
  --value "placeholder-synthetic-config-token-7b2e" \
  --description "feature flag service token"
```

## 2. Encrypt inline

```bash
seclusor secrets inline encrypt \
  --input secrets.json \
  --output secrets-inline.json \
  --recipient age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
```

The output file retains readable JSON structure. Each secret value is
replaced with a `sec:age:v1:<base64>` ciphertext string:

```json
{
  "projects": {
    "myapp": {
      "credentials": {
        "DEPLOY_HOOK_URL": {
          "type": "secret",
          "value": "sec:age:v1:YWdlLWVuY3J5cHRpb24ub3Jn..."
        }
      }
    }
  }
}
```

Key names, project slugs, and credential types remain visible. This is
the tradeoff: you get meaningful git diffs at the cost of metadata exposure.

## 3. Git workflow

The inline file is designed for version control:

```bash
git add secrets-inline.json
git commit -m "chore: update deploy hook URL"
```

Git diffs show which keys changed (but not the plaintext values). Review
[App Note 01: Git Storage](../../appnotes/01-git-armored-storage.md) for
risk guidance by sensitivity level.

## 4. Use at runtime

### Inject into a child process

```bash
seclusor secrets run \
  --file secrets-inline.json \
  --identity-file ~/.config/seclusor/identity.txt \
  --project myapp \
  --allow MYAPP_* \
  -- env | grep MYAPP_
```

Inline-encrypted values are decrypted transparently at runtime when an
identity file is provided.

### Read a single value

```bash
seclusor secrets get \
  --file secrets-inline.json \
  --identity-file ~/.config/seclusor/identity.txt \
  --project myapp \
  --key DEPLOY_HOOK_URL \
  --reveal
```

Without `--reveal`, the output is redacted. Without `--identity-file`,
inline ciphertext values are rejected.

## 5. Convert to bundle

If you later decide you need full opacity, convert to a bundle:

```bash
seclusor secrets convert \
  --input secrets-inline.json \
  --output secrets.age \
  --from inline \
  --to bundle \
  --identity-file ~/.config/seclusor/identity.txt \
  --recipient age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
```

## See also

- [Bundle Credentials](bundle-credentials.md) — for maximum security (no metadata leakage)
- [App Note 01: Git Storage](../../appnotes/01-git-armored-storage.md) — risk continuum for storing encrypted files in git
- [Storage Codecs](../codecs.md) — detailed comparison of bundle and inline
