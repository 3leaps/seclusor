# CLI Command Reference

## Top-level

- `seclusor secrets ...`
- `seclusor keys ...`
- `seclusor docs ...`

## Secrets

- `init`, `set`, `get`, `list`, `unset`, `validate`
- `export-env`, `import-env`, `run`
- `bundle encrypt|decrypt`
- `inline encrypt|decrypt`
- `convert`

### Value vs reference credentials

Every credential stores exactly one of `--value` or `--ref`:

- **`--value`** stores the secret directly. The plaintext is encrypted at rest
  (bundle or inline codec) and injected into the environment by `secrets run`.
  Max size: 1 MB.

  ```bash
  seclusor secrets set --key DB_PASSWORD --value "s3cret"
  ```

- **`--ref`** stores a pointer to a secret held elsewhere — a vault path,
  environment variable name, cloud secret manager ARN, or any URI your
  toolchain resolves at runtime. Seclusor stores and encrypts the reference
  string but does not resolve it. Max length: 2048 characters.

  ```bash
  seclusor secrets set --key DB_PASSWORD --ref "vault://prod/db/password"
  seclusor secrets set --key API_KEY --ref "aws:secretsmanager:us-east-1:prod/api-key"
  seclusor secrets set --key SIGNING_CERT --ref "env://SIGNING_CERT_PATH"
  ```

Ref credentials are excluded from `export-env` and `secrets run` by default
because seclusor cannot resolve them. The library-level `emit_ref` option
includes them as literal strings for downstream tooling to resolve.

**Path separators**: Use forward slashes (`/`) in ref strings for portability.
Backslashes are preserved verbatim but may not be portable across platforms.
On Windows, seclusor does not normalize path separators — what you store is
what you get back.

### Special characters in values

Some passwords and tokens contain characters that are problematic for
shells or JSON: backslashes (`\`), dollar signs (`$`), quotes, and
other metacharacters.

**Using `secrets set` (recommended)**: Use single quotes around the
value to prevent shell interpretation. Seclusor handles JSON escaping
automatically:

```bash
# Single quotes pass the value literally to seclusor:
seclusor secrets set --key DB_PASSWORD --value 'GXY\$fzDiIofvN8n3EuuW1'
# Stored correctly, retrieved correctly
seclusor secrets get --key DB_PASSWORD --reveal
# GXY\$fzDiIofvN8n3EuuW1
```

**Hand-editing JSON (not recommended)**: If you paste a value containing
backslashes directly into a JSON file, you must escape each backslash
as `\\`. JSON only recognizes `\"`, `\\`, `\/`, `\b`, `\f`, `\n`,
`\r`, `\t`, and `\uXXXX` as valid escape sequences. A literal `\$` in
JSON is invalid and will produce an "invalid escape" error.

```json
// WRONG — \$ is not a valid JSON escape:
{"type": "secret", "value": "GXY\$fzDiIofvN8n3EuuW1"}

// CORRECT — backslash escaped:
{"type": "secret", "value": "GXY\\$fzDiIofvN8n3EuuW1"}
```

You can also pass the value from an environment variable to avoid
shell quoting issues entirely:

```bash
# Shell expands $LAKEHOUSE_PASSWORD before seclusor sees it:
seclusor secrets set --key DB_PASSWORD --value "$LAKEHOUSE_PASSWORD"
```

This works because the shell resolves the variable and passes the
raw value to seclusor, bypassing any quoting or escaping concerns.

If you encounter an "invalid escape" error on a file you edited
manually, either fix the escaping or re-enter the value using
`secrets set` which handles this automatically. If the credential
system allows it, regenerating the password without backslashes
avoids the issue entirely.

### Credential type

Each credential has a `type` field (`--credential-type`, default `"secret"`).
This is a free-form metadata label — any non-empty string up to 64
characters is valid. Seclusor does not enforce a fixed set of values and
does not change behavior based on the type.

```bash
seclusor secrets set --key DB_PASSWORD --value "s3cret"                          # type: "secret" (default)
seclusor secrets set --key DB_PASSWORD --value "s3cret" --credential-type token   # type: "token"
seclusor secrets set --key APP_ENV --value "production" --credential-type config  # type: "config"
```

Suggested conventions:

| Type          | Intent                                                                                                |
| ------------- | ----------------------------------------------------------------------------------------------------- |
| `secret`      | Sensitive credential (API key, password, secret key value). Default.                                  |
| `id`          | Non-sensitive identifier paired with a secret (key ID, token ID, account ID). Safe to display or log. |
| `username`    | Login name or service account identifier paired with a password or token.                             |
| `token`       | Authentication token (PAT, JWT, bearer token)                                                         |
| `uri`         | Endpoint address (server URL, API base URL, connection string). `url` works equally.                  |
| `config`      | Non-sensitive configuration value (region, project name, feature flag)                                |
| `certificate` | TLS certificate or key material                                                                       |
| `signing-key` | Cryptographic signing key                                                                             |
| `ref`         | Often paired with `--ref` for external store pointers                                                 |

A common pattern is pairing an `id` with a `secret` for the same service:

```bash
seclusor secrets set --key AWS_ACCESS_KEY_ID --value "AKIA..." --credential-type id --description "AWS access key ID"
seclusor secrets set --key AWS_SECRET_ACCESS_KEY --value "wJalr..." --credential-type secret --description "AWS secret key"
seclusor secrets set --key CF_TOKEN_ID --value "abc123" --credential-type id --description "Cloudflare API token ID"
seclusor secrets set --key CF_TOKEN --value "v1.0-..." --credential-type secret --description "Cloudflare API token"
```

This makes intent clear to operators reading `secrets list --verbose`
even though seclusor treats both types identically.

These are conventions, not restrictions. All values are treated equally
by seclusor — redacted by `get`, encrypted by inline/bundle, injected
by `run`. The type helps operators and downstream tooling categorize
credentials.

### Description metadata

- `secrets set --description <text>` stores a credential description.
- Omitting `--description` preserves the existing credential description.
- `secrets set --description ""` clears the description.
- `secrets get --show-description` prints description metadata only.
- `secrets get --show-description` and `--reveal` are mutually exclusive.
- `secrets list --verbose` prints `KEY<TAB>description`; keys without descriptions print as just `KEY`.

### Runtime source behavior (`get`, `export-env`, `run`)

- Plaintext JSON input (`--file secrets.json`) works without identities.
- Bundle ciphertext input (`--file secrets.age`) requires one or more `--identity-file <path>`.
- Source classification is fail-closed: bundle-classified input does not fall back to plaintext parsing after decrypt/identity failure.

Examples:

```bash
seclusor secrets get --file secrets.age --identity-file ./identity.txt --project demo --key API_KEY
seclusor secrets export-env --file secrets.age --identity-file ./identity.txt --project demo --format export
seclusor secrets run --file secrets.age --identity-file ./identity.txt --project demo --allow APP_API_KEY -- env | grep APP_API_KEY
```

### `secrets run` and shell features

`seclusor secrets run` executes the child command directly. It does not add a shell
layer, so pipes, redirects, glob expansion, and `$VAR` interpolation only work if
you wrap them explicitly in a shell.

```bash
# This does NOT work (no shell):
seclusor secrets run --file secrets.age --identity-file ./identity.txt --project demo -- echo $APP_API_KEY | base64

# This works:
seclusor secrets run --file secrets.age --identity-file ./identity.txt --project demo -- sh -c 'echo "$APP_API_KEY" | base64'

# Windows:
seclusor secrets run --file secrets.age --identity-file .\\identity.txt --project demo -- cmd /c "echo %APP_API_KEY%"
```

## Keys

- `keys age identity generate --output <path>`

## Docs

- `docs list [--format plain|json]`
- `docs show [--format plain|json] <slug>`

## Scenarios

For end-to-end examples of each command in context, see
[Workflow Scenarios](scenarios/index.md) and the
[Quick Reference](scenarios/quick-reference.md) command lookup table.
