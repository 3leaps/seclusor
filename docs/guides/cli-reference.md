# CLI Command Reference

## Top-level

- `seclusor secrets ...`
- `seclusor keys ...`
- `seclusor assets ...`
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

Passwords and tokens from external systems sometimes contain characters
that have special meaning in shells, `.env` files, or JSON. The most
common offenders are `$`, `\`, `"`, and `!`. The critical thing to
understand is that **the same raw value is represented differently in
each format**. See [App Note 03: Special Characters in Credentials](../appnotes/03-special-characters.md) for the full guide with examples.

**Quick rules**:

- **`secrets set` with single quotes** is the safest CLI path — it
  bypasses shell interpretation and seclusor handles JSON escaping:
  ```bash
  seclusor secrets set --key DB_PASSWORD --value 'GXY$fzDiIofvN8n3'
  ```
- **Do not copy escaped values between formats** — a `.env` file
  escapes `$` as `\$`, but the actual password has no backslash.
  Pasting the `.env` representation into JSON adds a character that
  isn't in the password.
- **Verify with length check** after setting:
  ```bash
  seclusor secrets get --key DB_PASSWORD --reveal | tr -d '\n' | wc -c
  ```

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

### Runtime source behavior (`get`, `list`, `validate`, `export-env`, `run`)

All five read-side commands accept plaintext JSON, bundle ciphertext, or
inline-encrypted JSON via the same auto-detect path (`--file`).

- Plaintext JSON works without identities.
- Bundle ciphertext requires `--identity-file <path>` **or**
  `--identity-public-key <age1...>` (mutually exclusive; see
  [Identity files and recipients](identity-and-recipients.md)).
- Inline JSON without an identity: `list` still prints keys (values never
  shown); `validate` runs **structural-only** checks (schema + inline
  marker/base64/size — **not** authenticity/decryptability); `get` can
  redact or show descriptions; `export-env` / `run` need identities when
  ciphertext values must be opened.
- Source classification is fail-closed: bundle-classified input does not fall
  back to plaintext parsing after decrypt/identity failure.

#### `secrets validate` modes

| Input     | Identity? | Exit 0 stdout           | Notes                                         |
| --------- | --------- | ----------------------- | --------------------------------------------- |
| Plaintext | n/a       | `valid`                 | Full structural validation                    |
| Bundle    | no        | (fails)                 | Fail-closed; supply an identity selector      |
| Bundle    | yes       | `valid`                 | Decrypt in memory, then validate              |
| Inline    | no        | `structural-only valid` | Encoding/shape only; stderr explains the mode |
| Inline    | yes       | `valid`                 | Decrypt values, then full validation          |

Both structural-only and full success exit `0`. Scripts must inspect **stdout**
for the `structural-only` token — do not treat exit code alone as proof of
cryptographic validation. Structural-only never claims authenticity or that
values are decryptable with any particular identity.

Examples:

```bash
seclusor secrets get --file secrets.age --identity-file ./identity.txt --project demo --key API_KEY
seclusor secrets list --file secrets.age --identity-file ./identity.txt --project demo
seclusor secrets validate --file secrets-inline.json
seclusor secrets validate --file secrets.age --identity-public-key age1...
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
- `keys signing generate --output <path> --recipient <age1...>`

`keys signing generate` creates an age-encrypted Ed25519 signing-key file
outside the repository root and prints the public verification identity:

```bash
seclusor keys signing generate \
  --output ~/.config/seclusor/release-signing.key.age \
  --recipient age1...
```

Stdout contains `public_key=<base64url>` and
`key_fingerprint=<base64url>`. Both values are raw bytes encoded as
unpadded URL-safe base64. The encrypted signing-key file is created with
`0600` permissions on Unix and must be owned by the current user when loaded.
It must be unlocked with an age identity when signing assets.

## Assets

- `assets sign --input <path> --signing-key <key.age> --identity-file <identity>`
- `assets verify --input <path> --public-key <base64url>`
- `assets verify --input <path> --fingerprint <base64url>`

If `--signature` is omitted, both `sign` and `verify` use
`<input>.secsig`.

```bash
seclusor assets sign \
  --input dist/seclusor.tar.gz \
  --signing-key ~/.config/seclusor/release-signing.key.age \
  --identity-file ~/.config/seclusor/operator-identity.txt \
  --signer-label release-signing \
  --claimed-at 2026-05-17T12:00:00Z

seclusor assets verify \
  --input dist/seclusor.tar.gz \
  --public-key AtZytOpHFK-qNxEa2Tl54imvnWhELx90w1oihgOobkA
```

Verification fails closed by default: callers must provide either
`--public-key` or `--fingerprint`. `--trust-embedded-key` is available
only for explicit self-consistency checks and does not prove signer
identity. `claimed_at` is signed metadata supplied by the signer; it is
not trusted timestamp evidence. Verification stdout is line-oriented; signed
metadata values such as `signer_label` are escaped when needed so control
characters cannot create extra output lines.

## Docs

- `docs list [--format plain|json]`
- `docs show [--format plain|json] <slug>`

## Scenarios

For end-to-end examples of each command in context, see
[Workflow Scenarios](scenarios/index.md) and the
[Quick Reference](scenarios/quick-reference.md) command lookup table.
