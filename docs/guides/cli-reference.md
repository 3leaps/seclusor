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
