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
