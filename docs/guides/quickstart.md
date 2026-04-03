# Quick Start

Seclusor encrypts secrets with age so they can be used safely in code and pipelines. **Important**: While secrets can be stored in git, this carries risk. See [App Note 01: Git Storage](../appnotes/01-git-armored-storage.md).

## Initialize a file

```bash
seclusor secrets init --file secrets.json --project demo --env-prefix APP_
```

Add credentials with `seclusor secrets set` rather than hand-writing bare
`"KEY": "value"` pairs. Each JSON credential is an object such as
`{"API_KEY":{"type":"secret","value":"sk-123"}}`.

## Set and read secrets

```bash
seclusor secrets set --file secrets.json --project demo --key API_KEY --value sk-123 --description "primary demo API key"
seclusor secrets get --file secrets.json --project demo --key API_KEY                            # redacted
seclusor secrets get --file secrets.json --project demo --key API_KEY --show-description         # description only
seclusor secrets get --file secrets.json --project demo --key API_KEY --reveal                   # plaintext
seclusor secrets list --file secrets.json --project demo --verbose                               # key<TAB>description
```

## Export for app runtime

```bash
seclusor secrets export-env --file secrets.json --project demo --format export
```

## Simplest Useful Case: Secure Runtime Injection

The most common and safest pattern is using `seclusor run` to inject secrets without exposing them in shell history or process lists.

```bash
# Generate a passphrase-protected identity (recommended):
seclusor keys age identity generate --output ~/.config/seclusor/identity.txt --passphrase
# Note the age1... recipient printed to stdout

# Run a command with secrets injected from an armored bundle:
seclusor secrets run \
  --file secrets.age \
  --identity-file ~/.config/seclusor/identity.txt \
  --project demo \
  --allow APP_* \
  -- env | grep APP_
# You'll be prompted for the passphrase if the identity is protected
```

Other patterns (export to .env, library calls, or building a secret server) are also supported.

See [Workflow Scenarios](scenarios/index.md) for complete end-to-end guides covering bundle, inline, blob, CI, and team workflows.

## Encrypt for sharing and runtime

Bundle files can be used directly as runtime input (recommended for security). Plaintext JSON works for local editing.

```bash
seclusor secrets bundle encrypt --input secrets.json --output secrets.age --recipient age1...
seclusor secrets export-env --file secrets.age --identity-file ./identity.txt --project demo --format export
seclusor secrets bundle decrypt --input secrets.age --output secrets.json --identity-file ./identity.txt
```
