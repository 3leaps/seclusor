# Quick Reference

"I want to..." command lookup. Every command links to the relevant scenario
for full context.

## Identity and key management

| I want to...                             | Command                                                                                     |
| ---------------------------------------- | ------------------------------------------------------------------------------------------- |
| Generate a passphrase-protected identity | `seclusor keys age identity generate --output ~/.config/seclusor/identity.txt --passphrase` |
| Generate a plaintext identity            | `seclusor keys age identity generate --output ~/.config/seclusor/identity.txt`              |
| Find my recipient (public key)           | `grep -i '^# public key:' ~/.config/seclusor/identity.txt`                                  |

## Creating and editing secrets

| I want to...                | Command                                                                                                        |
| --------------------------- | -------------------------------------------------------------------------------------------------------------- |
| Initialize a secrets file   | `seclusor secrets init --file secrets.json --project myapp --env-prefix MYAPP_`                                |
| Add a secret value          | `seclusor secrets set --file secrets.json --project myapp --key DB_PASSWORD --value "..." --description "..."` |
| Add a reference pointer     | `seclusor secrets set --file secrets.json --project myapp --key DB_PASSWORD --ref "vault://prod/db/password"`  |
| Remove a credential         | `seclusor secrets unset --file secrets.json --project myapp --key DB_PASSWORD`                                 |
| List keys (no values shown) | `seclusor secrets list --file secrets.json --project myapp`                                                    |
| List keys with descriptions | `seclusor secrets list --file secrets.json --project myapp --verbose`                                          |
| Read a value (redacted)     | `seclusor secrets get --file secrets.json --project myapp --key DB_PASSWORD`                                   |
| Read a value (plaintext)    | `seclusor secrets get --file secrets.json --project myapp --key DB_PASSWORD --reveal`                          |
| Read a description only     | `seclusor secrets get --file secrets.json --project myapp --key DB_PASSWORD --show-description`                |
| Validate a secrets file     | `seclusor secrets validate --file secrets.json`                                                                |

## Bundle encryption

| I want to...       | Command                                                                                                     |
| ------------------ | ----------------------------------------------------------------------------------------------------------- |
| Encrypt as bundle  | `seclusor secrets bundle encrypt --input secrets.json --output secrets.age --recipient age1...`             |
| Decrypt a bundle   | `seclusor secrets bundle decrypt --input secrets.age --output secrets.json --identity-file ./identity.txt`  |
| Encrypt for a team | `seclusor secrets bundle encrypt --input secrets.json --output secrets.age --recipient-file recipients.txt` |

See [Bundle Credentials](bundle-credentials.md) for the full workflow.

## Inline encryption

| I want to...             | Command                                                                                                                                                  |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Encrypt inline           | `seclusor secrets inline encrypt --input secrets.json --output secrets-inline.json --recipient age1...`                                                  |
| Decrypt inline           | `seclusor secrets inline decrypt --input secrets-inline.json --output secrets.json --identity-file ./identity.txt`                                       |
| Convert inline to bundle | `seclusor secrets convert --input secrets-inline.json --output secrets.age --from inline --to bundle --identity-file ./identity.txt --recipient age1...` |
| Convert bundle to inline | `seclusor secrets convert --input secrets.age --output secrets-inline.json --from bundle --to inline --identity-file ./identity.txt --recipient age1...` |

See [Inline Credentials](inline-credentials.md) for the full workflow.

## Blob encryption

| I want to...                  | Command                                                                                                                     |
| ----------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| Encrypt a file                | `seclusor secrets blob encrypt --input deploy-key.pem --output deploy-key.pem.age --recipient age1...`                      |
| Decrypt a file                | `seclusor secrets blob decrypt --input deploy-key.pem.age --output deploy-key.pem --identity-file ./identity.txt`           |
| Encrypt a large file (>10 MB) | `seclusor secrets blob encrypt --input large.tar.gz --output large.tar.gz.age --recipient age1... --allow-large`            |
| Decrypt a large file (>10 MB) | `seclusor secrets blob decrypt --input large.tar.gz.age --output large.tar.gz --identity-file ./identity.txt --allow-large` |

See [Blob Encryption](blob-encryption.md) for the full workflow.

## Runtime use

| I want to...                          | Command                                                                                                                         |
| ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| Run a command with injected secrets   | `seclusor secrets run --file secrets.age --identity-file ./identity.txt --project myapp -- ./my-command`                        |
| Run with glob-filtered keys           | `seclusor secrets run --file secrets.age --identity-file ./identity.txt --project myapp --allow MYAPP_* -- ./my-command`        |
| Run with shell features (pipes, etc.) | `seclusor secrets run --file secrets.age --identity-file ./identity.txt --project myapp -- sh -c 'echo "$MYAPP_KEY" \| base64'` |
| Export as shell variables             | `seclusor secrets export-env --file secrets.age --identity-file ./identity.txt --project myapp --format export`                 |
| Import from environment               | `seclusor secrets import-env --file secrets.json --project myapp --prefix MYAPP_`                                               |

## Passphrase channels (protected identities)

| I want to...           | Add this flag                           |
| ---------------------- | --------------------------------------- |
| Prompt interactively   | `--passphrase`                          |
| Read from env variable | `--passphrase-env SECLUSOR_PASSPHRASE`  |
| Read from a file       | `--passphrase-file /path/to/passphrase` |
| Read from stdin        | `--passphrase-stdin`                    |

See [CI/Automation](ci-automation.md) for non-interactive usage patterns.

## Embedded docs

| I want to...            | Command                            |
| ----------------------- | ---------------------------------- |
| List all available docs | `seclusor docs list`               |
| Show a specific doc     | `seclusor docs show <slug>`        |
| List docs as JSON       | `seclusor docs list --format json` |
