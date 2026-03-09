# Quick Start

Seclusor stores secrets in a git-trackable JSON document and encrypts data with age.

## Initialize a file

```bash
seclusor secrets init --file secrets.json --project demo --env-prefix APP_
```

## Set and read secrets

```bash
seclusor secrets set --file secrets.json --project demo --key API_KEY --value sk-123
seclusor secrets get --file secrets.json --project demo --key API_KEY           # redacted
seclusor secrets get --file secrets.json --project demo --key API_KEY --reveal  # plaintext
```

## Export for app runtime

```bash
seclusor secrets export-env --file secrets.json --project demo --format export
```

## Encrypt for sharing

```bash
seclusor secrets bundle encrypt --input secrets.json --output secrets.age --recipient age1...
seclusor secrets bundle decrypt --input secrets.age --output secrets.json --identity-file ./identity.txt
```
