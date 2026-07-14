# App Note 02: Runtime & Deployment Patterns

**Status**: Active
**Audience**: Developers, DevSecOps, platform engineers

Beyond git storage, seclusor supports several secure runtime patterns for
**reading** secrets without staging plaintext on disk.

## 1. Local Secure Runner (`seclusor secrets run`)

**Use case**: Developer workstations and CI jobs where secrets are stored locally.

- Bundle or inline file lives in a secure location (e.g. next to private SSH keys
  or under the seclusor config directory).
- Identity files: mode `0600` and owned by the current user on Unix.
- Inject secrets into a child process without putting values in CLI args or shell
  history:

```bash
seclusor secrets run \
  --file secrets.age \
  --identity-file ~/.config/seclusor/identity.txt \
  --project myapp \
  --allow 'APP_*' \
  -- ./my-command
```

Quote glob patterns (`'APP_*'`) so the shell does not expand them as pathnames.

**Best for**: Local development, personal CI tokens, glassbreak access.

## 2. Encrypted-read flows (CLI)

All read-side `secrets` commands accept plaintext JSON, bundle ciphertext, or
inline-encrypted JSON via auto-detect on `--file`:

| Command      | Encrypted input | Notes                                                                                                                    |
| ------------ | --------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `run`        | Yes             | Requires identity when values must open                                                                                  |
| `get`        | Yes             | Redacted by default; `--reveal` needs full decrypt                                                                       |
| `list`       | Yes             | Keys only; never values                                                                                                  |
| `validate`   | Yes             | Bundle without identity fails closed; inline without identity is **structural-only** (`structural-only valid` on stdout) |
| `export-env` | Yes             | Shell format has extra safety (see below)                                                                                |

Identity selectors (mutually exclusive):

- `--identity-file <path>` (repeatable)
- `--identity-public-key age1...` (bounded keyring discovery; public metadata only)

### Shell export (`export-env --format export`)

For `eval "$(...)"` into the current shell:

```bash
eval "$(seclusor secrets export-env \
  --file secrets.age \
  --identity-file ~/.config/seclusor/identity.txt \
  --project myapp \
  --format export \
  --allow 'APP_*')"
```

Shell format only:

- requires at least one `--allow` pattern
- refuses writing to a TTY without `--force`
- completion summary only with `--verbose` (default success keeps stderr empty)

Dotenv and JSON formats keep empty-allow = all keys.

## 3. Passphrase channels (protected identities)

Never pass the passphrase value on the CLI. Prefer:

| Channel          | Flag                     | Notes                  |
| ---------------- | ------------------------ | ---------------------- |
| Interactive      | `--passphrase`           | TTY prompt             |
| Env var **name** | `--passphrase-env VAR`   | Automation             |
| File             | `--passphrase-file PATH` | `0600` + owner on Unix |
| Stdin            | `--passphrase-stdin`     | One line               |

Only one explicit channel may be set (Clap conflicts).

### `--passphrase-env` tradeoff (honest)

`--passphrase-env VAR` avoids argv and shell-history leakage, but the passphrase
**value** still lives in the parent process environment:

- It is **inherited by child processes** unless cleared
- Same-UID tools can often inspect it (`/proc/<pid>/environ`, debuggers, some CI
  “dump env” steps)
- Scope the variable to a single command and `unset VAR` immediately after

Prefer TTY prompt for interactive use; use `--passphrase-env` only when automation
requires it and the environment is tightly controlled.

## 4. Library / FFI integration

- **Rust**: depend on `seclusor-crypto`, `seclusor-codec`, and/or `seclusor-keyring`
  directly (e.g. lanyte-attest).
- **Go**: `LoadSecretsJSON`, plus full-decrypt loaders `LoadSecretsBundle` and
  `LoadSecretsInline` with a `KeyringHandle` that already has identities added.
- **C-ABI**: `seclusor_secrets_handle_new_from_json`,
  `seclusor_secrets_handle_new_from_bundle` / `_from_inline` (pointer + length;
  never C strings for ciphertext).
- Prefer decrypting in memory with size limits enforced.
- Encrypted handle constructors (`LoadSecretsBundle` / `LoadSecretsInline` and
  matching C APIs) always **full-decrypt the entire document** before exposing a
  secrets handle. There is no structural-only handle; use CLI `validate` without
  an identity for structural-only inspection of inline JSON.

## 5. Secure servers & protected storage

- Store bundle files in dedicated volumes, cloud buckets with IAM, or similar.
- Prefer library/FFI decryption in services over shelling out to the CLI.
- High-sensitivity: local secure files + `secrets run` or direct library use.

## Recommendations by sensitivity

- **Low**: Git + inline is acceptable.
- **Medium**: Bundle in protected storage + `secrets run` or library calls.
- **High**: Local secure files + `secrets run` or direct library use. Avoid
  long-lived plaintext environments.

See [App Note 01: Git Storage of Armored Secrets](01-git-armored-storage.md).

Identity lookup and discovery roots: [Identity files and recipients](../guides/identity-and-recipients.md).
CI patterns: [CI / Automation](../guides/scenarios/ci-automation.md).
Full workflows: [Workflow Scenarios](../guides/scenarios/index.md).
