# Release Notes

**Content policy**: This file contains the most recent 3 releases (reverse chronological). Older releases are archived in `docs/releases/vX.Y.Z.md`.

## v0.2.1 (August 2026)

**Security patch** — Keep the identity passphrase out of processes launched by
`secrets run`, and stop a stale recipients list from silently restoring a
retired recipient after rotation. GitHub Security Advisory published with this
release.

- **`secrets run`:** the `--passphrase-env` variable is excluded from the child
  environment through a single construction chokepoint; the command also
  refuses to start if any child env **value** equals the resolved passphrase
- **Write paths:** fail closed when the write-target recipient set diverges from
  document metadata (schema v1.1.0+); deliberate changes require
  `--allow-recipient-mismatch`. On legacy v1.0.0 documents, a full inline
  rewrite or bundle write emits an indeterminate establishment notice; a partial
  inline write instead refuses and directs you to `secrets rekey`
- **`rekey --write-recipients PATH`:** optional explicit durable recipient-list
  refresh after a successful rekey (never an implicit rewrite of
  `--recipient-file`)
- Prefer `--passphrase-file` / `--passphrase-stdin` for ordinary automation;
  parent-process residual remains for `--passphrase-env`

**Upgrade cue:** install 0.2.1 first, then rotate any identity that may have
been exposed; refresh durable recipient sources before further encrypted
writes.

**Install** (after the GitHub release is published):
`brew upgrade seclusor` · `scoop update seclusor`

See `docs/releases/v0.2.1.md` for full notes, ranges, residuals, and workarounds.

## v0.2.0 (August 2026)

**Encrypted documents you can live in** — Inspect, mutate, and rekey bundle and
inline secrets without a plaintext-on-disk edit cycle; sign release assets with
fail-closed verification; publish from locked, audited dependency graphs.

- Read and validate plaintext, inline-encrypted, and bundle documents through a
  common auto-detected command path
- Mutate encrypted documents with `set`, `unset`, and `import-env`; use `rekey`
  as the explicit recipient-membership operation
- Prefer `--value-stdin` / `--value-file` / `--value-env` for secret input
  (legacy `--value` still works, with a warning)
- Create detached `seclusor.signature.v1` asset signatures with age-protected
  Ed25519 signing keys and expected-key verification by default
- Optional schema v1.1.0 recipient metadata with fail-closed handling of
  plaintext credential values—and fail-closed older strict readers
- Locked dependency graphs for published CLI and Go artifacts, with scheduled
  audits, parity checks, and negative controls

**Upgrade cue**: if documents will carry `recipients` metadata, upgrade writers
and readers together. Documents without `recipients` stay readable on older
binaries.

**Install** (after the GitHub release is published):
`brew install 3leaps/tap/seclusor` ·
`scoop bucket add 3leaps https://github.com/3leaps/scoop-bucket && scoop install seclusor`

See `docs/releases/v0.2.0.md` for full notes and upgrade guidance.

## v0.1.6 (April 2026)

**Inline runtime decryption fix and workflow scenarios guide** — Fixes a bug where inline-encrypted values were not decrypted at runtime, and adds comprehensive end-to-end workflow documentation.

- **Bug fix (SC-012)**: `secrets run`, `secrets get`, and `secrets export-env` now correctly decrypt `sec:age:v1:` inline-encrypted values when identity files are provided. Previously these commands returned raw ciphertext for inline-encrypted documents
- **Workflow scenarios (SC-014)**: 7 new embedded docs in `docs/guides/scenarios/` covering bundle, inline, blob, CI/automation, team recipients, and a quick-reference command table. Available via `seclusor docs show scenarios/index`
- **Docs fix**: Corrected stale flag names in codecs guide (`--to-codec` → `--from`/`--to`)

See `docs/releases/v0.1.6.md` for full notes.

_(Older releases archived in `docs/releases/`. This file is kept short per project convention.)_
