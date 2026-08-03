# Release Notes

**Content policy**: This file contains the most recent 3 releases (reverse chronological). Older releases are archived in `docs/releases/vX.Y.Z.md`.

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

## v0.1.5 (April 2026)

**Blob encryption for opaque files** — Encrypt any file (shell scripts, configs, binary tokens) as age ciphertext.

- `secrets blob encrypt` and `secrets blob decrypt` for opaque file encryption (SC-010)
- 10 MB default size limit with `--allow-large` override
- Atomic writes on blob decrypt; output created with 0600 permissions on Unix

See `docs/releases/v0.1.5.md` for full notes.

_(Older releases archived in `docs/releases/`. This file is kept short per project convention.)_
