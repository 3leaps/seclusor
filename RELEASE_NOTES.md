# Release Notes

**Content policy**: This file contains the most recent 3 releases (reverse chronological). Older releases are archived in `docs/releases/vX.Y.Z.md`.

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

## v0.1.4 (April 2026)

**Passphrase-protected identities, CLI documentation, and release infrastructure** — Adds SSH-key-style passphrase protection for age identities, completes CLI help text, and aligns release packaging with org conventions.

- Passphrase-protected identity files with four input channels (SC-008)
- Help text on all CLI arguments (SC-007 Part A)
- Identity and recipients documentation guide (SC-007 Part B)
- Homebrew and Scoop distribution; org-standard asset naming (DDR-0003)

See `docs/releases/v0.1.4.md` for full notes.

_(Older releases archived in `docs/releases/`. This file is kept short per project convention.)_
