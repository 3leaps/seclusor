# Release Notes

**Content policy**: This file contains the most recent 3 releases (reverse chronological). Older releases are archived in `docs/releases/vX.Y.Z.md`.

## v0.2.2 (August 2026)

**Safer interactive input and compatibility-focused maintenance** — Hide
terminal value entry by default, normalize line-oriented passphrases across
platforms, extend encrypted-write self-lockout advisories, and refresh private
signing and build dependencies without changing public formats.

- **Interactive values:** terminal `secrets set --value-stdin` hides input and
  accepts Enter; explicit `--echo-value` restores visible entry and its existing
  EOF terminator. Piped and redirected stdin behavior is unchanged
- **Passphrases:** interactive, file, and stdin channels normalize one trailing
  LF or CRLF and reject empty normalized input; environment input remains
  byte-for-byte unchanged for narrow legacy recovery
- **Encrypted writes:** `set` and `import-env` warn when none of the already
  loaded identities belongs to the target recipient set; the advisory does not
  replace fail-closed recipient policy or post-write verification
- **Compatibility:** signing, digest, entropy, error, and embedded-doc build
  dependencies are refreshed with byte-exact signing-envelope coverage and no
  public API or data-format changes

**Upgrade cue:** scripts using piped input require no change. Interactive
`--value-stdin` now hides input and closes on Enter; add `--echo-value` only for
deliberate visible terminal entry.

The `secrets run` child-environment issue fixed in v0.2.1 is documented in
[GHSA-2w88-3q86-736g](https://github.com/3leaps/seclusor/security/advisories/GHSA-2w88-3q86-736g).

**Install** (after the GitHub release is published):
`brew upgrade seclusor` · `scoop update seclusor`

See `docs/releases/v0.2.2.md` for full notes, compatibility, and residuals.

## v0.2.1 (August 2026)

**Security patch** — Keep the identity passphrase out of processes launched by
`secrets run`, and stop a stale recipients list from silently restoring a
retired recipient after rotation. The published advisory is
[GHSA-2w88-3q86-736g](https://github.com/3leaps/seclusor/security/advisories/GHSA-2w88-3q86-736g).

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

_(Older releases archived in `docs/releases/`. This file is kept short per project convention.)_
