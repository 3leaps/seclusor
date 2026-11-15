# Release Notes

**Content policy**: This file contains the most recent 3 releases (reverse chronological). Older releases are archived in `docs/releases/vX.Y.Z.md`.

## v0.2.3 (November 2026)

**Encrypted pack sealing, clean child environments, macOS ACL guards, and signed release provenance** — Fail-closed recipient flags on unencrypted targets, `secrets run --clean-env` ambient environment scrubbing, macOS extended-ACL protection for private files, and OpenPGP-signed dual release tags with `decernor` fingerprint anchors. Document formats and Rust, Go, TypeScript, and C-ABI contracts are unchanged.

- **Pack-sealing guard:** `secrets set`, `secrets unset`, and `secrets import-env` now fail closed without modifying the file when `--recipient`, `--recipient-file`, `--recipient-env-var`, or `--allow-recipient-mismatch` is passed against an unencrypted plaintext document (previously, `secrets set` with `--recipient-file` against a plaintext document created via `secrets init` without `--codec bundle` ignored the recipient flag and wrote the credential value in plaintext). `secrets init --codec inline` and `-` stream support on `secrets inline encrypt` are now supported, and `--recipient-file` is repeatable across recipient-taking commands
- **`secrets run --clean-env`:** scrubs inherited ambient environment variables down to a minimal OS baseline plus repeatable `--env-allow <VAR>`, while preserving the v0.2.1 `--passphrase-env` exclusion and passphrase-value equality guard and rebinding child `stdin` to null after `--passphrase-stdin` unlock
- **macOS private-file ACLs:** creating identity files, signing keys, or decrypted outputs on macOS clears inherited extended ACLs before writing private bytes and refuses parent directories whose ACL grants non-owner write, `add_file`, or `delete_child` access; loading an existing private file on macOS warns on `stderr` when a non-owner ACL grant is present (`ls -le` / `chmod -N <path>`) and fails closed if ACL inspection fails. Linux keeps its `0600` mode check; Windows is not covered by POSIX/macOS ACL preflight
- **Signed release provenance & Go 1.27+:** v0.2.3 is the first release published with OpenPGP-signed dual annotated tags (`v0.2.3` and `bindings/go/seclusor/v0.2.3`), committed public signing pins (`docs/security/`), `decernor` fingerprint anchors (`keys/expected-fingerprints.{txt,ndjson}`), read-only SHA-pinned workflows, and LLVM bitcode stripping on prebuilt Go FFI archives

**Upgrade cue:** if a macOS load prints an extended-ACL warning, inspect the file with `ls -le <path>` and clear the ACL with `chmod -N <path>`. If a script passed `--recipient*` to `secrets set` against a plaintext file, initialize with `secrets init --codec bundle` or `secrets init --codec inline` (or convert with `secrets rekey` / `inline encrypt` / `bundle encrypt`) and re-encrypt any value that was previously written in plaintext.

If you are still on v0.2.0 or earlier, this release also includes the v0.2.1 `secrets run` fix:
[GHSA-2w88-3q86-736g](https://github.com/3leaps/seclusor/security/advisories/GHSA-2w88-3q86-736g).
This release does not reopen that advisory.

**Install** (after the GitHub release is published):
`brew upgrade seclusor` · `scoop update seclusor`

See `docs/releases/v0.2.3.md` for full notes and `docs/releases/v0.2.3-announce.md`
for a short announcement.

## v0.2.2 (August 2026)

**Type a secret without it showing on screen** — Hidden terminal value entry,
consistent LF/CRLF passphrase-file handling across Windows and Unix, a
self-lockout heads-up on encrypted writes, and a drop-in dependency refresh.
Document formats and Rust, Go, TypeScript, and C-ABI contracts are unchanged.

- **Interactive values:** type at the `Value:` prompt; keystrokes are hidden
  and Enter finishes. `--echo-value` is opt-in visible typing (still ends on
  EOF). Piped and redirected stdin is unchanged
- **Passphrases:** file and stdin channels treat a trailing LF or CRLF the
  same and reject empty input. `--passphrase-env` stays exact-byte for the
  narrow legacy-recovery path
- **Encrypted writes:** `set` and `import-env` warn when none of the already
  loaded identities belongs to the target recipient set. Verify decryptability
  before retiring an old identity; the warning is not a safety verdict
- **Compatibility:** signing and build internals refresh with byte-exact
  envelope coverage and no library, binding, FFI, or data-format changes

**Upgrade cue:** scripts that pipe values need no change. If you type values
at a prompt, press Enter — not EOF. First-time install uses `brew install`
/ `scoop install`; existing installs use `brew upgrade` / `scoop update`.

If you are still on v0.2.0 or earlier, this release also includes the v0.2.1
`secrets run` fix:
[GHSA-2w88-3q86-736g](https://github.com/3leaps/seclusor/security/advisories/GHSA-2w88-3q86-736g).
This release does not reopen that advisory.

**Install** (after the GitHub release is published):
`brew upgrade seclusor` · `scoop update seclusor`

See `docs/releases/v0.2.2.md` for full notes and `docs/releases/v0.2.2-announce.md`
for a short announcement.

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

_(Older releases archived in `docs/releases/`. This file is kept short per project convention.)_
