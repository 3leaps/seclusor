# Changelog

**Content policy**: This file contains the most recent 10 releases (reverse chronological). Older releases are archived in `docs/releases/vX.Y.Z.md`.

All notable changes to seclusor will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to Semantic Versioning.

## [Unreleased]

## [0.2.3] - 2026-11-14

Hardening and release-provenance update: encrypted pack-sealing guards,
`secrets run --clean-env`, macOS extended-ACL checks on private files,
signed dual-tag and `decernor` release-provenance controls, control-plane
decision records (`ADR-0013` and `DDR-0006`), Go 1.27+ FFI bitcode stripping,
and dependency lock refreshes. Document formats and Rust, Go, TypeScript, and
C-ABI contracts are unchanged.

### Added

- `secrets run --clean-env` and repeatable `--env-allow <VAR>` to scrub ambient
  parent environment variables down to a minimal OS baseline before overlaying
  project credentials. The `v0.2.1` `--passphrase-env` exclusion and
  passphrase-value equality checks still apply unconditionally, and child
  `stdin` is rebound to null when `--passphrase-stdin` unlocks a protected
  identity.
- `secrets init --codec inline` for creating an empty inline-encrypted skeleton
  with established schema `v1.1.0` recipient metadata on an absent target path,
  plus `-` stream support on `secrets inline encrypt --input` and `--output`.
- Repeatable `--recipient-file <path>` across recipient-taking CLI commands with
  first-seen public-key deduplication and recipient-count bounds.
- OpenPGP-signed dual release-tag helpers (`vX.Y.Z` and
  `bindings/go/seclusor/vX.Y.Z`), public release-signing pins
  (`docs/security/release-signing-keys.asc`,
  `docs/security/seclusor-minisign.pub`, `config/release/signing-subkey.txt`,
  `config/release/tagger-identity.txt`), `decernor` fingerprint anchors
  (`keys/expected-fingerprints.{txt,ndjson}`), and read-only SHA-pinned GitHub
  Actions workflow verification (`scripts/release-workflow-pin.py`,
  `scripts/test-release-controls.sh`).
- `ADR-0013` (control-plane secret-isolation and value-free invariant for MCP
  and graphical inspection surfaces), `DDR-0006` (`Proposed` dual native Rust
  and pure-Go implementation and conformance layout for `v0.3.0`), and
  `SDR-0004` (`RUSTSEC-2026-0374` advisory evaluation).

### Fixed

- `secrets set`, `secrets unset`, and `secrets import-env` now fail closed
  without modifying the target file when `--recipient`, `--recipient-file`,
  `--recipient-env-var`, or `--allow-recipient-mismatch` is passed against an
  unencrypted plaintext document (previously, `secrets set` with
  `--recipient-file` against a plaintext document created via `secrets init`
  without `--codec bundle` ignored the recipient flag and wrote the credential
  value in plaintext).
- On macOS, private file creation (age identities, Ed25519 signing keys, and
  decrypted plaintext outputs) clears inherited extended ACLs before writing
  private bytes and rejects parent directories whose ACL grants non-owner write,
  `add_file`, or `delete_child` access. Loading an existing private file on
  macOS warns on `stderr` when a non-owner extended ACL grant is present
  (`ls -le` / `chmod -N <path>`) and fails closed if ACL inspection fails. Linux
  retains its `0600` mode check; Windows remains outside POSIX/macOS ACL
  preflight.
- Plaintext file writers across the CLI and bindings enforce owner-only (`0600`)
  Unix permissions before writing and refuse symlink or multi-hardlink targets.
- Interactive passphrase and echoed value prompts on Unix now require a
  foreground controlling terminal and fail fast in non-interactive runners
  instead of hanging.

### Changed

- Refreshed root and TypeScript native `Cargo.lock` dependency graphs (including
  `rustix 1.1.6` for `RUSTSEC-2026-0486`) and updated the cross-workspace
  crypto parity manifest.
- Stripped LLVM bitcode and compiler command-line sections from prebuilt CGo
  `libseclusor_ffi.a` archives (`scripts/strip-ffi-bitcode.sh`) for Go 1.27+
  linker compatibility, and separated local development CGo linking behind the
  `seclusor_local` build tag.
- Aligned `LICENSE-MIT`, `LICENSE-APACHE`, and `NOTICE` (`3 Leaps, LLC`, North
  Carolina) across the workspace root, Go module, and TypeScript package,
  enforced via `make license-check`.

## [0.2.2] - 2026-08-17

Compatibility release: hidden terminal value entry, consistent line-oriented
passphrases, broader self-lockout advisories, and a private dependency
refresh. Document formats and Rust, Go, TypeScript, and C-ABI contracts are
unchanged.

### Added

- `--echo-value` opt-in for visible terminal `secrets set --value-stdin`. The
  switch is rejected unless stdin is a terminal. Visible mode keeps the existing
  EOF terminator.

### Fixed

- Interactive, file, and stdin passphrase channels now normalize a single
  trailing LF or CRLF line ending consistently and reject input that is empty
  after normalization. Environment passphrases remain byte-for-byte unchanged
  so identities created from legacy CRLF passphrase files can be recovered,
  replaced, and rekeyed.
- Encrypted `set` and `import-env` writes now emit the existing self-lockout
  advisory when none of the identities already loaded for the operation belongs
  to the target recipient set. The warning is advisory and does not replace
  recipient-policy enforcement or post-write verification.

### Changed

- Terminal `secrets set --value-stdin` is hidden by default, closes on Enter,
  and restores terminal state across success, errors, and interrupts. Piped and
  redirected stdin behavior is unchanged.
- Updated the private Ed25519, SHA-256, and entropy dependencies behind the
  existing signing wrappers, with byte-exact compatibility coverage for
  versioned signing envelopes and fixtures.
- Updated first-party error derives and replaced the embedded-docs YAML build
  manifest with JSON, removing the build-only YAML parser.

The `secrets run` child-environment issue fixed in v0.2.1 remains documented in
[GHSA-2w88-3q86-736g](https://github.com/3leaps/seclusor/security/advisories/GHSA-2w88-3q86-736g).

## [0.2.1] - 2026-08-11

### Security

This release fixes a privilege-boundary defect in `secrets run` and hardens
encrypted write paths against recipient-set divergence after identity rotation.
The published advisory is
[GHSA-2w88-3q86-736g](https://github.com/3leaps/seclusor/security/advisories/GHSA-2w88-3q86-736g)
(see it for CVSS, affected ranges, and CVE status).

- **`secrets run` child environment boundary:** when identity material is
  supplied with `--passphrase-env`, the named variable is excluded from the
  child process environment through a single construction chokepoint. The
  command also refuses to start if any effective child environment value equals
  the resolved passphrase (covering aliases under a different variable name).
  `--allow` / `--deny` continue to filter only which store keys are injected;
  they never controlled ambient environment pass-through.
  - Affected: **v0.1.4 – v0.2.0** (requires both `secrets run` and
    `--passphrase-env`)
  - Residual: the passphrase remains in the parent `seclusor` process
    environment for the lifetime of that invocation when supplied via
    `--passphrase-env`. Prefer `--passphrase-file` or `--passphrase-stdin` for
    ordinary use. This fix does **not** make `--passphrase-env` equivalent to
    those channels.
- **Recipient-set divergence on write:** write paths that establish or preserve
  recipient metadata (`set`, `import-env`, `rekey`, bundle encrypt) compare the
  write-target recipient set to recorded document metadata and **fail closed**
  on divergence, printing each public-key difference as `+age1…` / `-age1…`.
  Deliberate membership changes require an explicit `--allow-recipient-mismatch`
  on the same command (recipient-set only — not a general force switch). The
  guard reports a set difference the operator must read; it does not claim to
  classify “re-grant” vs intentional add.
  - Reported trap: **v0.2.0** only (`rekey` first shipped there)
  - Underlying missing cross-check: **v0.1.0 – v0.2.0** for writes that accept
    a recipient set, though the delta is only **detectable** once schema
    **v1.1.0** `recipients` metadata exists (v0.2.0+)
  - Residual: on legacy **v1.0.0** documents (no recorded recipient set) the
    comparison is **indeterminate**. When the operation covers every inline
    encrypted field (or writes a bundle), seclusor prints an explicit notice and
    establishes metadata from the write target; a partial inline write instead
    refuses and directs you to `secrets rekey`. It does not infer recipients
    from age stanzas. Prefer rekeying before relying on fail-closed divergence.
- **Explicit durable recipient refresh:** `secrets rekey --write-recipients PATH`
  optionally writes the canonical resulting public-key set to a named path after
  a successful rekey (atomic public-data write; never an implicit rewrite of
  `--recipient-file` unless the same path is named). Use this so a following
  write does not restore a retired recipient from a stale durable list. If the
  recipient-list write fails after the encrypted output commits, retry the
  refresh against that committed output with an identity for the new set.

If you may have been exposed via `--passphrase-env`: **upgrade to 0.2.1 first**,
then rotate the affected identity. On 0.2.1, recipient divergence fails closed
when metadata is present; rewrite durable recipient sources (or use
`--write-recipients` during rekey) before further encrypted writes. Treat
credentials reachable by the exposed child as compromised.

Interim workaround on unpatched binaries (stdin channel; `printf` is a shell
builtin so the value never appears in process arguments):

```bash
printf '%s' "$VAR" | env -u VAR \
  seclusor secrets run --passphrase-stdin … -- <command>
```

### Added

- `secrets rekey --write-recipients <path>` for explicit post-rekey recipient
  list refresh (canonical sorted public keys, one per line, trailing newline)
- `--allow-recipient-mismatch` on encrypted write commands that compare
  recipient metadata (deliberate set change only; not a general `--force`)
- Library three-state recipient-set comparison predicate for document writers
  that want the same delta check the CLI enforces

### Fixed

- `secrets run` no longer passes the identity passphrase environment variable
  through to the launched child (see Security)
- Encrypted write paths no longer succeed silently when the configured
  recipient set diverges from document recipient metadata (see Security)

### Changed

- Encrypted writes with recipient metadata now **fail closed** on
  write-target vs metadata divergence (previously could succeed silently —
  see Security). Deliberate membership changes use
  `--allow-recipient-mismatch`.
- Release workflow uploads the PGP public key (`release-key.asc`) with
  provenance / `--all` asset selection
- CI retains generated SBOM artifacts under stable package-named CycloneDX
  filenames for release audit trails

See `docs/releases/v0.2.1.md` for full notes and upgrade guidance.

## [0.2.0] - 2026-08-03

### Added

- Detached asset signing and verification with age-protected Ed25519 signing
  keys, streaming SHA-256 asset hashing, strict
  `seclusor.signature.v1` envelopes, and expected-key verification by default
- Read-side commands accept bundle, inline-encrypted, or plaintext secrets via
  automatic codec detection (`secrets get`, `list`, `validate`, `export-env`,
  `run`)
- `--identity-public-key age1…` identity selector with bounded keyring discovery
  (public metadata only; conflicts with `--identity-file`)
- `secrets validate` distinguishes full vs structural-only success on stdout
  (`valid` vs `structural-only valid`)
- Shell-safe `export-env --format export`: required `--allow`, TTY refuse without
  `--force`, verbose-only completion summary
- Go and C-ABI loaders for encrypted documents: `LoadSecretsBundle` /
  `LoadSecretsInline` and matching FFI constructors (pointer + length; full
  decrypt only)
- Classified runtime document load API in `seclusor-codec` (`ResolvedDocument`,
  source/mode tokens)
- Encrypting write path for `secrets set` / `import-env` (inline + bundle) with
  non-argv value channels (`--value-stdin` / `--value-file` / `--value-env`)
- Structural-only inline `unset` and description-only edits (no identity)
- `secrets rekey` for full-document recipient rewrite (including plaintext →
  encrypted transform)
- Schema **v1.1.0** optional top-level `recipients` metadata; establishing
  writes rewrite `schema_version` and emit a stderr notice
- `secrets init --codec bundle` create-only empty encrypted skeleton (explicit
  recipients required; no empty inline init; no `--force --codec`)
- Public `seclusor-codec` mutation API: `set_inline_value`, `unset_inline_value`,
  `set_inline_description`, `reencrypt_all_inline`, `mutate_bundle`,
  `SetInlineValueOptions`, `DescriptionAction`, related result types
- Public `seclusor-crypto` stanza helpers: `count_x25519_recipient_stanzas`,
  `count_inline_x25519_recipient_stanzas`
- Atomic ciphertext writer with CAS (Unix property-tested; Windows `ReplaceFileW`)
- App Note 04: encrypted write operations command matrix and residual table
- Pinned, locked, audited, and parity-checked dependency graphs for published
  CLI, Go, and private TypeScript-native build surfaces

### Changed

- Split the CLI implementation into focused command, handler, I/O, resolution,
  and test-support modules without changing the command surface
- Identity file loads enforce Unix owner UID in addition to mode `0600`
- Nested inline ciphertext inside a decrypted bundle is rejected (fail closed)
- Documentation for encrypted-read flows, identity discovery, and passphrase-env
  automation tradeoffs (App Note 02 and CLI guides)
- Added credential value and JSON-escaping guidance, including App Note 03 for
  special-character handling
- When `recipients` is present, JSON-at-rest documents must not carry direct
  plaintext credential values (fail closed on read and write; legacy docs
  without `recipients` keep mixed-value leniency). Decrypted bundle working
  copies use structure-only validation
- `SetInlineValueOptions` is `#[non_exhaustive]`; construct via
  `Default::default()` then field assignment from external crates
- Controlling-console preflight for interactive passphrase prompts (matches
  rpassword `/dev/tty` / `CONIN$`)

### Security

- Scheduled and pull-request security audits scan both committed Rust lockfiles
  under the same advisory policy
- Published artifact entrypoints enforce locked dependency resolution, with
  negative controls proving stale locks and dependency-graph divergence fail
- Crypto dependency closures are parity-checked across CLI/Go and
  TypeScript-native surfaces

### Compatibility

- Documents carrying top-level `recipients` use schema v1.1.0. Older binaries
  that predate recipients support and reject unknown fields **fail closed**
  on those documents (safe direction). Documents without `recipients` remain
  valid on older binaries.

## [0.1.6] - 2026-04-03

### Fixed

- Inline-encrypted values (`sec:age:v1:`) are now decrypted at runtime by `secrets run`, `secrets get`, and `secrets export-env` when identity files are provided (SC-012). Previously these commands returned the raw ciphertext string for inline-encrypted documents
- `secrets get --reveal` now correctly rejects inline ciphertext when no identity is provided, with a clear error message instead of returning the ciphertext
- Fixed stale flag names in `docs/guides/codecs.md` (`--to-codec`/`--file` → `--from`/`--to` and `--input`/`--output`)

### Added

- Workflow scenarios guide: 7 new embedded docs in `docs/guides/scenarios/` covering bundle, inline, blob, CI/automation, team recipients, and quick-reference workflows (SC-014)
- Cross-links between scenario guides and existing concept docs (bidirectional)

### Changed

- Updated Go prebuilt static libraries for v0.1.5 platform targets

See `docs/releases/v0.1.6.md` for full notes.

## [0.1.5] - 2026-04-02

### Added

- `secrets blob encrypt` and `secrets blob decrypt` commands for opaque file encryption (SC-010). Encrypt any file (shell scripts, configs, binary tokens) using age identity/recipient keys — no JSON parsing or schema validation
- 10 MB default size limit with `--allow-large` override (guardrail, not security boundary)
- Atomic writes on blob decrypt via `tempfile::NamedTempFile` + `persist()` to avoid partial output on failure
- Decrypt output created with 0600 permissions on Unix (decrypted content is assumed sensitive)

### Changed

- Release workflow checksum generation now uses `find` instead of `ls` (fixes shellcheck SC2012)

### Security

- Blob decrypt uses unique temp files with exclusive creation (no symlink or pre-existing file risk)
- Blob file size limit enforced at read time via bounded reader (no TOCTOU gap)

See `docs/releases/v0.1.5.md` for full notes.

## [0.1.4] - 2026-04-02

### Added

- Passphrase-protected identity files: generate and use age identity files encrypted with scrypt passphrases (SC-008). Four input channels: interactive prompt (`--passphrase`), environment variable (`--passphrase-env`), file (`--passphrase-file`), stdin (`--passphrase-stdin`).
- Library API for passphrase-protected identities in `seclusor-keyring`: `generate_identity_file_with_passphrase`, `load_identity_file_with_passphrase`, `load_identity_file_auto`, `is_passphrase_protected_identity`
- Help text on all CLI arguments across all commands (SC-007 Part A)
- Identity and recipients documentation guide (`docs/guides/identity-and-recipients.md`) explaining the conceptual model, file format, permissions, passphrase protection, and team workflows (SC-007 Part B)
- Homebrew formula and Scoop manifest for seclusor
- `update-homebrew-formula` and `update-scoop-manifest` Makefile targets wired into `release-upload`
- `release-upload-all` target for uploading platform binaries alongside provenance

### Changed

- Release assets now use org-standard bare binary naming (`seclusor-darwin-arm64`, `seclusor-linux-amd64`, etc.) instead of versioned archives (DDR-0003)
- `release-upload` now uploads provenance only (checksums, signatures, keys, notes); use `release-upload-all` for full assets
- CLI help text for `--value` and `--ref` explains the distinction and portability guidance (SC-007, carried from v0.1.3 cycle)
- `InlineEncrypted` error message no longer references passphrase (deferred until CLI support existed; now delivered in this release)
- Security guide updated: removed premature `secrets rekey` CLI example, added identity protection section

### Security

- Passphrase-protected identity files enforce 0600 permissions on Unix, same as plaintext identities. Passphrase files (`--passphrase-file`) additionally enforce current-user ownership
- Passphrases held as `SecretString` (zeroized on drop) at all CLI boundaries; never stored as plain `String`
- Protected identity file size capped at 8 KiB before decryption attempt
- Malformed armor in protected identity files fails closed (no plaintext fallback)

See `docs/releases/v0.1.4.md` for full notes.

## [0.1.3] - 2026-03-30

### Security

- Redacted all serde JSON error messages across CLI, FFI, and TypeScript bindings so malformed input never leaks secret material to console output or binding error state
- Defense-in-depth fallback sanitizer catches `invalid type:` and `invalid value:` error segments generically, independent of serde_json token formatting

### Added

- Lenient `secrets unset` recovery: when a secrets file contains malformed credentials (e.g., bare strings instead of credential objects), `unset` now falls back to raw JSON manipulation to remove the targeted entry without requiring the file to fully deserialize
- Credential format validation errors now include the key name, expected object shape, and a `secrets set` CLI hint — without revealing the malformed value
- Custom `Credential` deserializer rejects non-object entries (strings, arrays, numbers, booleans) with redaction-safe, actionable error messages
- Credential descriptions on the CLI: `secrets set --description`, `secrets get --show-description`, and `secrets list --verbose`
- Shared description normalization and validation for file, project, and credential descriptions, with schema updates to mirror the runtime contract

### Changed

- Quickstart documentation updated to clarify the init → set → encrypt → run workflow and the expected credential JSON shape
- Description validation now counts Unicode characters rather than UTF-8 bytes, matching the JSON schema contract

See `docs/releases/v0.1.3.md` for full notes.

## [0.1.2] - 2026-03-19

### Added

- Go bindings for Ed25519 signing workflows (D12)
- Signing parity tests between Rust and Go implementations
- The Go `seclusor` bindings now expose `GenerateSigningKeypair`, `Sign`, `Verify`, `SigningPublicKeyFromSecretKey`, and `WipeBytes`
- Full test coverage ensuring Rust and Go agree on key, signature, and error semantics

### Changed

- Public repo polish pass trimmed stale license allowances from `deny.toml`
- Updated top-level documentation and release notes to reflect shipped Go signing support in v0.1.2

See `docs/releases/v0.1.2.md` for full notes.

## [0.1.1] - 2026-03-17

### Added

- Ed25519 signing primitives in `seclusor-crypto` behind the `signing` feature flag: `generate_signing_keypair`, `sign`, `verify`, `signing_public_key`, and canonical byte conversion functions
- Ed25519 key types: `SigningKeypair`, `SigningSecretKey` (zeroized on drop, no `Debug`/`Clone`/serde), `SigningPublicKey`, `Signature`
- Four content-free signing error variants: `InvalidSecretKeyBytes`, `InvalidPublicKeyBytes`, `InvalidSignatureBytes`, `SignatureVerificationFailed`
- Go bindings Phase 1: platform-specific CGo files (`cgo_<os>_<arch>.go`) for dual local/CI library path resolution, matching the ipcprims/sysprims pattern
- `go-bindings.yml` CI workflow: cross-compiles `seclusor-ffi` static libraries for all supported platforms and opens a PR with prebuilt artifacts before each release tag
- Integration test harness for the `seclusor secrets run` subcommand
- ADR-0011 (Ed25519 signing placement and scoping) and DDR-0002 (Ed25519 signing byte contract)

### Security

- Pinned `actions/upload-artifact` to `v4.6.2` and `actions/download-artifact` to `v4.3.0` to address GHSA-cxww-7g56-2vh6 (zip-slip in artifact actions)

### Notes

- Ed25519 signing is Rust-native only in v0.1.1. Go and TypeScript signing bindings are intentionally deferred to v0.1.2 (tracked as D11B) to allow a deliberate FFI design pass before binding the signing contract to the stable v0.1.x ABI.

See `docs/releases/v0.1.1.md` for detailed release notes.

_(Older entries archived in `docs/releases/`)_
