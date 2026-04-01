# DDR-0003: Release Asset Naming Convention

Status: Accepted  
Date: 2026-03-31  
Owner: devlead

## Context

The seclusor release workflow (v0.1.0–v0.1.3) produced assets using Rust target
triples with version prefixes and archive wrappers:

```
seclusor-v0.1.3-aarch64-apple-darwin.tar.gz
seclusor-v0.1.3-x86_64-unknown-linux-gnu.tar.gz
seclusor-v0.1.3-x86_64-pc-windows-msvc.zip
```

Every other tool across both the 3leaps and FulmenHQ orgs uses a simpler
convention: bare binaries named `<app>-<os>-<arch>` with `.exe` only on Windows.
This includes Go tools (kitfly, gonimbus, dimlox) and Rust tools (refbolt).

The mismatch caused the homebrew tap's `update-formula.sh` script to fail for
seclusor because it expects asset names matching the `<app>-<os>-<arch>` pattern.
It also blocks future scoop bucket integration, which expects
`<app>-windows-<arch>.exe` assets (see `fulmenhq/scoop-bucket`).

## Decision

Release assets MUST follow the org-wide naming convention:

| Platform      | Asset name                   |
| ------------- | ---------------------------- |
| Linux amd64   | `seclusor-linux-amd64`       |
| Linux arm64   | `seclusor-linux-arm64`       |
| macOS arm64   | `seclusor-darwin-arm64`      |
| macOS amd64   | `seclusor-darwin-amd64`      |
| Windows amd64 | `seclusor-windows-amd64.exe` |
| Windows arm64 | `seclusor-windows-arm64.exe` |

Rules:

1. **No version in filename** — the version is in the tag and release metadata.
2. **No archive wrappers** — bare binaries on Unix, `.exe` on Windows.
3. **OS uses Go-style names** — `linux`, `darwin`, `windows` (not Rust triples).
4. **Arch uses Go-style names** — `amd64`, `arm64` (not `x86_64`, `aarch64`).
5. **Checksums** — `SHA256SUMS` and `SHA512SUMS` reference these filenames.

## Rationale

- **Homebrew compatibility**: The 3leaps homebrew tap `update-formula.sh`
  resolves assets by the pattern `<app>-<os>-<arch>` using the GitHub release
  API `digest` field for sha256. No version parsing or archive extraction needed.
- **Scoop compatibility**: The FulmenHQ scoop bucket `update-manifest.sh` resolves
  Windows assets by `<app>-windows-<arch>.exe` and reads hashes from `SHA256SUMS`.
  Bare `.exe` assets can be shimmed directly without extraction.
- **Consistency**: Every release across both orgs follows the same convention.
  Tooling written for one repo works for all.
- **Simplicity**: Bare binaries are simpler to consume. Users `chmod +x` and run.
  No tar/unzip step. Curl-pipe-install scripts are one line shorter.

## Consequences

- The release workflow maps Rust target triples to the canonical asset names in
  the matrix definition. The mapping is explicit and auditable.
- Existing install instructions referencing the old archive names will break.
  Since seclusor is pre-1.0 alpha, this is acceptable.
- Future platforms (e.g., FreeBSD, RISC-V) follow the same `<app>-<os>-<arch>`
  pattern.
- When seclusor is added to a 3leaps scoop bucket, the Windows assets will work
  without modification.
