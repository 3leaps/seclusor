# Development Guide

## Prerequisites

- Rust stable (1.80+)
- Go 1.22+ (for Go bindings)
- Node.js 20+ (for TypeScript bindings)
- `cargo-deny` (`cargo install cargo-deny`)
- `cargo-audit` (`cargo install cargo-audit`)
- `goneat` v0.5.8+ (for formatting and linting)
- `cbindgen` (for FFI header generation)

## Building

```bash
make build          # Full build including FFI and embed-verify
cargo build         # Rust workspace only
```

## Testing

```bash
cargo test --workspace --all-features   # All Rust tests
make go-test                            # Go bindings (requires local FFI build)
make ts-test                            # TypeScript bindings (requires local NAPI build)
make check-all                          # Full quality loop
```

### Feature-gated tests

The `signing` feature on `seclusor-crypto` is opt-in:

```bash
cargo test -p seclusor-crypto                      # default features only
cargo test -p seclusor-crypto --features signing   # includes signing tests
cargo test --workspace --all-features              # everything
```

## Branching and PRs

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for the full branching model.

**Quick version**: feature branches, PRs against `main`, CI must pass.

```bash
git checkout -b feat/crypto/my-feature
# ... develop ...
git push -u origin feat/crypto/my-feature
gh pr create --title "feat(crypto): my feature" --body "..."
```

## Quality gates

The CI workflow runs on every push to `main` and every PR:

| Gate              | Command                                                 | What it checks                  |
| ----------------- | ------------------------------------------------------- | ------------------------------- |
| Format            | `cargo fmt --all -- --check`                            | Rust formatting                 |
| Format (non-Rust) | `goneat fmt --check`                                    | Markdown, YAML, JSON            |
| Lint              | `cargo clippy --workspace --all-targets --all-features` | Rust lints                      |
| Lint (non-Rust)   | `goneat assess --categories lint`                       | YAML, shell, workflows          |
| Test              | `cargo test --workspace --all-features`                 | All Rust tests                  |
| License           | `cargo deny check licenses`                             | Dependency licenses             |
| Advisory          | `cargo deny check advisories`                           | Known vulnerabilities           |
| Version           | `make version-check`                                    | VERSION file matches Cargo.toml |
| Go bindings       | `go test ./...`                                         | Go wrapper tests                |
| TS bindings       | `npm test`                                              | TypeScript NAPI tests           |

Run `make prepush` locally to check all gates before pushing.

## Release process

See [RELEASE_CHECKLIST.md](../../RELEASE_CHECKLIST.md) for the full sequence.

**Summary**: feature PRs merge to `main` -> version bump -> Go bindings prep
workflow -> merge bindings PR -> tag -> release workflow -> sign -> publish.

## Workspace layout

```
crates/
  seclusor-core/      Domain types, validation, CRUD, env export
  seclusor-crypto/    age encryption + Ed25519 signing (feature-gated)
  seclusor-codec/     Bundle + inline storage codecs
  seclusor-keyring/   Identity/recipient management, rekeying
  seclusor-ffi/       C-ABI FFI exports for Go/TypeScript bindings
  seclusor/           CLI binary (thin adapter over library crates)
bindings/
  go/seclusor/        Go CGo wrapper + prebuilt platform libraries
  typescript/         TypeScript NAPI-RS native addon
docs/
  decisions/          ADRs, DDRs, SDRs
  guides/             User and developer guides
  releases/           Per-version release notes
  appnotes/           Application notes and patterns
```

## FFI development

When modifying FFI exports:

1. Update Rust code in `crates/seclusor-ffi/src/`
2. Regenerate C header: `make ffi-header`
3. Sync to Go bindings: `make go-sync`
4. Update Go wrapper functions in `bindings/go/seclusor/`
5. Run Go tests: `make go-test`

The CI-generated header (via `cbindgen`) is the source of truth. Local
`make ffi-header` is for development iteration.
