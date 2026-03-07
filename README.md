# seclusor

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![Rust: 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org/)

> **Git-trackable secrets management.**

Seclusor encrypts secrets with [age](https://age-encryption.org/) so they can live alongside your code in version control — visible to the right people, opaque to everyone else. A library-first Rust core powers a full CLI, with first-class Go and TypeScript bindings so every part of your stack can manage secrets through the same engine.

**Lifecycle Phase**: `alpha` | See [VERSION](VERSION) for current version

## The Problem

Secrets don't belong in plaintext, but they do belong near the code that uses them. Your options today:

1. **HashiCorp Vault** — powerful, but requires running infrastructure and a network dependency for every decrypt
2. **Mozilla SOPS** — git-friendly, but no library API; you shell out or parse its output
3. **git-crypt** — transparent encryption, but no per-field visibility or multi-format support
4. **Roll your own** — envelope encryption, key management, recipient rotation, format detection… you'll be maintaining crypto glue forever

## What Seclusor Offers

- **Git-trackable**: Encrypted secrets commit, branch, diff, and merge like any other file.
- **age encryption**: X25519 recipients for team sharing, scrypt passphrases for ad-hoc use. Modern cryptography, simple key format.
- **Two storage codecs**: Bundle (whole-file opaque `.age`) for safety, inline (`sec:age:v1:` per-field) for git-friendly diffs. Convert freely between them.
- **Library-first**: Core logic lives in Rust crates. No shelling out — link directly from Rust, Go, or TypeScript.
- **Full CLI**: `secrets init`, `set`, `get`, `list`, `export-env`, `run -- <cmd>` — everything you need from the command line.
- **Safe by default**: `get` redacts values unless `--reveal` is passed. `list` never shows values. Secrets never appear in CLI args or shell history.
- **Permissively licensed**: MIT/Apache-2.0 dual licensed. Link statically or dynamically with no additional obligations.

## Quick Start

### As a Rust Library

```toml
[dependencies]
seclusor-crypto = "0.1"   # encrypt/decrypt with age
seclusor-keyring = "0.1"  # identity generation, recipient management
seclusor-core = "0.1"     # domain types, validation
```

```rust
use seclusor_crypto::{encrypt, decrypt, load_identity_file};

// Encrypt a secret for one or more age recipients
let ciphertext = encrypt(b"sk-live-abc123", &recipients)?;

// Decrypt using an identity file
let identities = load_identity_file("~/.config/seclusor/identity.txt")?;
let plaintext = decrypt(&ciphertext, &identities)?;
```

### As a CLI

```bash
# Generate an age identity
seclusor keys age identity generate --output ~/.config/seclusor/identity.txt

# Initialize a secrets file
seclusor secrets init --output secrets.json

# Manage secrets
seclusor secrets set --file secrets.json --key API_KEY --value "sk-live-abc123"
seclusor secrets get --file secrets.json --key API_KEY --reveal
seclusor secrets list --file secrets.json

# Export to environment
eval $(seclusor secrets export-env --file secrets.json --format export)

# Run a command with secrets injected
seclusor secrets run --file secrets.json -- node server.js

# Bundle encrypt/decrypt
seclusor secrets bundle encrypt --file secrets.json --recipient age1...
seclusor secrets bundle decrypt --file secrets.age --identity-file identity.txt
```

### Exit Codes

| Code | Name          | When                                      |
| ---- | ------------- | ----------------------------------------- |
| 0    | Success       | Command completed successfully            |
| 1    | Failure       | Generic failure                           |
| 30   | ConfigInvalid | Configuration or document validation fail |
| 50   | FileNotFound  | Required file not found                   |

## Architecture

Seclusor is a Rust workspace with six crates. Library crates are the architecture — CLI and FFI are thin consumers.

```
seclusor/
├── crates/
│   ├── seclusor-core/         # Domain types, validation, env export/import
│   ├── seclusor-crypto/       # age encryption (X25519 + scrypt), identity parsing
│   ├── seclusor-codec/        # Bundle + inline codecs, format conversion
│   ├── seclusor-keyring/      # Key generation, recipient discovery, rekey
│   ├── seclusor-ffi/          # C-ABI exports (cdylib + staticlib)
│   └── seclusor/              # CLI binary (thin adapter)
├── bindings/
│   ├── go/seclusor/           # Go CGo wrapper
│   └── typescript/            # TypeScript NAPI-RS addon
├── schemas/
│   └── seclusor/v1.0.0/       # JSON Schema for secrets documents
└── docs/
    └── decisions/             # ADRs, SDRs, DDRs
```

### Crate Dependency Graph

```
seclusor-core          ← leaf, no internal deps
    ↑
seclusor-crypto        ← depends on core
    ↑
seclusor-codec         ← depends on core, crypto
seclusor-keyring       ← depends on core, crypto
    ↑
seclusor-ffi           ← depends on all library crates
seclusor (CLI)         ← depends on all library crates
```

### Storage Codecs

**Bundle** — Whole-file age encryption. The entire secrets document is a single opaque `.age` ciphertext. Best for: distribution, archival, environments where you want zero plaintext structure visible.

**Inline** — Per-field encryption with `sec:age:v1:<base64>` markers. The document structure (keys, project slugs) remains readable; only values are encrypted. Best for: git diffs, code review, config files where you need to see what's there without decrypting.

Convert between them freely:

```bash
seclusor secrets convert --file secrets.json --to-codec inline --recipient age1...
seclusor secrets convert --file secrets.json --to-codec bundle --recipient age1...
```

## Language Bindings

### Go

```go
import "github.com/3leaps/seclusor/bindings/go/seclusor"

handle, err := seclusor.LoadSecretsJSON(string(jsonBytes))
if err != nil {
    log.Fatal(err)
}
defer handle.Close()

keys, err := handle.List("")
env, err := handle.ExportEnv("", "", false)
```

### TypeScript

TypeScript bindings via NAPI-RS are planned for v0.1.0.

## FFI Contract

The `seclusor-ffi` crate exposes a C-ABI surface using:

- **Opaque handles** for stateful objects (`SeclusorSecretsHandle`, `SeclusorKeyringHandle`)
- **JSON-over-FFI** for complex return types (credential views, env exports, key lists)
- **Thread-local error state** via `seclusor_last_error()` with result code enum
- **Panic-safe boundary** — all exports wrap logic in `catch_unwind`

Once v0.1.0 ships, the FFI surface is treated as stable for the v0.1.x line. See [ADR-0008](docs/decisions/ADR-0008-ffi-contract-json-over-ffi-and-opaque-handles.md) for the full contract.

## Security Model

### Encryption

Seclusor uses [age](https://age-encryption.org/) (ADR-0002):

- **X25519** key exchange for multi-recipient encryption
- **ChaCha20-Poly1305** authenticated encryption
- **scrypt** passphrase-based encryption for ad-hoc sharing
- **16 MiB** decrypt size limit, **1 MiB** inline value limit

### Safety Defaults

- Secrets never appear in CLI arguments or shell history
- `get` redacts by default; `--reveal` required to see values
- `list` never shows values
- Identity files require `0600` permissions on Unix
- Key material is never written to the repository root (pathguard)
- Data output goes to stdout, diagnostics to stderr (stdout purity)

See [SDR-0002](docs/decisions/SDR-0002-secret-input-channels-and-cli-arg-policy.md) for the secret input channel policy.

## Platform Support

| Platform            | Target                       | Status    |
| ------------------- | ---------------------------- | --------- |
| Linux x64 (glibc)   | `x86_64-unknown-linux-gnu`   | Primary   |
| Linux arm64 (glibc) | `aarch64-unknown-linux-gnu`  | Primary   |
| Linux x64 (musl)    | `x86_64-unknown-linux-musl`  | Supported |
| Linux arm64 (musl)  | `aarch64-unknown-linux-musl` | Supported |
| macOS arm64          | `aarch64-apple-darwin`       | Supported |
| Windows x64          | `x86_64-pc-windows-msvc`     | Future    |

## Development

```bash
# Build
cargo build

# Test
cargo test

# Full quality check
make check-all
```

### Quality Gates

- `cargo fmt --check` — zero diff
- `cargo clippy --workspace -- -Dwarnings` — zero warnings
- `cargo test` — all tests pass
- `cargo deny check` — all dependencies permissively licensed

## Supply Chain

- **License-clean**: All dependencies use MIT, Apache-2.0, or compatible licenses
- **Auditable**: `cargo tree` for the full dependency graph
- **SBOM-ready**: Compatible with CycloneDX via `cargo sbom`
- **No runtime network calls**: All functionality is local

```bash
cargo deny check licenses
cargo audit
```

## Ecosystem

Seclusor is part of the 3leaps platform library family:

| Library                                        | Scope                       | Purpose                                            |
| ---------------------------------------------- | --------------------------- | -------------------------------------------------- |
| **seclusor**                                   | Secrets management          | Git-trackable secrets with age encryption          |
| [ipcprims](https://github.com/3leaps/ipcprims) | Inter-process communication | Framed, multiplexed IPC primitives                 |
| [sysprims](https://github.com/3leaps/sysprims) | System operations           | Process control and system interaction primitives  |

Seclusor is a key dependency for the [Lanyte](https://github.com/lanytehq/lanyte) secure agent platform, which uses `seclusor-crypto` and `seclusor-keyring` as direct Rust crate dependencies for session attestation and Ed25519 key management.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Subject to [3 Leaps OSS policies](https://github.com/3leaps/oss-policies).

## Contributing

See [MAINTAINERS.md](MAINTAINERS.md) for governance and [AGENTS.md](AGENTS.md) for AI contributor protocols.

---

<div align="center">

**Built by the [3 Leaps](https://3leaps.net) team**

Part of the [Fulmen Ecosystem](https://github.com/fulmenhq)

</div>
