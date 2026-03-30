# seclusor

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![Rust: 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org/)

> **Secure secrets management with age encryption.**

Seclusor is a library-first Rust project that lets developers, DevSecOps engineers, and integrators encrypt secrets with [age](https://age-encryption.org/). It provides a full CLI, secure runtime injection via `seclusor run`, and first-class bindings for Rust, Go, and TypeScript.

**Important**: While armored secrets _can_ be stored in git, this is not always advisable. See [App Note 01: Git Storage of Armored Secrets](docs/appnotes/01-git-armored-storage.md) for the risk continuum and guidance by sensitivity level.

**Lifecycle Phase**: `alpha` | Current version: **v0.1.3** (error redaction & credential recovery) | See [VERSION](VERSION) and [CHANGELOG.md](CHANGELOG.md)

## The Problem

Secrets don't belong in plaintext, but they often need to live near the code that uses them. Common alternatives include:

- **Cloud / managed secret stores** (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, HashiCorp Vault) — excellent but require network calls and infrastructure
- **Mozilla SOPS** — git-friendly but lacks a library API (requires shelling out)
- **git-crypt** — transparent but offers no per-field visibility or flexible formats
- **Password managers** (1Password, Bitwarden/Vaultwarden) — great for individuals, with varying automation support
- **HSMs** — appropriate for the highest-security keys and root material
- **Roll your own** — time-consuming and error-prone

Seclusor fills the gap for teams that want local-first, library-native, git-compatible secret management with strong defaults.

## What Seclusor Offers

- **Modern age encryption**: X25519 for team sharing and scrypt for passphrases. Strong defaults with size limits.
- **Two storage codecs**: Bundle (opaque, safest) and inline (`sec:age:v1:`) for when you need readable structure. Convert between them easily.
- **Ed25519 signing** (`seclusor-crypto/signing` feature): Generate keypairs, sign messages, and verify signatures. Available in Rust (v0.1.1) and Go (v0.1.2). Secret keys are zeroized on drop and stored encrypted at rest using the existing age backend.
- **Library-first design**: Use `seclusor-crypto`, `seclusor-codec`, and `seclusor-keyring` directly from Rust, Go, or TypeScript. No shelling out.
- **Secure CLI**: Full command set including `secrets run` (injects secrets without exposing them in CLI args, history, or process lists).
- **Safe by default**: Redaction, stdout purity, no secrets in arguments, strict validation.
- **Audience-focused**: Great for developers (local workflows), DevSecOps (secure pipelines), and integrators (library usage).

For guidance on storing armored files in git, see [App Note 01](docs/appnotes/01-git-armored-storage.md). For runtime patterns see [App Note 02](docs/appnotes/02-runtime-deployment-patterns.md).

## Quick Start

### As a Rust Library

```toml
[dependencies]
seclusor-crypto = "0.1"   # encrypt/decrypt with age
seclusor-keyring = "0.1"  # identity generation, recipient management
seclusor-core = "0.1"     # domain types, validation

# Optional: add Ed25519 sign/verify
seclusor-crypto = { version = "0.1", features = ["signing"] }
```

```rust
use seclusor_crypto::{encrypt, decrypt, load_identity_file};

// Encrypt a secret for one or more age recipients
let ciphertext = encrypt(b"example-secret-value-12345", &recipients)?;

// Decrypt using an identity file
let identities = load_identity_file("~/.config/seclusor/identity.txt")?;
let plaintext = decrypt(&ciphertext, &identities)?;
```

Ed25519 signing (requires `features = ["signing"]`):

```rust
use seclusor_crypto::{generate_signing_keypair, sign, verify};

let keypair = generate_signing_keypair()?;
let sig = sign(keypair.secret_key(), b"payload")?;
verify(keypair.public_key(), b"payload", &sig)?;

// Keys stored encrypted at rest — serialize the seed and encrypt with age
let seed_bytes = seclusor_crypto::signing_secret_key_to_bytes(keypair.secret_key());
let encrypted_key = encrypt(&seed_bytes, &recipients)?;
```

### Simplest Useful Case: Secure Local Run

Create a secrets file and run a command with injected environment variables (no secrets in shell history or process list):

```bash
# 1. Create identity (once)
seclusor keys age identity generate --output ~/.config/seclusor/identity.txt

# 2. Create and armor a simple secrets file
seclusor secrets init --output secrets.json --project myapp
# Add credentials with `secrets set`; the JSON shape is an object like:
# {"DB_PASSWORD":{"type":"secret","value":"..."}}
seclusor secrets set --file secrets.json --project myapp --key DB_PASSWORD --value "example-db-password-9xK7mP2qR8vT"
seclusor secrets bundle encrypt --file secrets.json --output secrets.age --recipient age1...yourrecipient...

# 3. Run with injected secrets (contrived example)
seclusor secrets run \
  --file secrets.age \
  --identity-file ~/.config/seclusor/identity.txt \
  --project myapp \
  --allow DB_* \
  -- env | grep DB_
```

Other access methods are supported: exporting to `.env` files, library calls, or building a simple secret server.

See the [App Notes](docs/appnotes/) for detailed guidance.

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
│   ├── seclusor-crypto/       # age encryption (X25519 + scrypt), Ed25519 signing (feature-gated)
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

The Go bindings (`bindings/go/seclusor`) use CGo over the `seclusor-ffi` static library and provide full access to secret document management, encryption, and keyring operations. Prebuilt static libraries for all supported platforms are committed to the repo and resolved at build time.

**Current Go surface**: encryption, secret document operations (`List`, `Get`, `ExportEnv`), bundle encrypt/decrypt, keyring management, and Ed25519 signing in v0.1.2.

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

TypeScript bindings via NAPI-RS are in development.

## FFI Contract

The `seclusor-ffi` crate exposes a C-ABI surface using:

- **Opaque handles** for stateful objects (`SeclusorSecretsHandle`, `SeclusorKeyringHandle`)
- **JSON-over-FFI** for complex return types (credential views, env exports, key lists)
- **Thread-local error state** via `seclusor_last_error()` with result code enum
- **Panic-safe boundary** — all exports wrap logic in `catch_unwind`

The FFI surface established in v0.1.0 is treated as stable for the v0.1.x line. Ed25519 signing was intentionally excluded from the first v0.1.1 FFI pass, then added in v0.1.2 after the Rust-side signing contract was reviewed. See [ADR-0008](docs/decisions/ADR-0008-ffi-contract-json-over-ffi-and-opaque-handles.md) and [ADR-0011](docs/decisions/ADR-0011-ed25519-signing-in-seclusor-crypto.md) for the full contract and rationale.

## Security Model

### Encryption

Seclusor uses [age](https://age-encryption.org/) (ADR-0002):

- **X25519** key exchange for multi-recipient encryption
- **ChaCha20-Poly1305** authenticated encryption
- **scrypt** passphrase-based encryption for ad-hoc sharing
- **16 MiB** decrypt size limit, **1 MiB** inline value limit

### Signing

The `seclusor-crypto/signing` feature adds Ed25519 digital signatures (added in v0.1.1):

- **Ed25519 plain mode** — 32-byte seed secret key, 32-byte public key, 64-byte signature, opaque message bytes
- **`SigningSecretKey`** implements `Zeroize`/`ZeroizeOnDrop`; no `Debug`, `Clone`, or serde to prevent accidental key exposure
- **Four content-free error variants** — no key material, message bytes, or signature bytes ever in error strings
- **Key at rest** — encrypt the 32-byte seed with the existing age `encrypt()`/`decrypt()` API; no new storage format
- Rust-native in v0.1.1; Go signing bindings added in v0.1.2. TypeScript signing remains out of scope.

See [ADR-0011](docs/decisions/ADR-0011-ed25519-signing-in-seclusor-crypto.md) and [DDR-0002](docs/decisions/DDR-0002-ed25519-signing-contract.md) for the full signing contract.

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
| macOS arm64         | `aarch64-apple-darwin`       | Supported |
| Windows x64         | `x86_64-pc-windows-msvc`     | Future    |

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

| Library                                        | Scope                       | Purpose                                                   |
| ---------------------------------------------- | --------------------------- | --------------------------------------------------------- |
| **seclusor**                                   | Secrets management          | Age encryption, secure runner, and cross-language library |
| [ipcprims](https://github.com/3leaps/ipcprims) | Inter-process communication | Framed, multiplexed IPC primitives                        |
| [sysprims](https://github.com/3leaps/sysprims) | System operations           | Process control and system interaction primitives         |

Seclusor is a key dependency for the [Lanyte](https://github.com/lanytehq/lanyte) secure agent platform, which uses `seclusor-crypto` and `seclusor-keyring` directly for session attestation and glassbreak credential handling.

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
