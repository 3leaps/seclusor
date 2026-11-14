# Go bindings

CGo wrapper for `crates/seclusor-ffi`.

Secrets handles:

- `LoadSecretsJSON(string)` — plaintext secrets document
- `LoadSecretsBundle([]byte, *KeyringHandle)` — age bundle ciphertext (full decrypt)
- `LoadSecretsInline([]byte, *KeyringHandle)` — inline-encrypted JSON (full decrypt)

Signing (from earlier releases):

- Ed25519 signing key generation
- public-key derivation from the canonical 32-byte seed
- sign / verify helpers over byte slices

Canonical signing forms remain:

- secret key: 32-byte Ed25519 seed
- public key: 32 bytes
- signature: 64 bytes

Secret-key hygiene:

- signing APIs return and accept the canonical 32-byte seed as a normal Go
  `[]byte`
- callers should keep secret-key slices short-lived
- use `WipeBytes(secretKey)` promptly after age-encrypting the seed for storage
  or after completing signing work
- this is best-effort zeroing of the current slice contents; Go runtime behavior
  may still leave other copies outside package control

## Local workflow

1. Generate/sync FFI artifacts:

```bash
make go-bindings-sync
```

2. Build or test the Go module:

```bash
make go-build
make go-test
make go-test-committed
```

`go-bindings-sync` copies (and strips embedded compiler bitcode sections from):

- `crates/seclusor-ffi/seclusor.h` -> `bindings/go/seclusor/include/seclusor.h`
- `target/release/libseclusor_ffi.a` -> `bindings/go/seclusor/lib/local/<platform>/libseclusor_ffi.a`

The platform-specific `cgo_*.go` files select between the committed release archive and the local build via the `seclusor_local` build tag:

- Default (`!seclusor_local`, used by external module consumers and `make go-test-committed`): links `bindings/go/seclusor/lib/<platform>/`
- `-tags seclusor_local` (used by `make go-build` and `make go-test`): links `bindings/go/seclusor/lib/local/<platform>/`

Committed release-lib target folders for v0.1.1:

- `darwin-amd64`
- `darwin-arm64`
- `linux-amd64`
- `linux-arm64`
- `windows-amd64`

Supported local static-lib target folders:

- `darwin-arm64`
- `linux-amd64`
- `linux-arm64`
