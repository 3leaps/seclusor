# Go bindings

CGo wrapper for `crates/seclusor-ffi`.

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

`go-bindings-sync` copies:

- `crates/seclusor-ffi/seclusor.h` -> `bindings/go/seclusor/include/seclusor.h`
- `target/release/libseclusor_ffi.a` -> `bindings/go/seclusor/lib/local/<platform>/libseclusor_ffi.a`

The platform-specific `cgo_*.go` files search both paths in order:

- `bindings/go/seclusor/lib/local/<platform>/` for local developer builds
- `bindings/go/seclusor/lib/<platform>/` for CI-generated, committed release libs

`make go-test-committed` temporarily hides the local override for the host platform
so the Go module links against the committed release archive instead.

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
