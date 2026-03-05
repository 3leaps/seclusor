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
```

`go-bindings-sync` copies:

- `crates/seclusor-ffi/seclusor.h` -> `bindings/go/seclusor/include/seclusor.h`
- `target/release/libseclusor_ffi.a` -> `bindings/go/seclusor/lib/local/<platform>/libseclusor_ffi.a`

Supported local static-lib target folders in this bootstrap phase:

- `darwin-arm64`
- `linux-amd64`
- `linux-arm64`
