# Release Checklist

Use this checklist before tagging and publishing any `vX.Y.Z` release.

## Pre-Tag

1. `make release-preflight` passes (includes repo-status dirty-tree guard, prepush quality gates).
2. Working tree is clean (`git status` empty).
3. `VERSION` matches workspace Cargo version (`make version-check`).
4. Run `make clean` then `make build` (build depends on `embed-verify`, validating docs embedding path).
5. Release notes exist at `docs/releases/vX.Y.Z.md`.
6. All v0.1.0 briefs (D0-D8, D5C, D5D, D5E) show done status in local planning state.
7. Run Go bindings prep workflow and merge its PR before tagging:
   - `make go-bindings-ci`
   - Review and merge the auto-created PR
   - Wait for CI green on the merge commit
   - Confirm `bindings/go/seclusor/lib/<platform>/libseclusor_ffi.a` exists for all release platforms

## CI and Build Artifacts

1. `ci` workflow is green for the release commit.
   - Linux: full quality gates (fmt, clippy, test, deny, version-check, Go/TS bindings).
   - macOS arm64: clippy + test.
   - Windows: cross-check (type-check, no link) for x86_64-pc-windows-msvc and aarch64-pc-windows-msvc.
2. `release` workflow produced all required archives:
   - `x86_64-unknown-linux-gnu` (.tar.gz)
   - `aarch64-unknown-linux-gnu` (.tar.gz)
   - `aarch64-apple-darwin` (.tar.gz)
   - `x86_64-pc-windows-msvc` (.zip)
   - `aarch64-pc-windows-msvc` (.zip)
3. Draft release contains `SHA256SUMS` and `SHA512SUMS`.
4. SBOM artifact exists from CI (`bom.json` via CycloneDX).

## Security and Integrity

1. `cargo deny check licenses advisories` passed.
2. `cargo audit` passed.
3. Signatures created locally (`make release-sign`) and verified (`make release-verify`).
4. Public keys exported and attached (`make release-export-keys`).

## Publish Gate

1. Draft release notes reflect final asset set (5 platform archives + checksums).
2. Optional lanes (if omitted) are called out explicitly in notes.
3. Draft verified by four-eyes (`devrev`) and security (`secrev`) for release readiness.
4. Release commit carries both tags:
   - `vX.Y.Z`
   - `bindings/go/seclusor/vX.Y.Z`
5. Only after all checks pass: undraft/publish the GitHub release.
