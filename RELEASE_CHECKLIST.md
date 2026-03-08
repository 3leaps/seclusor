# Release Checklist

Use this checklist before tagging and publishing any `vX.Y.Z` release.

## Pre-Tag

1. `make release-preflight` passes.
2. Working tree is clean (`git status` empty).
3. `VERSION` matches workspace Cargo version (`make version-check`).
4. Release notes exist at `docs/releases/vX.Y.Z.md`.
5. D0-D8 briefs show approved status in local planning state.

## CI and Build Artifacts

1. `ci` workflow is green for the release commit.
2. `release` workflow produced all required archives:
   - `x86_64-unknown-linux-gnu`
   - `aarch64-unknown-linux-gnu`
   - `aarch64-apple-darwin`
3. Draft release contains `SHA256SUMS` and `SHA512SUMS`.
4. SBOM artifact exists from CI (`bom.json` via CycloneDX).

## Security and Integrity

1. `cargo deny check licenses advisories` passed.
2. `cargo audit` passed.
3. Signatures created locally (`make release-sign`) and verified (`make release-verify`).
4. Public keys exported and attached (`make release-export-keys`).

## Publish Gate

1. Draft release notes reflect final asset set.
2. Optional lanes (if omitted) are called out explicitly in notes.
3. Draft verified by four-eyes (`devrev`) and security (`secrev`) for release readiness.
4. Only after all checks pass: undraft/publish the GitHub release.
