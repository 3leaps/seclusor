# Release Checklist

Use this checklist before tagging and publishing any `vX.Y.Z` release.

## Pre-Release

1. All feature PRs for this release are merged to `main`.
2. `main` CI is green.
3. `make release-preflight` passes on local `main` (in sync with remote).
4. Working tree is clean (`git status` empty).
5. `VERSION` matches workspace Cargo version (`make version-check`).
6. Run `make clean` then `make build` (build depends on `embed-verify`,
   validating docs embedding path).
7. Release notes exist at `docs/releases/vX.Y.Z.md`.
8. All planned briefs for this release show done status.

## Version Bump

9. Update `VERSION` and workspace `Cargo.toml` version:
   ```bash
   make version-bump VERSION=X.Y.Z
   git push origin main
   ```
10. Wait for CI green on version bump commit.

## Go Bindings Prep

11. Verify local and remote are in sync before triggering the workflow:
    ```bash
    git fetch origin
    git log --oneline origin/main..HEAD   # must be empty
    git log --oneline HEAD..origin/main   # must be empty
    ```
12. Trigger Go bindings prep workflow:
    ```bash
    make go-bindings-ci
    ```
13. Review and merge the auto-created PR (adds platform `.a` files).
14. Wait for CI green on the merge commit.
15. Pull the merge commit locally:
    ```bash
    git pull origin main
    ```
16. Confirm `bindings/go/seclusor/lib/<platform>/libseclusor_ffi.a` exists
    for all release platforms.

## Tag and Release

17. Create annotated tags on the merge commit:
    ```bash
    VERSION=$(cat VERSION)
    git tag -a "v${VERSION}" -m "v${VERSION}"
    git tag -a "bindings/go/seclusor/v${VERSION}" -m "bindings/go/seclusor/v${VERSION}"
    git push origin "v${VERSION}" "bindings/go/seclusor/v${VERSION}"
    ```
    **IMPORTANT**: Both tags must point to the same commit — the Go bindings
    PR merge commit. The Go submodule tag is required so
    `go get github.com/3leaps/seclusor/bindings/go/seclusor@vX.Y.Z` resolves.
18. Monitor release workflow for all 5 platform assets.

## CI and Build Artifacts

19. `ci` workflow is green for the release commit.
    - Linux: full quality gates (fmt, clippy, test, deny, version-check,
      Go/TS bindings).
    - macOS arm64: clippy + test.
    - Windows: cross-check (type-check, no link) for x86_64-pc-windows-msvc
      and aarch64-pc-windows-msvc.
20. `release` workflow produced all required assets (bare binaries, no archives):
    - `seclusor-linux-amd64`
    - `seclusor-linux-arm64`
    - `seclusor-darwin-arm64`
    - `seclusor-windows-amd64.exe`
    - `seclusor-windows-arm64.exe`
21. Draft release contains `SHA256SUMS` and `SHA512SUMS`.
22. SBOM artifact exists from CI (`bom.json` via CycloneDX).

## Security and Integrity

23. `cargo deny check licenses advisories` passed.
24. `cargo audit` passed.
25. Signatures created locally (`make release-sign`) and verified
    (`make release-verify`).
26. Public keys exported and attached (`make release-export-keys`).

## Publish Gate

27. Draft release notes reflect final asset set (5 platform binaries +
    checksums).
28. Optional lanes (if omitted) are called out explicitly in notes.
29. Draft verified by four-eyes (`devrev`) and security (`secrev`) for
    release readiness.
30. Only after all checks pass: undraft/publish the GitHub release.

## Post-Publish

31. Upload signed assets and release notes (also triggers homebrew and scoop
    update targets automatically):
    ```bash
    make release-upload
    ```
32. Review and commit homebrew-tap formula update:
    ```bash
    cd ../homebrew-tap
    git diff Formula/seclusor.rb
    make audit APP=seclusor
    make test APP=seclusor
    git add Formula/seclusor.rb && git commit -m "Update seclusor to vX.Y.Z"
    git push
    ```
33. Review and commit scoop-bucket manifest update:
    ```bash
    cd ../scoop-bucket
    git diff bucket/seclusor.json
    python3 -m json.tool bucket/seclusor.json >/dev/null
    git add bucket/seclusor.json && git commit -m "Update seclusor to vX.Y.Z"
    git push
    ```

## Troubleshooting: Local/Remote Divergence

The Go bindings workflow runs on remote HEAD. If you have unpushed local
commits when you trigger the workflow, the PR it creates will diverge from
your local tree.

**Before running `make go-bindings-ci`**, always verify:

```bash
git fetch origin
git log --oneline origin/main..HEAD   # must be empty
git log --oneline HEAD..origin/main   # must be empty
```

If divergence occurs, pull remote first, resolve any conflicts, and retry.
