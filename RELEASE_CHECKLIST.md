# Release Checklist

Use this checklist before tagging and publishing any `vX.Y.Z` release.

## Pre-Release

1. All feature PRs for this release are merged to `main`.
2. `main` CI is green.
3. `make release-preflight` passes on local `main` (in sync with remote).
4. Working tree is clean (`git status` empty).
5. `VERSION` matches workspace Cargo version (`make version-check`).
6. Run `make pr-final`.
7. Run `make clean` then `make build` (build depends on `embed-verify`,
   validating docs embedding path).
8. Release notes exist at `docs/releases/vX.Y.Z.md`.
9. All planned briefs for this release show done status.

## Version Bump

10. Create a release/version branch from `main`:

```bash
git switch -c chore/release-vX.Y.Z
```

11. Update `VERSION` and workspace `Cargo.toml` version:

```bash
make version-set V=X.Y.Z
make pr-final
```

12. Push the branch, open a PR, and merge after review and green CI.
13. Pull the merge commit locally:

```bash
git switch main
git pull origin main
```

## Go Bindings Prep

14. Verify local and remote are in sync before triggering the workflow:
    ```bash
    git fetch origin
    git log --oneline origin/main..HEAD   # must be empty
    git log --oneline HEAD..origin/main   # must be empty
    ```
15. Trigger the read-only Go bindings prep workflow:
    ```bash
    make go-bindings-ci
    ```
16. After the workflow completes, download and digest-verify the staged FFI
    bundle (`go-bindings-vX.Y.Z`, with LLVM bitcode stripped across all 5 Go
    targets), open a reviewed PR, and merge:
    ```bash
    git switch -c chore/go-bindings-vX.Y.Z
    RELEASE_RUN_ID=<run-id> RELEASE_RUN_ATTEMPT=<attempt> make go-bindings-fetch
    make pr-final
    ```
17. Wait for CI green on the merge commit.
18. Pull the merge commit locally:
    ```bash
    git switch main
    git pull origin main
    ```
19. Confirm `bindings/go/seclusor/lib/<platform>/libseclusor_ffi.a` exists
    for all release platforms.

## Tag and Release

20. On the clean `main` merge commit, copy the literal full SHA of the reviewed
    merge commit from the merged PR and run the local signed-tag gate. Keep the
    same value for every tag and verification step while `main` identifies the
    release commit. Never replace the literal SHA with a newly resolved `HEAD`
    or `origin/main`:

    ```bash
    export SECLUSOR_RELEASE_COMMIT='<literal full SHA of reviewed merge commit>'
    make release-preflight
    make release-tag
    make release-verify-tag
    ```

    The helpers create and verify both `vX.Y.Z` and
    `bindings/go/seclusor/vX.Y.Z` as signed annotated tag objects directly on
    the same `origin/main` commit. The Go module tag is required for
    `go get github.com/3leaps/seclusor/bindings/go/seclusor@vX.Y.Z`.
    After the maintainer's explicit publication cue, run:

    ```bash
    make release-push-tag
    make release-verify-remote-tag
    ```

    The push is atomic across both tags; the remote verifier requires GitHub
    `Verified` with reason `valid` for each tag object. Do not advance `main`
    between the tag push and remote verification: the gate requires the pinned
    release commit to remain at both local `HEAD` and freshly fetched
    `origin/main` throughout this sequence.

    `SECLUSOR_RELEASE_COMMIT` must be a literal lowercase 40-hex SHA matching
    the reviewed `HEAD` and `origin/main` at the tag ceremony. The signing
    helper requires an exact signing-subkey selector in
    `SECLUSOR_PGP_KEY_ID` (trailing `!`), `SECLUSOR_GPG_HOMEDIR`,
    `SECLUSOR_GPG_SIGNING_FINGERPRINT`, and the infosec tagger identity in
    `SECLUSOR_TAGGER_NAME` / `SECLUSOR_TAGGER_EMAIL`. The maintainer sets those
    through the release environment. The helper requires an interactive GPG
    terminal. For fingerprint anchors and key verification, set
    `SECLUSOR_DECERNOR_BIN` to an absolute path to a release-tag-built
    decernor version 0.1.8 or newer; ceremony targets have no PATH fallback.
    Generate `docs/security/release-signing-keys.asc`,
    `docs/security/seclusor-minisign.pub`, `config/release/signing-subkey.txt`,
    and `keys/expected-fingerprints.{txt,ndjson}` with
    `make release-insert-anchors` and review the change before tagging. On a
    signing-key rotation, merge refreshed anchors before the first new tag.

21. Monitor the read-only `release` workflow (`release.yml`) for all 5 platform
    assets staged into the `release-packages-vX.Y.Z` workflow artifact. The
    workflow holds `contents: read` only and never creates or mutates a GitHub
    Release.

## CI and Build Artifacts

22. `ci` workflow is green for the release commit.
    - Linux: full quality gates (fmt, clippy, test, deny, version-check,
      workflow-pin verification, Go/TS bindings).
    - Native tests across Linux (`x86_64`, `aarch64`), macOS (`aarch64`), and
      Windows (`x86_64`, `aarch64`).
    - Windows cross-check (type-check, no link) for `x86_64-pc-windows-msvc`
      and `aarch64-pc-windows-msvc`.
23. `release` workflow produced all required assets (bare binaries, no archives)
    inside `release-packages-vX.Y.Z`:
    - `seclusor-linux-amd64`
    - `seclusor-linux-arm64`
    - `seclusor-darwin-arm64`
    - `seclusor-windows-amd64.exe`
    - `seclusor-windows-arm64.exe`
24. Download, verify, sign, and create the GitHub draft release locally from the
    verified workflow artifact:
    ```bash
    RELEASE_RUN_ID=<run-id> RELEASE_RUN_ATTEMPT=<attempt> make release-download
    make release-stage-anchors
    make release-checksums
    make release-sign
    make release-export-keys
    make release-notes
    make release-verify
    RELEASE_RUN_ID=<run-id> RELEASE_RUN_ATTEMPT=<attempt> make release-create-draft
    ```
    (Or run `RELEASE_RUN_ID=<run-id> RELEASE_RUN_ATTEMPT=<attempt> make release`
    for the full clean-to-draft sequence.)
25. SBOM artifact exists from CI (`*.cdx.json` via CycloneDX).
    To regenerate the artifact from an exact release tag, dispatch the SBOM-only
    CI lane from the default branch:
    ```bash
    gh workflow run ci.yml --ref main -f source_ref=vX.Y.Z
    ```

## Security and Integrity

26. `cargo deny check licenses advisories` passed.
27. `cargo audit` passed.
28. Signatures created locally (`make release-sign`) and verified
    (`make release-verify`).
29. Public keys exported (`make release-export-keys`) and verified against the
    tagged commit's inert blobs before draft creation.

### Dependency-graph integrity

seclusor implements crucible **EPR-0001** (_published artifacts carry a pinned,
enforced, audited, parity-checked dependency graph_) for its binary surfaces. This
repository adopts that principle via the gates below; it does not restate it. See
`3leaps/crucible docs/decisions/EPR-0001-published-artifact-dependency-integrity.md`.

**Standing rule — refresh all committed locks in one PR.** Every dependency change
refreshes **both** committed lockfiles together, in the same PR, so they never
drift and are reviewed as one set:

- `Cargo.lock` (root workspace — CLI + FFI/Go surfaces)
- `bindings/typescript/native/Cargo.lock` (the TS native addon — a separate Cargo
  workspace)

After any bump, regenerate both and confirm the security-critical shared crypto
components (`age`, `x25519-dalek`, `zeroize`, and their curve/AEAD transitives)
still resolve to identical upstream source versions across the two locks.

**How the gates enforce it:**

- **Pin** — both locks are committed (the native lock is no longer gitignored).
- **Enforce** — every published-artifact build routes through the canonical
  entrypoint `scripts/cargo-artifact-build.sh`, which injects `--locked`: the CLI
  release assets (`release.yml`), the FFI/Go prebuilts (`go-bindings.yml`, incl.
  `cargo zigbuild`), and the `build-release`/`build-ffi` make targets; the TS
  `.node` (`build-native.js`) enforces `--locked` directly. So a committed lock the
  build could silently ignore cannot exist. `scripts/check-locked-artifact-builds.py`
  (a CI static guard, proven by `scripts/negative-control-locked-guard.sh`) refuses
  any artifact build that bypasses the wrapper without `--locked`, and
  `make negative-control-locks` drives the real entrypoints to prove a stale lock is
  rejected. Because the FFI build is `--locked` against root, the Go prebuilts'
  crypto graph equals root by enforcement, so root is the parity anchor for CLI + Go.
  - _TS scope note:_ the addon `--locked` build currently runs in the Linux
    `rust-quality` CI job only; the 5-platform `native-test` matrix does not enter
    the separate TS-native workspace. Per-platform addon enforcement is a **forward
    requirement gated on the TS publish workflow (D11B)**, which must build the addon
    `--locked` per platform via `cargo-artifact-build.sh` with the static guard
    covering the workflow YAML. This is not a v0.2.0 gap: the TS binding is
    `private:true` and ships no per-platform artifact in the 0.2.0 cut, while the
    CLI/Go release builds are `--locked` on every target.
- **Audit** — `make ci-security` scans **both** locks (`cargo audit --file …`) with
  the exact ID-pinned accepted advisories (`RUSTSEC-2026-0173` per
  [SDR-0003](docs/decisions/SDR-0003-rustsec-2026-0173-advisory-acceptance.md) and
  `RUSTSEC-2026-0374` per
  [SDR-0004](docs/decisions/SDR-0004-rustsec-2026-0374-advisory-acceptance.md)). It
  runs on every PR (ci.yml) **and daily on a schedule** (`security-audit.yml`) so an
  advisory disclosed against an unchanged pin is still caught.
- **Parity** — `make parity-check` asserts, keyed by full `(name, version, source,
checksum)` identity, that the crypto-roots closure resolves identically across
  surfaces, under two declared policies in `ci/parity-manifest.toml`:
  `[crypto_components]` is the **security gate** (EPR-0001 §4; divergence or a
  component missing from a scoped surface → exit 2), and `[non_crypto_shared]` is a
  separate **shared-graph lockstep** policy (a utility drift → exit 4, kept out of
  the security verdict). Reconciliation is two-way (undeclared node → REFUSE exit 3;
  declared-but-absent → FAIL) and declared roots are surface-scoped (a root on an
  undeclared surface REFUSEs). Non-crypto subtrees (localization, embedding,
  temp-file, platform shims) are declared out-of-scope. Regenerate the generated
  tables with `make parity-manifest-regen` after any dependency change and review
  the diff (the crypto/util boundary is a secrev gate).
- **Prove, don't assume** — `make negative-control-locks` staleens each lock and
  asserts the `--locked` build **fails**; `make negative-control-parity` proves the
  parity check rejects a divergent, absent, or undeclared crypto graph. CI runs
  both, so the gates are demonstrated, not merely configured.

## Publish Gate

30. Draft release notes reflect final asset set (5 platform binaries +
    checksums + signatures + public keys + anchors).
31. Optional lanes (if omitted) are called out explicitly in notes.
32. Draft verified by four-eyes (`devrev`) and security (`secrev`) for
    release readiness.

## Post-Publish

33. If release notes or provenance metadata were amended while still a draft,
    re-upload provenance to the existing draft:
    ```bash
    make release-upload
    ```
34. Undraft/publish the GitHub release.
35. Update and commit homebrew-tap formula (**must run after undraft** —
    the tap script queries the latest published release):
    ```bash
    make update-homebrew-formula
    cd ../homebrew-tap
    git diff Formula/seclusor.rb
    make audit APP=seclusor
    make test APP=seclusor
    git add Formula/seclusor.rb && git commit -m "Update seclusor to vX.Y.Z"
    git push
    ```
36. Update and commit scoop-bucket manifest:
    ```bash
    make update-scoop-manifest
    cd ../scoop-bucket
    git diff bucket/seclusor.json
    python3 -m json.tool bucket/seclusor.json >/dev/null
    git add bucket/seclusor.json && git commit -m "Update seclusor to vX.Y.Z"
    git push
    ```

## Troubleshooting: Local/Remote Divergence

The Go bindings workflow runs on remote `main` HEAD. If you have unpushed local
commits when you trigger the workflow, `make go-bindings-fetch` will refuse the
bundle because the workflow's recorded commit will not match `origin/main` or
your branch base.

**Before running `make go-bindings-ci`**, always verify:

```bash
git fetch origin
git log --oneline origin/main..HEAD   # must be empty
git log --oneline HEAD..origin/main   # must be empty
```

If divergence occurs, pull remote first, resolve any conflicts, and retry.
