# Release Signing and Verification

Official `seclusor` releases use OpenPGP-signed annotated Git tags and
minisign-signed `SHA256SUMS` and `SHA512SUMS` checksum manifests (with optional
detached OpenPGP `.asc` signatures on the same manifests). Tag signatures and
manifest signatures are independent cryptographic checks.

Establish the expected OpenPGP primary key, the exact signing subkey, and the
minisign public-blob fingerprint through an independently trusted maintainer
channel before accepting downloaded public keys. A public key distributed beside
a signature is not independent authentication.

## Public pins

| File                                     | Contents                                                                                               |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `docs/security/release-signing-keys.asc` | Public OpenPGP export: the approved primary key and the exact signing subkey, nothing else             |
| `docs/security/seclusor-minisign.pub`    | The minisign public key that signs `SHA256SUMS` and `SHA512SUMS`                                       |
| `config/release/signing-subkey.txt`      | The 40-hex fingerprint of the single signing subkey release tags may use                               |
| `config/release/tagger-identity.txt`     | The exact Git tagger identity (`Name <email>`)                                                         |
| `keys/expected-fingerprints.txt`         | Two lines: the OpenPGP primary fingerprint, then the minisign public-blob SHA-256                      |
| `keys/expected-fingerprints.ndjson`      | `decernor` fingerprint records (`openpgp-fingerprint-v1` primary and `minisign-public-blob-sha256-v1`) |
| `config/release/decernor-ci-sha256.txt`  | Pinned SHA-256 digest of the `decernor` archive used by read-only CI verification                      |
| `config/release/release-workflow.sha256` | Reviewed SHA-256 digests for every GitHub Actions workflow under `.github/workflows/`                  |

Post-tag release staging extracts the public keys, fingerprint anchors, and
per-cut release notes from the verified tagged commit as inert Git blobs, not
from a mutable working tree or an external public-key locator. Published
`minisign.pub`, `release-key.asc`, and `expected-fingerprints.{txt,ndjson}`
assets must match the tagged commit's blobs byte-for-byte; independent
fingerprint verification remains required.

## Fingerprint anchors and manifest verification

The text and NDJSON anchors in each tagged commit are derived by `decernor`
`0.1.8` or newer (`openpgp-fingerprint-v1` primary and
`minisign-public-blob-sha256-v1`). The minisign fingerprint covers the decoded
public key blob rather than its untrusted comment line or whole-file bytes.

To verify a release:

1. Verify `release-key.asc` and `minisign.pub` against independently trusted
   anchors using `decernor >= 0.1.8`:
   ```bash
   decernor fingerprint verify \
     --anchors expected-fingerprints.txt \
     --anchors-ndjson expected-fingerprints.ndjson \
     --gpg release-key.asc \
     --minisign minisign.pub
   ```
2. Verify `SHA256SUMS.minisig` and `SHA512SUMS.minisig` against `minisign.pub`
   (and `SHA256SUMS.asc` / `SHA512SUMS.asc` against `release-key.asc` in an
   isolated keyring when OpenPGP manifest verification is required).
3. Verify every entry in `SHA256SUMS` and `SHA512SUMS` against the complete
   expected asset set (`seclusor-linux-amd64`, `seclusor-linux-arm64`,
   `seclusor-darwin-arm64`, `seclusor-windows-amd64.exe`,
   `seclusor-windows-arm64.exe`, `expected-fingerprints.txt`, and
   `expected-fingerprints.ndjson`). Do not pass `--ignore-missing` for full
   release verification.

## Dual release tags

Every `seclusor` release tags a single reviewed commit on `main` with two
OpenPGP-signed annotated tag objects at the same version:

- `vX.Y.Z` (canonical repository and CLI release tag, message `seclusor vX.Y.Z`)
- `bindings/go/seclusor/vX.Y.Z` (Go module release tag required for
  `go get github.com/3leaps/seclusor/bindings/go/seclusor@vX.Y.Z`, message
  `seclusor bindings/go/seclusor/vX.Y.Z`)

Both tags are pushed atomically, must point directly at the same commit, must
carry the committed tagger identity, and must verify in an isolated keyring
against `docs/security/release-signing-keys.asc` using the exact subkey in
`config/release/signing-subkey.txt`. GitHub `Verified` with reason `valid` is
checked in addition to local isolated-keyring verification. Historical tags
predating signed-tag enforcement are not retroactively rewritten.

## Read-only CI boundary

Every GitHub Actions workflow in this repository runs with
`permissions: contents: read` and `persist-credentials: false`. Neither
`release.yml` nor `go-bindings.yml` holds signing keys, creates or mutates
GitHub Releases, or pushes branches or pull requests.

Because tag-triggered workflows are defined by the tagged commit itself, a
passing workflow run is a build and consistency signal rather than release
authorization. Maintainers independently verify the remote tag objects and
artifact digests from trusted checkout code on the maintainer machine before
creating the draft release, signing manifests, uploading provenance, or
publishing. Repository tag-protection rules (`refs/tags/v*` and
`refs/tags/bindings/go/seclusor/v*`) and the local maintainer ceremony form the
publication boundary.
