# Review Checklist

Use this checklist for pull requests before merge. Seclusor is
security-sensitive: correctness, secrecy boundaries, and library API stability
matter more than speed.

## Author Gate

- [ ] Work is on a feature branch, not `main`
- [ ] `make pr-final` passed locally before pushing the branch
- [ ] PR description summarizes behavior changes and test coverage
- [ ] Public API changes are intentional and documented
- [ ] Docs or release notes are updated when user-facing behavior changes
- [ ] No `.plans/` or `AGENTS.local.md` files are staged

## Reviewer Gate

- [ ] CI is green
- [ ] Changes are scoped to the PR purpose
- [ ] Tests cover the changed behavior and relevant failure paths
- [ ] Error messages and logs avoid plaintext, passphrases, keys, and raw
      secret material
- [ ] Dependencies are license-compatible and justified
- [ ] Cross-platform behavior is considered for Linux, macOS, and Windows

## Crypto and Key Management

Required when touching `seclusor-crypto`, `seclusor-keyring`, signing,
identity handling, passphrase handling, or encryption/decryption flows.

- [ ] `secrev` review requested before merge
- [ ] Size limits are enforced before allocation where applicable
- [ ] Ciphertext prefixes and formats are validated defensively
- [ ] Identity files and decrypted output permissions remain restrictive
- [ ] Wrong-key and wrong-passphrase failures do not disclose sensitive data
- [ ] Tests include adversarial or malformed input

## FFI and Bindings

Required when touching `seclusor-ffi`, generated headers, Go bindings, or
TypeScript bindings.

- [ ] Memory ownership remains explicit
- [ ] Returned strings are freed through the documented free function
- [ ] Panic-safe FFI boundaries are preserved
- [ ] JSON-over-FFI contracts remain backward-compatible or are versioned
- [ ] Go and TypeScript parity impacts are documented

## Merge Gate

- [ ] Required human review is complete
- [ ] `devrev` review is complete for substantive code changes
- [ ] `secrev` review is complete for crypto/key/FFI-sensitive changes
- [ ] Branch is up to date with `main` or merge conflict risk is resolved
- [ ] Squash/merge strategy matches the PR shape
