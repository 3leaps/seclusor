# App Note 02: Runtime & Deployment Patterns

**Status**: Draft — subject to change (v0.1.0)  
**Audience**: Developers, DevSecOps, platform engineers

Beyond git storage, seclusor supports several secure runtime patterns.

## 1. Local Secure Runner (`seclusor run`)

**Use case**: Developer workstations and CI jobs where secrets are stored locally.

- Armored file lives in a secure location (e.g. next to private SSH keys or in `~/.config/seclusor/`).
- File permissions: `0600` (enforced where possible).
- `seclusor run --file secrets.age --identity-file identity.txt --allow APP_* -- command ...`
- Secrets are injected into the child process environment without appearing in CLI arguments, shell history, or process lists.

**Best for**: Local development, personal CI tokens, glassbreak access.

## 2. Secure Servers & Protected Cloud Storage

- Store armored bundle files in:
  - Dedicated secret volumes (Kubernetes secrets, mounted with restricted access).
  - Cloud storage with IAM controls (e.g. GCS with encryption, S3 with bucket policies).
  - VM instance metadata or dedicated secret managers (with seclusor library for decryption).
- Use the library (`seclusor-crypto` / `seclusor-codec`) directly in services rather than the CLI when possible.
- Build simple secret-access services using the Rust library or FFI bindings.

## 3. Library / FFI Integration (Recommended for Production)

- Rust services can depend directly on `seclusor-crypto` and `seclusor-codec`.
- Go and TypeScript applications use the provided bindings.
- Decrypt only what you need, in memory, with strict size limits enforced.

## Recommendations by Sensitivity

- **Low-sensitivity**: Git + inline is acceptable.
- **Medium-sensitivity**: Bundle in protected storage + `seclusor run` or library calls.
- **High-sensitivity**: Local secure files + `seclusor run` or direct library use. Avoid persistent storage in shared systems.

See [App Note 01: Git Storage of Armored Secrets](01-git-armored-storage.md) for the full risk continuum.

For complete end-to-end runtime workflows, see [Workflow Scenarios](../guides/scenarios/index.md).
