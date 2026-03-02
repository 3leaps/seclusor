# SDR-0002: Secret Input Channels and CLI Argument Policy

Status: Accepted  
Date: 2026-03-02

## Context

seclusor handles sensitive material across multiple interfaces:

- plaintext secret values
- age private identities (`AGE-SECRET-KEY-...`)
- passphrases
- ciphertext payloads

Some channels are materially riskier than others. In particular, values passed
via CLI arguments can leak through shell history, process listings, job control
logs, crash reporting, and telemetry in surrounding tooling.

At the same time, seclusor cannot prevent operators from launching a process
with ambient environment assignments (for example:
`MYSECRET=... seclusor secrets run ...`). That exposure is a user/operator
choice outside the process boundary.

We need an explicit policy that distinguishes:

1. what seclusor must refuse by design
2. what seclusor may consume but should treat as operator-managed risk

Scope note: this SDR governs unseal/key material channels (private identities
and passphrases). General secret entry UX (for example `secrets set`) is
separate and should be finalized with ADR-0010 (planned).

## Decision

### 1) No secret-bearing CLI options for unseal/key material

CLI transports MUST NOT accept private key material or passphrases as direct
argument values (flags or positionals).

Forbidden examples:

- `--identity AGE-SECRET-KEY-...`
- `--passphrase ...`
- positional private key or passphrase inputs

Allowed channels for this class of secret:

- identity files (`--identity-file`)
- interactive prompt (`rpassword`) where applicable
- library/FFI in-memory APIs where the caller manages process boundary risk

### 2) Public crypto metadata is allowed in args

Non-secret inputs (for example age public recipients `age1...`) may be accepted
via CLI args.

### 3) Ambient environment remains operator-managed risk

seclusor may read environment variables for explicit features (recipient
discovery, import/export workflows, process injection), but this does NOT imply
those channels are risk-free.

seclusor cannot prevent a caller from injecting sensitive values into the
process environment before startup. Documentation and UX should treat this as an
operator-controlled risk, not as a default-safe secret channel.

CLI transports MUST NOT introduce dedicated environment-variable inputs for
private identities or passphrases (for example `SECLUSOR_IDENTITY` or
`SECLUSOR_PASSPHRASE`) as convenience unseal channels.

### 4) Transport parity requirement

This policy applies consistently across CLI/server/FFI adapters under the DRY
transport model. Transport adapters must not reintroduce forbidden CLI/env
convenience channels for unseal/key material.

Library and FFI in-memory inputs remain caller-risk channels, but adapters built
on top of them must still enforce this SDR's CLI/env constraints.

## Rationale

- Reduces accidental leakage through ubiquitous OS/shell surfaces.
- Keeps key-unseal paths aligned with security posture already required by
  repository policy.
- Preserves practical workflows for recipient/public metadata.
- Clarifies threat-model boundaries without claiming impossible guarantees.

## Consequences

- CLI surfaces that accept unseal/key secrets via args should be removed or
  rejected with a clear error.
- Future command design must explicitly classify each input as secret vs
  non-secret and choose channels accordingly.
- Docs should distinguish "supported" channels from "recommended" channels.
- Regression tests should assert forbidden CLI flags/env convenience channels
  are absent or explicitly rejected.

## Related Decisions

- [ADR-0006](ADR-0006-dry-core-cli-server-and-stdout-purity.md)
- [ADR-0002](ADR-0002-age-as-default-encryption-backend.md)
- [SDR-0001](SDR-0001-server-unseal-and-key-management.md)
