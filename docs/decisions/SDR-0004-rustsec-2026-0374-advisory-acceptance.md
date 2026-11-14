# SDR-0004: Acceptance of RUSTSEC-2026-0374 (basic-toml unmaintained)

Status: Accepted  
Date: 2026-11-13

## Context

seclusor's advisory gates (`cargo deny check advisories` and `cargo audit`) flag
**RUSTSEC-2026-0374**: the `basic-toml` crate (`v0.1.10`) is **unmaintained**
(repository archived following its March 2025 release). Like
[SDR-0003](SDR-0003-rustsec-2026-0173-advisory-acceptance.md)
(`RUSTSEC-2026-0173`), this is an informational "unmaintained" advisory, not a
report of a known vulnerability.

`basic-toml` enters **transitively and at compile time only**, through the same
`age` localization proc-macro dependency chain documented in `SDR-0003`:

```text
age -> i18n-embed-fl (proc-macro) -> i18n-config -> basic-toml
age -> i18n-embed -> i18n-embed-impl (proc-macro) -> i18n-config -> basic-toml
```

`cargo tree -e features -i basic-toml` confirms `i18n-config v0.4.8` (invoked by
the `i18n-embed-fl` and `i18n-embed-impl` proc-macros during `age` compilation)
as its sole parent. It executes only at build time to parse upstream `i18n.toml`
configuration and is **not linked into any shipped runtime binary or static
library**.

Both committed dependency graphs are affected because both compile `age v0.11.5`:

- root `Cargo.lock` — the CLI and FFI/Go static libraries
- `bindings/typescript/native/Cargo.lock` — the TypeScript native addon

Per Crucible **EPR-0001** §3 and `SDR-0003`, any additional accepted residual
advisory requires its own dated, revisit-conditioned security decision record
rather than stretching an existing exception.

## Decision

seclusor **accepts** `RUSTSEC-2026-0374` as a bounded build-time residual under
the conditions below.

### 1) Scope of acceptance

- Advisory: **RUSTSEC-2026-0374** (`basic-toml`, unmaintained).
- Affected graphs: root `Cargo.lock` and `bindings/typescript/native/Cargo.lock`.
- Nature: **compile-time-only** transitive dependency of proc-macros in the
  `age -> i18n-embed* -> i18n-config` chain; **not** present in any shipped
  runtime artifact.
- Class: **unmaintained** flag; **no known vulnerability**.

### 2) Why accepted

- **No safe upgrade path within `age 0.11.x`.** `age v0.11.5` unconditionally
  depends on `i18n-embed` / `i18n-embed-fl`, and no compatible `i18n-config`
  `0.4.x` release drops `basic-toml`.
- **No runtime exposure.** `basic-toml` parses static crate localization
  metadata during proc-macro expansion only and does not process untrusted
  inputs or ship in compiled artifacts.

### 3) Enforcement (fail-closed)

- Explicit ID-pinned entry in `deny.toml` (`RUSTSEC-2026-0374`) alongside
  `RUSTSEC-2026-0173` (`SDR-0003`). No wildcard or crate-wide suppression is
  used.
- Matching `--ignore RUSTSEC-2026-0374` flags on both `cargo audit` invocations
  in `make ci-security` (root `Cargo.lock` and
  `bindings/typescript/native/Cargo.lock`), run on every PR (`ci.yml`) and daily
  on schedule (`security-audit.yml`).

### 4) Owner and revisit

- Owner: seclusor maintainers (`secrev` gate).
- **Revisit at the `v0.3.0` (`age 0.12`) migration boundary or by 2027-02-13,
  whichever comes first** (aligned with the `SDR-0003` revisit schedule).

### 5) Removal condition

Remove `RUSTSEC-2026-0374` from `deny.toml` and both `cargo audit` invocations
in the same commit as soon as `age` or `i18n-config` resolves off `basic-toml`.
If a **vulnerability** (not merely an unmaintained status) is ever disclosed
against `basic-toml`, this acceptance is immediately void and must be treated as
an unignored finding.

## Consequences

- `deny.toml` and `make ci-security` explicitly enumerate the two build-time
  `age` localization proc-macro residuals (`RUSTSEC-2026-0173` per `SDR-0003`
  and `RUSTSEC-2026-0374` per `SDR-0004`) across both locks.
- Any newly disclosed advisory outside those two exact IDs continues to fail CI
  and scheduled audits immediately.

## Related Decisions

- [ADR-0002](ADR-0002-age-as-default-encryption-backend.md)
- [SDR-0003](SDR-0003-rustsec-2026-0173-advisory-acceptance.md)
- Crucible **EPR-0001** — published-artifact dependency integrity
