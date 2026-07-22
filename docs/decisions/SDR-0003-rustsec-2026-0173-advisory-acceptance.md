# SDR-0003: Acceptance of RUSTSEC-2026-0173 (proc-macro-error2 unmaintained)

Status: Accepted  
Date: 2026-07-20

## Context

seclusor's advisory gates (`cargo deny check advisories` and `cargo audit`) flag
**RUSTSEC-2026-0173**: the `proc-macro-error2` crate is **unmaintained**. It is an
informational "unmaintained" advisory, not a report of a known vulnerability.

`proc-macro-error2` is reached **transitively and at compile time only**, via the
encryption backend:

```
age -> i18n-embed-fl -> proc-macro-error2   (proc-macro, build-time)
```

`cargo tree -i proc-macro-error2` shows `i18n-embed-fl` as its sole parent. As a
proc-macro dependency it runs during compilation and is **not linked into any
shipped runtime binary**.

Two committed dependency graphs are affected, because both build the age crypto
stack:

- root `Cargo.lock` — the CLI (homebrew/scoop) and the FFI/Go prebuilts
- `bindings/typescript/native/Cargo.lock` — the TypeScript native addon

EPR-0001 §3 (published-artifact dependency integrity) requires that an accepted
residual advisory be recorded as a **dated, revisit-conditioned security decision
record** owned by the adopting repository, rather than only as a suppression
comment. This SDR is that record; it is the source of truth, and the `deny.toml`
ignore plus the two `cargo audit` invocations are terse enforcement references to
it so the rationale does not fork.

## Decision

seclusor **accepts** RUSTSEC-2026-0173 as a residual, under the conditions below.
It is the **only** permitted advisory ignore.

### 1) Scope of acceptance

- Advisory: **RUSTSEC-2026-0173** (`proc-macro-error2`, unmaintained).
- Affected graphs: root `Cargo.lock` and `bindings/typescript/native/Cargo.lock`.
- Nature: **compile-time-only** transitive proc-macro via `age -> i18n-embed-fl`;
  **not** present in any shipped runtime artifact.
- Class: **unmaintained** flag; **no known vulnerability**.

### 2) Why accepted

- **No safe upgrade path.** No released `age` / `i18n-embed-fl` version resolves
  off `proc-macro-error2` at this time.
- **No runtime exposure.** The crate is a build-time proc-macro; it does not ship.
- Removing the dependency is upstream's to make; seclusor cannot patch it out
  without forking the age i18n chain.

### 3) Enforcement (fail-closed)

- A **single-ID** ignore in `deny.toml` — a _new_ advisory must not hide behind
  it. `cargo audit` does not read `deny.toml`, so its `--ignore RUSTSEC-2026-0173`
  flag MUST match the `deny.toml` ID exactly (drop both together on removal).
- **Both** locks are audited: `cargo audit --file <lock> --deny warnings --ignore
RUSTSEC-2026-0173` for root and TS-native (see `make ci-security`).
- Audits run **on-change** (ci.yml) **and on a daily schedule**
  (`security-audit.yml`), so a vulnerability newly disclosed against
  `proc-macro-error2` — which would change this SDR's basis — is surfaced even
  while the pins are static.

### 4) Owner and revisit

- Owner: seclusor maintainers (secrev gate).
- **Revisit by the v0.2.1 train or 2026-10-13, whichever comes first.**

### 5) Removal condition

Drop this acceptance — remove the `deny.toml` ignore and both `--ignore` flags in
the same change — as soon as the `age -> i18n-embed-fl` chain no longer resolves
`proc-macro-error2` (or an equivalent maintained replacement lands upstream). If a
**vulnerability** (not merely an unmaintained flag) is ever filed against
`proc-macro-error2`, this acceptance is void and the advisory must be treated as
an unignored finding.

## Rationale

- Records the residual as a durable, dated, revisit-conditioned repository
  decision (EPR-0001 §3), not a comment that quietly widens as surfaces are added.
- Keeps a single acceptance covering both affected graphs, so the disposition
  cannot drift between the root and TS-native locks.
- Preserves fail-closed posture: exactly one advisory is ignored, by ID, on both
  locks, on-change and on schedule.

## Consequences

- `deny.toml` and both `cargo audit` invocations cite this SDR as the source of
  truth and carry only terse enforcement context.
- The revisit date and removal condition are load-bearing: at v0.2.1 / 2026-10-13
  the chain must be re-checked and this SDR updated or retired.
- Any second advisory ignore requires its own SDR — this one does not stretch.

## Related Decisions

- [ADR-0002](ADR-0002-age-as-default-encryption-backend.md)
- [SDR-0001](SDR-0001-server-unseal-and-key-management.md)
- crucible **EPR-0001** — published-artifact dependency integrity (governing
  principle; see `3leaps/crucible docs/decisions/EPR-0001-published-artifact-dependency-integrity.md`)
