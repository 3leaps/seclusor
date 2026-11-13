# ADR-0013: Value-Free Control-Plane, MCP, and UI Boundary; Retirement of Standalone Server Mode

Status: Accepted  
Date: 2026-11-13

## Context

`seclusor` is an offline-first cryptographic secrets and signature toolkit built
around `age` encryption ([ADR-0002](ADR-0002-age-as-default-encryption-backend.md)),
`bundle` and `inline` ciphertext codecs ([ADR-0003](ADR-0003-storage-codecs-bundle-and-inline.md)),
Ed25519 signing ([ADR-0011](ADR-0011-ed25519-signing-in-seclusor-crypto.md)), and
strict secret input-channel hygiene ([SDR-0002](SDR-0002-secret-input-channels-and-cli-arg-policy.md)).

Two architectural questions arise as automated agents, developer tooling, and
operator interfaces integrate with `seclusor`:

1. **Control-plane, MCP, and UI inspection surfaces:** Operators and AI-assisted
   workflows benefit from inspecting secret inventories, validating schemas,
   verifying recipient sets, and auditing rotation or signature health through
   structured control planes, Model Context Protocol (MCP) tools, or optional
   graphical ceremony/inspection views ("glass"). However, returning decrypted
   secret values over these surfaces exposes plaintext credentials to LLM context
   windows, persistent session transcripts, telemetry/logging pipelines, IPC
   peers, and browser/WebView heaps.
2. **Deferred standalone server mode:** Early carry-forward records
   ([SDR-0001](SDR-0001-server-unseal-and-key-management.md),
   [ADR-0004](ADR-0004-sqlite-driver-and-replication.md),
   [ADR-0005](ADR-0005-api-contract-schema-first.md), and
   [ADR-0006](ADR-0006-dry-core-cli-server-and-stdout-purity.md)) left open a
   future long-lived `seclusor` server/daemon transport (`serve`) backed by a
   local database to decrypt and emit secrets over a network or IPC boundary.

We need an explicit boundary governing what control-plane, MCP, and UI surfaces
may expose, and whether `seclusor` itself ever operates as a long-lived
secret-serving daemon.

## Decision

### 1) Value-free invariant for control-plane and MCP surfaces

Any control-plane API, Model Context Protocol (MCP) message in either direction
(tools, resources, prompts, elicitation, and sampling), or automation inspection
adapter built in or around `seclusor` **MUST NEVER** return, echo, stream, copy
to clipboard, log, or serialize:

- plaintext secret values or decrypted blob bytes
- `age` private identity keys (`AGE-SECRET-KEY-...`) or plugin identity stubs
  containing secret recovery material
- Ed25519 signing private keys or seeds
- passphrases, PINs, or unseal shares

Error messages, diagnostics, and structured logs across all surfaces **MUST**
remain strictly value-free.

Direct local CLI commands invoked by an operator or subprocess (`secrets get
--reveal`, `secrets export-env`, `secrets run`) and in-process Rust/Go/FFI
library decryption APIs remain outside this control-plane/MCP prohibition and
continue to be governed by
[ADR-0006](ADR-0006-dry-core-cli-server-and-stdout-purity.md) and
[SDR-0002](SDR-0002-secret-input-channels-and-cli-arg-policy.md).

Control-plane and MCP surfaces are strictly restricted to **value-free metadata,
policy, and verification operations**, including:

- listing project slugs, credential keys, logical paths, credential types, and
  non-secret descriptions
- validating document structure, schema compliance, and codec invariants
- inspecting public recipient keys (`age1...`), recipient counts, and recipient
  metadata drift against expected recipient sets
- verifying detached or embedded Ed25519 signatures against public verification
  keys
- orchestrating re-encryption or rotation checks whose outputs report status and
  public recipient state without emitting secret values

### 2) Retirement of standalone secret-serving server mode

`seclusor` **will not** ship a standalone long-lived server, HTTP/gRPC service,
or secret-vending daemon (`serve`). `seclusor` remains a daemon-free library and
CLI toolkit for at-rest ciphertext, signatures, cold unseal ceremonies, and
scoped local execution (`secrets run`).

- [ADR-0004](ADR-0004-sqlite-driver-and-replication.md) (SQLite storage and
  replication for server mode) is retired as **Not Planned**.
- Future server-mode OpenAPI HTTP contract clauses in
  [ADR-0005](ADR-0005-api-contract-schema-first.md) are retired; JSON Schema
  remains the single source of truth for file and document contracts.
- Future server/daemon transport references in
  [ADR-0006](ADR-0006-dry-core-cli-server-and-stdout-purity.md) are retired;
  the DRY core principle and CLI stdout-purity contract continue to govern
  library crates, CLI commands, and language bindings/twins.
- [SDR-0001](SDR-0001-server-unseal-and-key-management.md) standalone server
  mode is retired. Its key-custody, non-repository identity storage, and
  re-encryption rotation rules remain normative for external runtime services
  that embed `seclusor` as an in-process library for cold-start unseal or
  at-rest storage.

### 3) Secret input isolation across control-plane, MCP, and UI adapters

Extending [SDR-0002](SDR-0002-secret-input-channels-and-cli-arg-policy.md),
control-plane requests, MCP tool arguments, and browser/WebView DOM inputs
**MUST NOT** carry passphrases, private identities, hardware PINs, or plaintext
secret values.

When an interactive ceremony requires unlock material or secret entry, input
must traverse an OS-isolated channel outside LLM context and outside WebView DOM
event streams:

- interactive terminal TTY prompt with echo disabled
- explicit standard-input / file-descriptor pipe controlled by the caller
- owner-only (`0600`) identity or passphrase file stored outside any repository
  root
- hardware security key / enclave touch or native OS prompt

### 4) Local human inspection boundary (TUI and optional ceremony UI)

- **Terminal UI (`TUI`):** Interactive local browsing or copying of decrypted
  entries, when offered by the CLI, runs strictly in-process within an
  interactive terminal session using zeroized memory buffers, masked values by
  default, explicit single-entry reveal or time-bounded clipboard copy that
  conditionally clears only its own item on expiry and on idle lock (disabled
  when safe conditional clearing is unavailable, without claiming erasure of
  external clipboard history), and idle auto-lock. It must not expose an IPC,
  HTTP, or MCP listener.
- **Optional graphical UI ("glass"):** Any future graphical inspection or
  ceremony surface must preserve the value-free display invariant: it may render
  key catalogs, recipient sets, signature verification, drift posture, and
  ceremony step status, while delegating any secret entry or unlock gesture to
  an OS-isolated input port rather than rendering decrypted secret values into a
  WebView or browser DOM. Graphical, MCP, and control-plane surfaces must not
  offer clipboard copy of decrypted values.

## Rationale

- **Context and transcript safety:** AI agents and MCP hosts routinely persist
  tool inputs and outputs in conversation transcripts, prompt caches, and audit
  logs. A structural prohibition on secret-returning MCP/control-plane tools
  eliminates accidental secret exfiltration into model context by design.
- **Separation of duties:** Keeping `seclusor` focused on at-rest cryptography,
  signatures, and deterministic local execution avoids duplicating online lease
  management, authentication, and policy engines that belong in dedicated
  credential brokers or vault services.
- **Reduced attack surface:** Eliminating a network/IPC secret-serving daemon
  and SQLite server store removes long-lived decrypted heap state, localhost
  peer-authentication hazards, and database replication surface from `seclusor`.
- **DOM/renderer hygiene:** Browser and WebView runtimes retain strings across
  garbage-collected heaps, accessibility trees, and developer tools; keeping UI
  surfaces value-free prevents silent plaintext retention.

## Consequences

- No `serve` command, MCP tool, or control-plane endpoint in `seclusor` may
  return decrypted secret values, offer clipboard copy of decrypted values, or
  accept secret-bearing tool arguments.
- Automated tests for any future control-plane or MCP surface must include
  canary-secret non-disclosure assertions verifying that known canary values
  never appear in responses, errors, or logs.
- External services that require online secret brokering or leased credentials
  integrate with `seclusor` via its library APIs rather than shelling out to a
  daemon mode.
- Decision index (`docs/decisions/README.md`), `SDR-0001`, `ADR-0004`,
  `ADR-0005`, and `ADR-0006` are updated to reflect the retirement of
  standalone server mode.

## Related Decisions

- [ADR-0002](ADR-0002-age-as-default-encryption-backend.md)
- [ADR-0004](ADR-0004-sqlite-driver-and-replication.md)
- [ADR-0005](ADR-0005-api-contract-schema-first.md)
- [ADR-0006](ADR-0006-dry-core-cli-server-and-stdout-purity.md)
- [SDR-0001](SDR-0001-server-unseal-and-key-management.md)
- [SDR-0002](SDR-0002-secret-input-channels-and-cli-arg-policy.md)
