# DDR-0001: Go/TypeScript Delivery Strategy (In-Repo vs Adjacent Repos)

Status: Proposed  
Date: 2026-02-28  
Owner: entarch

## Context

seclusor is a Rust library-first implementation with planned Go and TypeScript
consumers. We have two viable approaches for how those consumers obtain and
ship their interfaces:

1. **In-repo delivery**: publish Go/TS packages and (optionally) a Go/TS CLI from
   this repository (as bindings + wrappers around `seclusor-ffi` and/or shipped
   artifacts).
2. **Adjacent repos**: create public `seclusor-go` and `seclusor-ts` repos that
   consume seclusor’s published artifacts (Rust crates, headers, shared libs,
   npm package, etc.) and provide ecosystem-native packaging and tooling.

We want maximum DRY (single crypto/codec implementation) while also supporting
good ecosystem UX (Go module semantics, npm publishing conventions, release
cadence, and platform binaries).

## Decision

Defer until MVP (v0.1.x), but adopt these constraints now:

- **Single source of truth** for crypto/codec/keyring behavior is the Rust
  library crates (`crates/seclusor-*`).
- Go/TS integrations MUST NOT re-implement domain logic; they are adapters over
  seclusor’s library/FFI surface.
- Release engineering MUST support multi-platform artifacts suitable for Go/TS
  consumption (darwin-arm64, linux-amd64/arm64; windows later).

## Options and Tradeoffs

### Option A: In-repo delivery

Pros:

- Single repo to version and release.
- Easier to ensure ABI/package parity.
- Can ship prebuilt artifacts under `bindings/` with tight control.

Cons:

- Repo becomes multi-ecosystem heavy (Cargo + Go + Node tooling).
- Go/TS publishing workflows can constrain Rust release cadence.

### Option B: Adjacent repos

Pros:

- Ecosystem-native packaging and release cadence per language.
- Cleaner separation of concerns (bindings wrappers vs core crypto).

Cons:

- Requires explicit artifact distribution strategy (release assets, registries).
- More coordination overhead (versioning and compatibility matrix).

## Follow-ups

- ADR-0008/0009 define the stability surface needed for packaging (FFI contract + error model).
- Release engineering (D8) must decide the artifact format(s) and hosting approach.
