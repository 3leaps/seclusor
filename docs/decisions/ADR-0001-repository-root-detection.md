# ADR-0001: Repository Root Detection

Status: Accepted (carried forward)  
Date: 2026-02-28

## Context

seclusor needs to locate repository-relative assets (schemas, default config,
and other repo-scoped resources) regardless of current working directory.

This matters for:

- tests (running from crate/package directories)
- CI environments (where `$HOME` may not be an ancestor of the repo)
- user workflows (running the binary from anywhere)

## Decision

Implement repository root detection as a bounded upward search for common repo
markers.

- Search upward for markers like `.git`, `Cargo.toml` (workspace), and/or a
  seclusor-specific marker directory (e.g. `schemas/`, `config/`).
- Keep the walk bounded (depth limit) to avoid pathological filesystem scans.
- In CI contexts, allow an explicit boundary hint (e.g. `FULMEN_WORKSPACE_ROOT`)
  but still require an actual marker to be discovered within the boundary.

## Consequences

- Config/schema discovery is stable across working directories.
- CI remains reliable when `$HOME` boundaries differ from repo location.
- Root discovery remains bounded and predictable.

## Notes

This decision is carried forward from a prior internal Go implementation
(unpublished) and adapted for Rust:
there is no dependency on `gofulmen/pathfinder` in this repository.
