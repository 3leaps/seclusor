# ADR-0004: SQLite Driver and Replication Strategy

Status: Retired — Not Planned (superseded by ADR-0013)  
Date: 2026-02-28 (retired 2026-11-13)

## Context

seclusor may eventually need a local state store (SQLite-class) for features
like:

- indexes/cache
- audit/event logs
- background jobs

We also need a clear story for “replication” or “backups” in VM/container
deployments.

## Options Considered (Rust)

1. `rusqlite` (SQLite C via `libsqlite3-sys`)
   - Pros: mature Rust ecosystem integration.
   - Cons: native dependency; cross-compilation and musl/static builds require care.

2. `libsql` (Turso/libSQL)
   - Pros: optional sync model, embedded replicas.
   - Cons: native dependency expectations; operational complexity; compatibility concerns require validation.

3. External store (defer / out of scope for v0.1.0)
   - Pros: simplifies v0.1.0 scope.
   - Cons: delays “server mode” features that benefit from local persistence.

Replication/backups:

- For plain SQLite files: tools like Litestream (or platform snapshots) are strong candidates.
- For libSQL embedded replicas: treat vendor sync as replication and evaluate backups separately.

## Decision (Proposed)

- Defer selecting a Rust storage backend for v0.1.0.
- When selected, document platform constraints (glibc vs musl, static builds,
  cross-compilation) and provide a clear backup/replication recommendation.

## Notes

Retired as **Not Planned** by [ADR-0013](ADR-0013-value-free-control-plane-and-mcp-boundary.md):
`seclusor` does not ship a standalone secret-serving server/daemon mode or
local database store. This record is preserved for historical context only.
