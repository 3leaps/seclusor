# Integration Tests

Workspace-level integration tests live here. They test cross-crate
interactions (e.g., encrypt with seclusor-crypto, store with seclusor-codec,
manage with seclusor-keyring).

Unit tests live inside each crate's `src/` directory as `#[cfg(test)]` modules.
