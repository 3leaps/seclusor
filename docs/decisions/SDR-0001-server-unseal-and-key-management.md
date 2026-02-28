# SDR-0001: Server Unseal and Key Management

Status: Accepted (carried forward; server mode deferred)  
Date: 2026-02-28

## Context

When seclusor runs as a long-lived service (“server mode”), it must decrypt
secrets to serve/emit them. The core problem is unseal material:

- where it lives
- how it is protected
- how it is rotated
- how access is revoked

There is no perfect solution; the goal is to make tradeoffs explicit and
operationally safe.

## Decision

Recommended default for production-like server deployments:

- Use age X25519 recipient encryption.
- Store the age identity (private key) on the server as a file, delivered by the
  runtime platform’s secret mechanism.
- Do not default to storing passphrases in environment variables.

Supported modes (explicit opt-in):

- Passphrase-based unseal using age scrypt recipients.
- Manual operator unseal (interactive prompt) for environments that want
  Vault-like ceremony.

Tooling guardrails:

- seclusor tooling must refuse to write private keys / identity files anywhere
  under the detected repository root.
- Do not treat gitignored paths as safe; `.gitignore` can change or be removed.

## Rationale

- An identity file can be handled like any other host secret (permissions,
  access controls, secret injection).
- Multi-recipient encryption allows CI + operators + break-glass keys without
  shared passphrases.
- Passphrase-in-env is convenient but increases exposure in real systems.

## Rotation Model

Key rotation is defined as:

1. generate a new identity
2. add the new recipient to the encryption set
3. re-encrypt artifacts (bundle or inline values) so future deployments are
   decryptable by the new key
4. deploy the new identity to servers
5. remove old recipients and re-encrypt again (to fully revoke)

Important: removing a recipient without re-encrypting does not revoke access to
already-existing ciphertext.

## Notes

This SDR is carried forward from a prior internal Go implementation
(unpublished). Server mode is deferred beyond
v0.1.0, but the key material posture influences CLI/FFI design now.
