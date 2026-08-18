# App Note 04: Encrypted Write Operations

**Status**: Active
**Audience**: Operators, DevSecOps, library consumers of write-side CLI
**Depends on**: App Note 02 (encrypted read); ADR-0012 recipients metadata

---

## 1. Why encrypting writes

Prefer in-place encrypting commands over decrypt → edit → re-encrypt when a
secrets document is already under seclusor management as bundle or
inline-encrypted JSON. That closes the plaintext-on-disk window for mutations.

**Read-side** patterns: [App Note 02](02-runtime-deployment-patterns.md).

---

## 2. Command map

| Command                          | Plaintext                                                    | Inline encrypted                                                                       | Bundle encrypted                                                                             |
| -------------------------------- | ------------------------------------------------------------ | -------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| `secrets set` (value/ref)        | mutate                                                       | Full decrypt; encrypt only changed values; recipients rules                            | Full decrypt→mutate→re-encrypt                                                               |
| `secrets set --description` only | mutate                                                       | Structural-only (no identity)                                                          | Encrypting write                                                                             |
| `secrets unset`                  | mutate                                                       | Structural-only (no identity)                                                          | Encrypting write                                                                             |
| `secrets import-env`             | mutate                                                       | Full encrypting write                                                                  | Full encrypting write                                                                        |
| `secrets rekey`                  | Encrypt values + establish recipients (preserve credentials) | Normalize all fields + recipients                                                      | Same                                                                                         |
| `secrets init`                   | Fresh skeleton JSON                                          | **Not via empty init** — create by encrypting a value (`set` / `import-env` / `rekey`) | **Create-only** empty skeleton: `--codec bundle` + explicit recipients on an **absent** path |

Recipient **set changes** never ride on `set` / `import-env` — use **`rekey`**.

---

## 3. Value input (documented default)

Prefer non-argv channels for secret material:

```bash
printf '%s' "$SECRET" | seclusor secrets set \
  --file secrets.age --identity-file id.txt \
  --key API_KEY --value-stdin --recipient age1...

seclusor secrets set --value-file ./secret.txt ...
seclusor secrets set --value-env MY_SECRET ...
```

On a terminal, `--value-stdin` hides what you type and closes on Enter so
the secret does not appear on screen. `--echo-value` is the explicit
visible-typing opt-in (EOF terminator). A pipe or redirect keeps the
existing byte-stream path and rejects `--echo-value`.

Legacy `--value <str>` remains but **warns on stderr** and is not the
documented safe path.

---

## 4. Recipients and establishment

Encrypting writes resolve recipients as:

1. Explicit `--recipient` / `--recipient-file` / `--recipient-env-var`, else
2. Document `recipients` metadata (schema v1.1.0), else
3. Fail closed

Establishment (persist `recipients` + rewrite `schema_version` to v1.1.0)
follows the coverage rule: bundle always OK; inline only if the write covers
every encrypted field (else refuse → `rekey`).

Stanza-count divergence on encrypting writes: **fail closed** (name `rekey`).
Read/inspect paths may **warn** only.

`rekey --write-recipients PATH` is the explicit durable-recipient refresh
surface. The ciphertext commit happens first; the resulting canonical public
recipient list is then committed through a distinct same-directory atomic
writer. Fresh Unix recipient files are `0644` subject to umask, and existing
modes are preserved. The input `--recipient-file` is never rewritten
implicitly. Because the document and list are two targets, a list-write failure
after rekey returns a nonzero, explicit partial-success diagnostic.

### Schema invariant: recipients ⇒ no plaintext credential values (JSON at rest)

When top-level `recipients` is present on a **JSON** secrets document (plaintext
or inline-encrypted file), the document must not carry any **direct plaintext**
credential values (refs and `sec:age:v1:` values are fine). Validation fails
closed on **read and write** for that JSON form (including parse and FFI). This
is a deliberate fail-secure upgrade against plaintext-downgrade tampering. It
does **not** detect equal-count recipient membership swap (see residuals).

**Bundle note:** After decrypting an age **bundle**, credential values are
plaintext JSON _inside_ the outer ciphertext by design. Structure-only
validation applies to that working copy; confidentiality is the outer age
layer, not per-value `sec:age:v1:` markers.

Malformed recipients+plaintext **JSON** documents will not load until repaired
or removed; `rekey` may not open them until fixed.

---

## 5. Encrypted init (bundle create-only)

```bash
# Plaintext skeleton (unchanged)
seclusor secrets init --file secrets.json --project myapp

# Empty encrypted bundle (create-only; path must not exist)
seclusor secrets init --file secrets.age --codec bundle \
  --recipient age1... --project myapp
```

Rules:

- **`--codec bundle` only** for encrypted init; requires at least one
  **explicit** recipient channel (ambient `SECLUSOR_RECIPIENTS` alone is not
  enough).
- Target path must be **absent**. Existing files: use `rekey` to encrypt
  existing credentials, or remove the file for a fresh empty encrypted skeleton.
- **No** `--force --codec`. Plaintext `--force` remains empty-skeleton reset only.
- Recipient flags without `--codec` are refused.
- X25519 recipients only — no identity, passphrase, or scrypt on init
  (data-passphrase UX is a separate surface).
- Fresh Unix files: owner-only **0600**. Windows fresh-file ACL parity is not
  guaranteed (directory guidance applies).
- stdout = path; establishment notice on stderr.

Inline encrypted documents: plaintext `init` then `set`/`import-env` with
recipients, or `rekey` from plaintext.

---

## 6. Honest residuals

| Residual                            | Meaning                                                                                                                                                             |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Inline `recipients` unauthenticated | Plaintext JSON field; integrity = git + tripwires, not age authentication                                                                                           |
| Same-count member-swap              | Replacing one recipient at equal stanza count is **not** detected by count tripwire (distinct from the recipients+plaintext validation upgrade)                     |
| Operator value channels             | `--value-file` / env / stdin / legacy argv are operator-chosen sources with documented exposure                                                                     |
| import-env in-memory buffer         | Import path may hold env values in owned `String` pairs that are not zeroized on drop — deferred zeroizing value newtype; not the same as operator-channel exposure |
| age `Identity`                      | Upstream does not zeroize secret scalar on drop — minimize lifetime                                                                                                 |
| Scrypt data bundles                 | Write paths refuse; data-passphrase CLI UX is owned elsewhere                                                                                                       |
| Windows atomicity                   | `ReplaceFileW`; crash atomicity not guaranteed                                                                                                                      |
| Windows fresh-file ACL              | Owner-only parity not guaranteed on create (Unix 0600 is)                                                                                                           |

---

## 7. Compatibility

Documents that carry top-level `recipients` use schema **v1.1.0**. Older
binaries that predate schema v1.1.0 recipients support and use
`deny_unknown_fields` **fail closed** on those documents (safe direction).
Documents without `recipients` remain readable on older binaries.

---

## 8. Related

- ADR-0012 — recipients metadata schema v1.1.0
- App Note 02 — encrypted read / runtime patterns
- Guides: key-management (rekey), identity-and-recipients, codecs
