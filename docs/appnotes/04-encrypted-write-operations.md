# App Note 04: Encrypted Write Operations

**Status**: DRAFT (SC-019 Slice 4 design illustration — not final; not embedded)  
**Audience**: Operators, DevSecOps, library consumers of write-side CLI  
**Depends on**: SC-018 read-side patterns (App Note 02); ADR-0012 recipients metadata  
**Channel**: `#brief-sc-019` design lock — see OOB
`planning/seclusor/SC-019-slice4-init-and-docs-design.md`

> **Do not treat this draft as shipped operator guidance.** Content and residual
> wording land only after multi-seat design lock and Slice 4 implementation.

---

## 1. Why encrypting writes

SC-019 closes the plaintext-on-disk window for **mutating** secrets documents
that are already bundle or inline ciphertext. Prefer in-place encrypting
commands over decrypt → edit → re-encrypt when the document is already under
seclusor management.

**Read-side** patterns remain in [App Note 02](02-runtime-deployment-patterns.md).

---

## 2. Command map (target after Slice 4)

| Command | Plaintext | Inline encrypted | Bundle encrypted |
|---------|-----------|------------------|------------------|
| `secrets set` (value/ref) | mutate | Full decrypt; encrypt only changed values; recipients rules | Full decrypt→mutate→re-encrypt |
| `secrets set --description` only | mutate | Structural-only (no identity) | Encrypting write (identity + recipients) |
| `secrets unset` | mutate | Structural-only (no identity) | Encrypting write |
| `secrets import-env` | mutate | Full encrypting write | Full encrypting write |
| `secrets rekey` | n/a | Normalize all fields + recipients metadata | Same |
| `secrets init` | skeleton JSON | **Slice 4:** `--codec inline` + recipients | **Slice 4:** `--codec bundle` + recipients |

Recipient **set changes** never ride on `set` / `import-env` — use **`rekey`**.

---

## 3. Value input (documented default)

Prefer non-argv channels for secret material:

```bash
# stdin
printf '%s' "$SECRET" | seclusor secrets set \
  --file secrets.age --identity-file id.txt \
  --key API_KEY --value-stdin --recipient age1...

# file / env
seclusor secrets set --value-file ./secret.txt ...
seclusor secrets set --value-env MY_SECRET ...
```

Legacy `--value <str>` remains but **warns on stderr** and must not be the
documented safe path.

---

## 4. Recipients and establishment (summary)

Encrypting writes resolve recipients as:

1. Explicit `--recipient` / `--recipient-file` / `--recipient-env-var`, else  
2. Document `recipients` metadata (schema v1.1.0), else  
3. Fail closed  

Establishment (first write that may persist `recipients` + rewrite
`schema_version` to v1.1.0) follows the **coverage rule**:

- **Bundle:** always whole-document re-encrypt → establishment OK  
- **Inline:** only if the write covers every encrypted field (else refuse → `rekey`)

Stanza-count divergence on encrypting writes: **fail closed** (name `rekey`).
Read/inspect paths may **warn** only.

### Honest residuals (must ship in final note)

| Residual | Meaning |
|----------|---------|
| Inline `recipients` unauthenticated | Field is plaintext JSON; integrity = git + tripwires, not age authentication |
| Same-count member-swap | Replacing one recipient while keeping stanza count equal is **not** detected by count tripwire |
| Value channels | Operator-chosen sources (`--value-file`, env, stdin, legacy argv) have documented exposure; seclusor must not re-persist plaintext to its own temps/logs |
| age `Identity` | Upstream does not zeroize secret scalar on drop — minimize lifetime; do not claim guaranteed erasure |
| Scrypt data bundles | Write paths refuse; **SC-011** owns data-passphrase CLI UX |
| Windows atomicity | `ReplaceFileW`; crash atomicity not guaranteed (documented platform residual) |

---

## 5. Proposed encrypted init (design lock)

```bash
# Plaintext (unchanged)
seclusor secrets init --file secrets.json --project myapp

# Inline encrypted skeleton (proposed)
seclusor secrets init --file secrets.json --codec inline \
  --recipient age1... --project myapp

# Bundle encrypted skeleton (proposed)
seclusor secrets init --file secrets.age --codec bundle \
  --recipient age1... --project myapp
```

**Refuse:** `--force` against an existing **encrypted** target (init is not
repair/rekey). Remove the file or use encrypting write / rekey workflows.

Identity is **not** required for init (encrypt-only create).

---

## 6. Compatibility

Documents that carry top-level `recipients` use schema **v1.1.0**. Pre-SC-019
binaries with `deny_unknown_fields` **fail closed** on those documents (safe
direction). Documents without `recipients` remain readable on older binaries.

---

## 7. Related

- ADR-0012 — recipients metadata schema v1.1.0  
- App Note 02 — encrypted read / runtime patterns  
- Guides: key-management (rekey), identity-and-recipients, codecs  
- OOB design lock: `planning/seclusor/SC-019-slice4-init-and-docs-design.md`  
- **Crucible:** Slice 4 does **not** emit `contract: data-artifact/v0` or
  `process-run/v0` on secrets files; full adopt/defer disposition is in the
  OOB design lock (stance alignment only).
