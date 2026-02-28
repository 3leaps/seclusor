# Role Catalog (seclusor)

Agentic role prompts for AI agent sessions in this repository.

Roles extend [crucible baseline roles](https://crucible.3leaps.dev/catalog/roles/) with
seclusor-specific scope, responsibilities, and validation requirements.

## Available Roles

| Role                                   | Slug           | Version | Category   | Purpose                                              |
| -------------------------------------- | -------------- | ------- | ---------- | ---------------------------------------------------- |
| [Development Lead](devlead.yaml)       | `devlead`      | 1.0.1   | agentic    | Core implementation, Rust crates, CLI                |
| [Development Reviewer](devrev.yaml)    | `devrev`       | 1.0.1   | review     | Code review, four-eyes audit, contract parity        |
| [Enterprise Architect](entarch.yaml)   | `entarch`      | 1.0.0   | governance | Cross-repo coordination, API parity, bindings design |
| [Security Review](secrev.yaml)         | `secrev`       | 1.0.0   | review     | Security analysis, crypto review, FFI safety         |
| [Delivery Lead](deliverylead.yaml)     | `deliverylead` | 1.0.0   | governance | Delivery coordination, sprint/phase tracking         |
| [Quality Assurance](qa.yaml)           | `qa`           | 1.0.1   | review     | Testing, cross-platform coverage, parity validation  |
| [Release Engineering](releng.yaml)     | `releng`       | 2.0.0   | automation | Release coordination, versioning, platform matrix    |
| [CI/CD Automation](cicd.yaml)          | `cicd`         | 1.0.0   | automation | Pipelines, runners, build matrix                     |
| [Information Architect](infoarch.yaml) | `infoarch`     | 1.0.0   | agentic    | Documentation, schemas, ADRs/SDRs/DDRs               |

## Key Context for seclusor

### Library-First Architecture

This is a **Rust library with cross-language bindings**, not just a CLI tool.
All roles must consider:

- Crate public API surface (what's `pub` matters for consumers)
- FFI boundary safety (crypto primitives crossing C-ABI)
- Go and TypeScript binding parity
- Library consumers may not have CLI available

### Security-Sensitive Domain

seclusor handles **secrets and encryption**. All roles include heightened
security awareness:

- age encryption with X25519 recipients and scrypt passphrase
- Ciphertext integrity (sec:age:v1: prefix validation)
- Key material never written to repo root (pathguard)
- Secrets never printed to stdout without explicit --reveal
- FFI boundary must never leak plaintext through error messages

### Platform Matrix

Roles that involve builds or releases reference the supported platform set:

- Linux x64/arm64 (glibc + musl)
- macOS arm64
- Windows x64 (future)

## Role Selection Guide

| Task                   | Primary Role   | May Escalate To                              |
| ---------------------- | -------------- | -------------------------------------------- |
| Feature implementation | devlead        | secrev (crypto), qa (testing)                |
| Bug fixes              | devlead        | qa (regression tests)                        |
| Code review            | devrev         | secrev (security), devlead (intent)          |
| Security review        | secrev         | human maintainers (critical)                 |
| Crypto implementation  | devlead+secrev | human maintainers (algorithm decisions)      |
| FFI / bindings design  | entarch        | devlead (implementation)                     |
| Cross-language parity  | entarch        | qa (parity tests)                            |
| Test design            | qa             | devlead (implementation questions)           |
| Delivery coordination  | deliverylead   | devlead (technical), releng (release)        |
| CI/CD changes          | cicd           | releng (release workflows), secrev (secrets) |
| Release preparation    | releng         | cicd (workflows), human maintainers          |
| Documentation / ADRs   | infoarch       | devlead (technical accuracy)                 |

## Usage

Reference roles in session prompts or AGENTS.md:

```yaml
roles:
  - slug: devlead
    source: config/agentic/roles/devlead.yaml
```

## Schema

Role files conform to the [role-prompt schema](https://schemas.3leaps.dev/agentic/v0/role-prompt.schema.json).
