# App Note 01: Git Storage of Armored Secrets — Risk Continuum

**Status**: Draft — subject to change (v0.1.0)  
**Audience**: Developers, DevSecOps engineers, integrators

Seclusor allows you to store encrypted ("armored") secrets alongside code. However, **git is not a secret store**. The safety of this practice exists on a continuum.

## The Risk Spectrum

### 1. Low-Sensitivity / Obfuscation (Recommended for Git)

- **Examples**: CI/CD configuration files, non-secret paths, key IDs, build metadata.
- **Typical content** (contrived low-sensitivity example):
  ```bash
  export BUILD_GPG_HOMEDIR=~/.gnupg/
  export BUILD_PGP_KEY_ID=4A8B2C9D7E1F3A6B!
  export BUILD_SIGNING_KEY=/opt/build-keys/release-signing.key
  ```
- **Goal**: Prevent casual indexing by web crawlers, GitHub search, or accidental exposure in logs.
- **Recommended codec**: Inline (good diffs) or Bundle.
- **Acceptable for long-term git storage** with normal repo access controls.

### 2. Medium-Sensitivity (Use with Caution)

- **Examples**: Database passwords, service account tokens, API keys.
- **Risks**:
  - Key compromise + git history = high-value target.
  - Metadata leakage (inline codec reveals which keys exist and when they changed).
  - Old versions in git retain old ciphertexts even after rekeying.
- **Guidance**: Prefer short-lived branches or external secret managers for production. Use bundle codec. Rotate keys frequently. Audit git history periodically.

### 3. High-Sensitivity (Strongly Discouraged in Git)

**Glassbreak credentials** are the highest-sensitivity secrets (root keys, master passphrases, long-term signing keys, and emergency break-glass accounts).

- **Examples**: Glassbreak credentials, root keys, master passphrases, long-term signing keys (primary initial use case for seclusor).
- **Recommendation**: **Never commit to git**. Store locally with strong file permissions (0600) or in dedicated secret managers. Use `seclusor run` or library calls for injection.

## General Best Practices

- Use the **bundle** codec for maximum metadata protection.
- Never rely on `.gitignore` as a security boundary.
- Rotate recipient keys regularly and re-encrypt.
- Consider whether the information revealed by a compromised key would constitute material risk.
- Prefer `seclusor run` or library-based access over direct git checkout of secrets in production.

---

**Next**: See [App Note 02: Runtime & Deployment Patterns](02-runtime-deployment-patterns.md) for secure local and server-side usage models.

For end-to-end guides using inline encryption with git, see [Inline Credentials Scenario](../guides/scenarios/inline-credentials.md).
