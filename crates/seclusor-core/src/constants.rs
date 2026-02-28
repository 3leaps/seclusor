/// Current schema version for secrets files.
pub const SCHEMA_VERSION: &str = "v1.0.0";

/// Prefix for inline-encrypted age ciphertext values.
pub const INLINE_CIPHERTEXT_PREFIX: &str = "sec:age:v1:";

/// Maximum size of a secrets document in bytes (2 MiB).
pub const MAX_SECRETS_DOC_BYTES: usize = 2 * 1024 * 1024;

/// Maximum size of bundle ciphertext in bytes (16 MiB).
pub const MAX_BUNDLE_CIPHERTEXT_BYTES: usize = 16 * 1024 * 1024;

/// Maximum size of bundle plaintext in bytes (16 MiB).
pub const MAX_BUNDLE_PLAINTEXT_BYTES: usize = 16 * 1024 * 1024;

/// Maximum number of projects in a secrets file.
pub const MAX_PROJECTS: usize = 200;

/// Maximum number of credentials per project.
pub const MAX_CREDENTIALS_PER_PROJECT: usize = 500;

/// Maximum length of a project slug.
pub const MAX_PROJECT_SLUG_LEN: usize = 128;

/// Maximum length of a credential key.
pub const MAX_CREDENTIAL_KEY_LEN: usize = 128;

/// Maximum length of a credential type string.
pub const MAX_CREDENTIAL_TYPE_LEN: usize = 64;

/// Maximum size of a credential value in bytes (1 MiB).
pub const MAX_CREDENTIAL_VALUE_BYTES: usize = 1024 * 1024;

/// Maximum length of a credential ref string.
pub const MAX_CREDENTIAL_REF_LEN: usize = 2048;

/// Maximum size of inline ciphertext in bytes after decoding (1 MiB).
pub const MAX_INLINE_CIPHERTEXT_BYTES: usize = 1024 * 1024;

/// Maximum size of inline plaintext in bytes (1 MiB).
pub const MAX_INLINE_PLAINTEXT_BYTES: usize = 1024 * 1024;

/// Maximum size of decrypted plaintext in bytes (16 MiB).
pub const MAX_DECRYPT_PLAINTEXT_BYTES: usize = 16 * 1024 * 1024;

/// Default credential type when importing from environment.
pub const DEFAULT_CREDENTIAL_TYPE: &str = "secret";

/// Human-readable credential key pattern (for error messages).
pub const CREDENTIAL_KEY_PATTERN: &str = "^[A-Z_][A-Z0-9_]*$";
