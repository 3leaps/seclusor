use std::path::PathBuf;

use thiserror::Error;

/// Result type alias for keyring operations.
pub type Result<T> = std::result::Result<T, KeyringError>;

/// Error type for identity and recipient management operations.
#[derive(Debug, Error)]
pub enum KeyringError {
    /// No recipient sources were configured.
    #[error("at least one recipient source is required (file and/or env var)")]
    MissingRecipientSources,

    /// Identity file already exists and create_new mode refused overwrite.
    #[error("identity file already exists: {path}")]
    IdentityFileAlreadyExists { path: PathBuf },

    /// Identity file path is blocked by repository-root pathguard.
    #[error(
        "refusing to write identity file under repository root: {path} (repo root: {repo_root})"
    )]
    IdentityFilePathBlocked { path: PathBuf, repo_root: PathBuf },

    /// Configured recipient environment variable was not present.
    #[error("recipient environment variable is not set: {env_var}")]
    RecipientEnvVarMissing { env_var: String },

    /// Recipient source input exceeded configured size limit.
    #[error("{input} exceeds maximum size of {max} bytes (actual: {actual})")]
    RecipientSourceTooLarge {
        input: &'static str,
        actual: usize,
        max: usize,
    },

    /// Recipient file data was not valid UTF-8.
    #[error("recipient file must be utf-8 encoded")]
    InvalidRecipientFileEncoding,

    /// File-based recipient entry failed parsing.
    #[error("invalid recipient in file on line {line}")]
    InvalidRecipientLine { line: usize },

    /// Env-var recipient token failed parsing.
    #[error("invalid recipient token in env var at index {index}")]
    InvalidRecipientToken { index: usize },

    /// No recipients could be resolved from configured sources.
    #[error("no recipients found in configured sources")]
    EmptyRecipientSet,

    /// A credential had an invalid shape at runtime.
    #[error("credential {key:?} in project {project:?} must set exactly one of value or ref")]
    InvalidCredentialShape { project: String, key: String },

    /// Rekeyed inline payload was not valid UTF-8.
    #[error("credential {key:?} in project {project:?} decrypted to non-utf8 data")]
    NonUtf8InlineValue { project: String, key: String },

    /// Core-domain validation or model error.
    #[error(transparent)]
    Core(#[from] seclusor_core::SeclusorError),

    /// Crypto-layer error.
    #[error(transparent)]
    Crypto(#[from] seclusor_crypto::CryptoError),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
