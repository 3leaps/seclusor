use seclusor_core::error::sanitize_serde_json_error_message;
use seclusor_core::SeclusorError;
use seclusor_crypto::CryptoError;
use seclusor_keyring::KeyringError;
use seclusor_sign::SignError;
use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum CliError {
    #[error("{0}")]
    Message(String),
    /// Write command refused a positively identified encrypted target (bundle or inline).
    ///
    /// Display must never include document content — only path and source classification.
    #[error(
        "refusing to write into encrypted secrets file at {path} (source: {source_kind}); \
         encrypted write support is not available in this version. \
         Use a plaintext secrets file, or decrypt/convert first."
    )]
    EncryptedWriteUnsupported {
        path: String,
        /// Machine-readable source token: `bundle` or `inline`.
        source_kind: &'static str,
    },
    /// Target file changed between load and atomic commit (CAS precondition).
    #[error(
        "concurrent modification detected for {path}; refusing to overwrite. \
         Re-run the command against the current file."
    )]
    ConcurrentModification { path: String },
    #[error(transparent)]
    Core(#[from] SeclusorError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Codec(#[from] seclusor_codec::CodecError),
    #[error(transparent)]
    Keyring(#[from] KeyringError),
    #[error(transparent)]
    Sign(#[from] SignError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(String),

    #[error("command failed with exit code {0}")]
    CommandFailed(i32),
}

pub(crate) type CliResult<T> = std::result::Result<T, CliError>;

impl From<serde_json::Error> for CliError {
    fn from(value: serde_json::Error) -> Self {
        CliError::Json(sanitize_serde_json_error_message(&value.to_string()))
    }
}
