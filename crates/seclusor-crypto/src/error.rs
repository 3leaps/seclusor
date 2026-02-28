use thiserror::Error;

/// Result type alias for crypto operations.
pub type Result<T> = std::result::Result<T, CryptoError>;

/// Error type for encryption and decryption operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Recipient list is required for recipient-mode encryption.
    #[error("at least one recipient is required")]
    MissingRecipients,

    /// Identity list is required for recipient-mode decryption.
    #[error("at least one identity is required")]
    MissingIdentities,

    /// A recipient string could not be parsed.
    #[error("invalid recipient at index {index}")]
    InvalidRecipient { index: usize },

    /// An identity string could not be parsed.
    #[error("invalid identity at index {index}")]
    InvalidIdentity { index: usize },

    /// Identity file content was malformed.
    #[error("identity file contains non-identity data on line {line}")]
    InvalidIdentityFileLine { line: usize },

    /// Identity file did not contain any usable identities.
    #[error("identity file contains no identities")]
    EmptyIdentityFile,

    /// Identity file permissions are not secure enough.
    #[error("identity file permissions must be 0600 on unix (actual: {actual:o})")]
    InsecureIdentityFilePermissions { actual: u32 },

    /// Inline ciphertext value must have the required prefix.
    #[error("inline ciphertext must start with sec:age:v1:")]
    InvalidInlineCiphertextPrefix,

    /// Inline ciphertext value had invalid base64 encoding.
    #[error("inline ciphertext has invalid base64 encoding")]
    InvalidInlineCiphertextEncoding,

    /// A size limit was exceeded.
    #[error("{kind} exceeds maximum size of {max} bytes (actual: {actual})")]
    SizeLimitExceeded {
        kind: &'static str,
        actual: usize,
        max: usize,
    },

    /// Encryption failed.
    #[error("encryption failed")]
    EncryptionFailed,

    /// Decryption failed.
    #[error("decryption failed")]
    DecryptionFailed,

    /// Ciphertext was malformed or not an age payload.
    #[error("invalid ciphertext")]
    InvalidCiphertext,

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
