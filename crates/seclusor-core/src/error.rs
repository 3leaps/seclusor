use thiserror::Error;

/// Error type for seclusor operations.
#[derive(Debug, Error)]
pub enum SeclusorError {
    /// Validation failure with descriptive message.
    #[error("{0}")]
    Validation(String),

    /// Requested project was not found.
    #[error("project not found: {0}")]
    ProjectNotFound(String),

    /// Requested credential was not found in the specified project.
    #[error("credential {key:?} not found in project {project:?}")]
    CredentialNotFound { project: String, key: String },

    /// Multiple projects exist and no project_slug was specified.
    #[error("ambiguous project: file has {0} projects, specify project_slug")]
    AmbiguousProject(usize),

    /// Cannot auto-create a project in a non-empty secrets file.
    #[error("cannot auto-create project in non-empty secrets file")]
    CannotAutoCreateProject,

    /// Value is inline-encrypted and requires decryption.
    #[error("{0} is inline-encrypted; provide identity/passphrase to decrypt")]
    InlineEncrypted(String),

    /// Credential is a ref and --emit-ref was not specified.
    #[error("{0} is a ref; use --emit-ref to export references")]
    RefNotExportable(String),

    /// Document exceeds maximum size limit.
    #[error("document exceeds maximum size of {max} bytes (actual: {actual})")]
    DocumentTooLarge { actual: usize, max: usize },

    /// JSON serialization/deserialization error.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type alias for seclusor operations.
pub type Result<T> = std::result::Result<T, SeclusorError>;
