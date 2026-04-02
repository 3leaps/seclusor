use thiserror::Error;

pub fn sanitize_serde_json_error_message(message: &str) -> String {
    let message = sanitize_delimited_value(message, "string \"", '"');
    let message = sanitize_delimited_value(&message, "integer `", '`');
    let message = sanitize_delimited_value(&message, "floating point `", '`');
    let message = sanitize_delimited_value(&message, "boolean `", '`');
    let message = sanitize_delimited_value(&message, "character `", '`');
    let message = sanitize_delimited_value(&message, "byte array `", '`');
    let message = sanitize_segment_after_marker(&message, "invalid type: ");
    sanitize_segment_after_marker(&message, "invalid value: ")
}

fn sanitize_delimited_value(message: &str, prefix: &str, delimiter: char) -> String {
    let mut output = String::with_capacity(message.len());
    let mut remaining = message;

    while let Some(start) = remaining.find(prefix) {
        output.push_str(&remaining[..start]);
        output.push_str(prefix);
        output.push_str("<redacted>");
        output.push(delimiter);

        let after = &remaining[start + prefix.len()..];
        let mut escaped = false;
        let mut end = None;
        for (index, ch) in after.char_indices() {
            if escaped {
                escaped = false;
                continue;
            }
            match ch {
                '\\' if delimiter == '"' => escaped = true,
                ch if ch == delimiter => {
                    end = Some(index);
                    break;
                }
                _ => {}
            }
        }

        match end {
            Some(index) => remaining = &after[index + delimiter.len_utf8()..],
            None => {
                remaining = "";
                break;
            }
        }
    }

    output.push_str(remaining);
    output
}

fn sanitize_segment_after_marker(message: &str, marker: &str) -> String {
    let mut output = String::with_capacity(message.len());
    let mut remaining = message;

    while let Some(start) = remaining.find(marker) {
        output.push_str(&remaining[..start + marker.len()]);
        let after = &remaining[start + marker.len()..];
        let end = after
            .find(", expected")
            .or_else(|| after.find(" at line "))
            .unwrap_or(after.len());
        let segment = &after[..end];

        if segment.contains("<redacted>") {
            output.push_str(segment);
        } else {
            output.push_str("<redacted>");
        }

        remaining = &after[end..];
    }

    output.push_str(remaining);
    output
}

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
    #[error("{0} is inline-encrypted; provide --identity-file to decrypt")]
    InlineEncrypted(String),

    /// Credential is a ref and --emit-ref was not specified.
    #[error("{0} is a ref; use --emit-ref to export references")]
    RefNotExportable(String),

    /// Document exceeds maximum size limit.
    #[error("document exceeds maximum size of {max} bytes (actual: {actual})")]
    DocumentTooLarge { actual: usize, max: usize },

    /// JSON serialization/deserialization error.
    #[error("json error: {0}")]
    Json(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type alias for seclusor operations.
pub type Result<T> = std::result::Result<T, SeclusorError>;

impl From<serde_json::Error> for SeclusorError {
    fn from(value: serde_json::Error) -> Self {
        SeclusorError::Json(sanitize_serde_json_error_message(&value.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::{sanitize_serde_json_error_message, SeclusorError};
    use crate::SecretsFile;

    #[test]
    fn serde_json_error_redacts_plaintext_strings() {
        let json = r#"{"schema_version":"v1.0.0","projects":"cfat_secret_token"}"#;
        let err: SeclusorError = serde_json::from_str::<SecretsFile>(json)
            .expect_err("must fail")
            .into();
        let rendered = err.to_string();
        assert!(!rendered.contains("cfat_secret_token"));
        assert!(rendered.contains("string \"<redacted>\""));
    }

    #[test]
    fn serde_json_error_redacts_plaintext_scalar_values() {
        let json = r#"{"schema_version":"v1.0.0","projects":123456789}"#;
        let err: SeclusorError = serde_json::from_str::<SecretsFile>(json)
            .expect_err("must fail")
            .into();
        let rendered = err.to_string();
        assert!(!rendered.contains("123456789"));
        assert!(rendered.contains("integer `<redacted>`"));

        let json = r#"{"schema_version":"v1.0.0","projects":true}"#;
        let err: SeclusorError = serde_json::from_str::<SecretsFile>(json)
            .expect_err("must fail")
            .into();
        let rendered = err.to_string();
        assert!(!rendered.contains("`true`"));
        assert!(rendered.contains("boolean `<redacted>`"));
    }

    #[test]
    fn serde_json_error_generic_marker_redaction_is_defense_in_depth() {
        let message =
            r#"invalid type: borrowed secret token, expected something else at line 3 column 9"#;
        let rendered = sanitize_serde_json_error_message(message);
        assert_eq!(
            rendered,
            "invalid type: <redacted>, expected something else at line 3 column 9"
        );
    }
}
