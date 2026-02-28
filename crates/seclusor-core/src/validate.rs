use std::collections::HashSet;

use crate::constants::*;
use crate::error::SeclusorError;
use crate::model::{Credential, SecretsFile};

/// Check if a credential key matches the required pattern `^[A-Z_][A-Z0-9_]*$`.
pub fn is_valid_credential_key(key: &str) -> bool {
    if key.is_empty() {
        return false;
    }
    let bytes = key.as_bytes();
    let first = bytes[0];
    if !(first.is_ascii_uppercase() || first == b'_') {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|&b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

/// Validate a secrets file, collecting all validation errors.
///
/// Returns an empty vec if the file is valid.
pub fn validate(sf: &SecretsFile) -> Vec<SeclusorError> {
    let mut errors = Vec::new();

    validate_schema_version(sf, &mut errors);
    validate_projects(sf, &mut errors);

    errors
}

/// Validate and return the first error, if any.
pub fn validate_strict(sf: &SecretsFile) -> crate::error::Result<()> {
    let errors = validate(sf);
    if let Some(err) = errors.into_iter().next() {
        return Err(err);
    }
    Ok(())
}

fn validate_schema_version(sf: &SecretsFile, errors: &mut Vec<SeclusorError>) {
    if sf.schema_version.trim() != sf.schema_version {
        errors.push(SeclusorError::Validation(
            "schema_version must not contain leading/trailing whitespace".to_string(),
        ));
    } else if sf.schema_version != SCHEMA_VERSION {
        errors.push(SeclusorError::Validation(format!(
            "unsupported schema_version {:?}",
            sf.schema_version
        )));
    }
}

fn validate_projects(sf: &SecretsFile, errors: &mut Vec<SeclusorError>) {
    if sf.projects.len() > MAX_PROJECTS {
        errors.push(SeclusorError::Validation(format!(
            "too many projects ({}), maximum is {}",
            sf.projects.len(),
            MAX_PROJECTS
        )));
    }

    let mut seen_slugs = HashSet::new();

    for (i, project) in sf.projects.iter().enumerate() {
        if project.project_slug.is_empty() {
            errors.push(SeclusorError::Validation(format!(
                "projects[{}].project_slug is required",
                i
            )));
            continue;
        }

        if project.project_slug.trim() != project.project_slug {
            errors.push(SeclusorError::Validation(format!(
                "projects[{}].project_slug must not contain leading/trailing whitespace",
                i
            )));
        }

        if project.project_slug.len() > MAX_PROJECT_SLUG_LEN {
            errors.push(SeclusorError::Validation(format!(
                "projects[{}].project_slug exceeds maximum length of {}",
                i, MAX_PROJECT_SLUG_LEN
            )));
        }

        if !seen_slugs.insert(&project.project_slug) {
            errors.push(SeclusorError::Validation(format!(
                "duplicate project_slug {:?}",
                project.project_slug
            )));
        }

        if project.credentials.len() > MAX_CREDENTIALS_PER_PROJECT {
            errors.push(SeclusorError::Validation(format!(
                "projects[{}] has too many credentials ({}), maximum is {}",
                i,
                project.credentials.len(),
                MAX_CREDENTIALS_PER_PROJECT
            )));
        }

        for (key, cred) in &project.credentials {
            validate_credential_entry(errors, i, key, cred);
        }
    }
}

fn validate_credential_entry(
    errors: &mut Vec<SeclusorError>,
    project_index: usize,
    key: &str,
    cred: &Credential,
) {
    let ctx = format!("projects[{}].credentials[{:?}]", project_index, key);

    if !is_valid_credential_key(key) {
        errors.push(SeclusorError::Validation(format!(
            "{}: invalid key (must match {})",
            ctx, CREDENTIAL_KEY_PATTERN
        )));
    }

    if key.len() > MAX_CREDENTIAL_KEY_LEN {
        errors.push(SeclusorError::Validation(format!(
            "{}: key exceeds maximum length of {}",
            ctx, MAX_CREDENTIAL_KEY_LEN
        )));
    }

    if cred.credential_type.is_empty() || cred.credential_type.trim().is_empty() {
        errors.push(SeclusorError::Validation(format!(
            "{}.type is required and must not be empty or whitespace",
            ctx
        )));
    }

    if cred.credential_type.len() > MAX_CREDENTIAL_TYPE_LEN {
        errors.push(SeclusorError::Validation(format!(
            "{}.type exceeds maximum length of {}",
            ctx, MAX_CREDENTIAL_TYPE_LEN
        )));
    }

    match (&cred.value, &cred.reference) {
        (Some(_), Some(_)) | (None, None) => {
            errors.push(SeclusorError::Validation(format!(
                "{} must set exactly one of value or ref",
                ctx
            )));
        }
        (Some(v), None) => {
            if v.is_empty() || v.trim().is_empty() {
                errors.push(SeclusorError::Validation(format!(
                    "{}.value must not be empty or whitespace",
                    ctx
                )));
            }
            if v.len() > MAX_CREDENTIAL_VALUE_BYTES {
                errors.push(SeclusorError::Validation(format!(
                    "{}.value exceeds maximum size of {} bytes",
                    ctx, MAX_CREDENTIAL_VALUE_BYTES
                )));
            }
        }
        (None, Some(r)) => {
            if r.is_empty() || r.trim().is_empty() {
                errors.push(SeclusorError::Validation(format!(
                    "{}.ref must not be empty or whitespace",
                    ctx
                )));
            }
            if r.len() > MAX_CREDENTIAL_REF_LEN {
                errors.push(SeclusorError::Validation(format!(
                    "{}.ref exceeds maximum length of {}",
                    ctx, MAX_CREDENTIAL_REF_LEN
                )));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Credential, Project, SecretsFile};
    use std::collections::BTreeMap;

    fn valid_file() -> SecretsFile {
        let mut creds = BTreeMap::new();
        creds.insert(
            "API_KEY".to_string(),
            Credential::with_value("secret", "sk-123"),
        );
        SecretsFile {
            schema_version: "v1.0.0".to_string(),
            env_prefix: None,
            description: None,
            projects: vec![Project {
                project_slug: "myapp".to_string(),
                description: None,
                credentials: creds,
            }],
        }
    }

    #[test]
    fn valid_file_passes() {
        let errors = validate(&valid_file());
        assert!(errors.is_empty(), "expected no errors, got: {:?}", errors);
    }

    #[test]
    fn valid_credential_keys() {
        assert!(is_valid_credential_key("API_KEY"));
        assert!(is_valid_credential_key("A"));
        assert!(is_valid_credential_key("_PRIVATE"));
        assert!(is_valid_credential_key("DB_URL_2"));
        assert!(is_valid_credential_key("X"));
        assert!(is_valid_credential_key("__"));
    }

    #[test]
    fn invalid_credential_keys() {
        assert!(!is_valid_credential_key(""));
        assert!(!is_valid_credential_key("api_key")); // lowercase
        assert!(!is_valid_credential_key("1KEY")); // starts with digit
        assert!(!is_valid_credential_key("API-KEY")); // hyphen
        assert!(!is_valid_credential_key("API KEY")); // space
        assert!(!is_valid_credential_key("api.key")); // dot
    }

    #[test]
    fn unsupported_schema_version() {
        let mut sf = valid_file();
        sf.schema_version = "v2.0.0".to_string();
        let errors = validate(&sf);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].to_string().contains("unsupported schema_version"));
    }

    #[test]
    fn schema_version_whitespace() {
        let mut sf = valid_file();
        sf.schema_version = " v1.0.0".to_string();
        let errors = validate(&sf);
        assert_eq!(errors.len(), 1);
        assert!(errors[0]
            .to_string()
            .contains("leading/trailing whitespace"));
    }

    #[test]
    fn empty_project_slug() {
        let mut sf = valid_file();
        sf.projects[0].project_slug = String::new();
        let errors = validate(&sf);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].to_string().contains("project_slug is required"));
    }

    #[test]
    fn project_slug_whitespace() {
        let mut sf = valid_file();
        sf.projects[0].project_slug = "myapp ".to_string();
        let errors = validate(&sf);
        assert!(!errors.is_empty());
        assert!(errors[0]
            .to_string()
            .contains("leading/trailing whitespace"));
    }

    #[test]
    fn duplicate_project_slugs() {
        let mut sf = valid_file();
        sf.projects.push(Project {
            project_slug: "myapp".to_string(),
            description: None,
            credentials: BTreeMap::new(),
        });
        let errors = validate(&sf);
        assert!(!errors.is_empty());
        assert!(errors
            .iter()
            .any(|e| e.to_string().contains("duplicate project_slug")));
    }

    #[test]
    fn too_many_projects() {
        let mut sf = valid_file();
        sf.projects.clear();
        for i in 0..201 {
            sf.projects.push(Project {
                project_slug: format!("proj_{}", i),
                description: None,
                credentials: BTreeMap::new(),
            });
        }
        let errors = validate(&sf);
        assert!(errors
            .iter()
            .any(|e| e.to_string().contains("too many projects")));
    }

    #[test]
    fn invalid_credential_key_in_file() {
        let mut sf = valid_file();
        sf.projects[0]
            .credentials
            .insert("bad-key".to_string(), Credential::with_value("secret", "v"));
        let errors = validate(&sf);
        assert!(errors.iter().any(|e| e.to_string().contains("invalid key")));
    }

    #[test]
    fn value_ref_both_set() {
        let mut sf = valid_file();
        sf.projects[0].credentials.insert(
            "BOTH".to_string(),
            Credential {
                credential_type: "secret".to_string(),
                value: Some("val".to_string()),
                reference: Some("ref".to_string()),
                description: None,
            },
        );
        let errors = validate(&sf);
        assert!(errors
            .iter()
            .any(|e| e.to_string().contains("exactly one of value or ref")));
    }

    #[test]
    fn value_ref_neither_set() {
        let mut sf = valid_file();
        sf.projects[0].credentials.insert(
            "NEITHER".to_string(),
            Credential {
                credential_type: "secret".to_string(),
                value: None,
                reference: None,
                description: None,
            },
        );
        let errors = validate(&sf);
        assert!(errors
            .iter()
            .any(|e| e.to_string().contains("exactly one of value or ref")));
    }

    #[test]
    fn empty_value() {
        let mut sf = valid_file();
        sf.projects[0]
            .credentials
            .insert("EMPTY".to_string(), Credential::with_value("secret", ""));
        let errors = validate(&sf);
        assert!(errors
            .iter()
            .any(|e| e.to_string().contains("value must not be empty")));
    }

    #[test]
    fn whitespace_only_value() {
        let mut sf = valid_file();
        sf.projects[0]
            .credentials
            .insert("WS".to_string(), Credential::with_value("secret", "   "));
        let errors = validate(&sf);
        assert!(errors
            .iter()
            .any(|e| e.to_string().contains("value must not be empty")));
    }

    #[test]
    fn empty_credential_type() {
        let mut sf = valid_file();
        sf.projects[0]
            .credentials
            .insert("KEY".to_string(), Credential::with_value("", "val"));
        let errors = validate(&sf);
        assert!(errors
            .iter()
            .any(|e| e.to_string().contains("type is required")));
    }

    #[test]
    fn ref_empty() {
        let mut sf = valid_file();
        sf.projects[0]
            .credentials
            .insert("EMPTYREF".to_string(), Credential::with_ref("dsn", ""));
        let errors = validate(&sf);
        assert!(errors
            .iter()
            .any(|e| e.to_string().contains("ref must not be empty")));
    }

    #[test]
    fn validate_strict_returns_first_error() {
        let mut sf = valid_file();
        sf.schema_version = "bad".to_string();
        sf.projects[0].project_slug = String::new();
        let result = validate_strict(&sf);
        assert!(result.is_err());
    }

    #[test]
    fn validate_strict_ok_for_valid() {
        let result = validate_strict(&valid_file());
        assert!(result.is_ok());
    }

    #[test]
    fn credential_value_too_large() {
        let mut sf = valid_file();
        let big_value = "x".repeat(MAX_CREDENTIAL_VALUE_BYTES + 1);
        sf.projects[0].credentials.insert(
            "BIG".to_string(),
            Credential::with_value("secret", &big_value),
        );
        let errors = validate(&sf);
        assert!(errors
            .iter()
            .any(|e| e.to_string().contains("exceeds maximum size")));
    }

    #[test]
    fn credential_ref_too_long() {
        let mut sf = valid_file();
        let long_ref = "x".repeat(MAX_CREDENTIAL_REF_LEN + 1);
        sf.projects[0].credentials.insert(
            "LONGREF".to_string(),
            Credential::with_ref("dsn", &long_ref),
        );
        let errors = validate(&sf);
        assert!(errors
            .iter()
            .any(|e| e.to_string().contains("ref exceeds maximum length")));
    }

    #[test]
    fn credential_type_too_long() {
        let mut sf = valid_file();
        let long_type = "x".repeat(MAX_CREDENTIAL_TYPE_LEN + 1);
        sf.projects[0]
            .credentials
            .insert("KEY".to_string(), Credential::with_value(&long_type, "val"));
        let errors = validate(&sf);
        assert!(errors
            .iter()
            .any(|e| e.to_string().contains("type exceeds maximum length")));
    }

    #[test]
    fn project_slug_too_long() {
        let mut sf = valid_file();
        sf.projects[0].project_slug = "x".repeat(MAX_PROJECT_SLUG_LEN + 1);
        let errors = validate(&sf);
        assert!(errors.iter().any(|e| e
            .to_string()
            .contains("project_slug exceeds maximum length")));
    }
}
