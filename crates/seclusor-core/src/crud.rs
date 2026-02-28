use std::collections::BTreeMap;

use crate::error::{Result, SeclusorError};
use crate::model::{Credential, Project, SecretsFile};
use crate::validate::is_valid_credential_key;

/// Resolve a project index by slug.
///
/// If `project_slug` is `None` and the file has exactly one project, returns
/// index 0. If the file has zero or multiple projects, returns an error.
pub fn resolve_project_index(sf: &SecretsFile, project_slug: Option<&str>) -> Result<usize> {
    match project_slug {
        Some(slug) => sf
            .projects
            .iter()
            .position(|p| p.project_slug == slug)
            .ok_or_else(|| SeclusorError::ProjectNotFound(slug.to_string())),
        None => match sf.projects.len() {
            1 => Ok(0),
            0 => Err(SeclusorError::ProjectNotFound(String::new())),
            n => Err(SeclusorError::AmbiguousProject(n)),
        },
    }
}

/// Get a credential from a project.
pub fn get_credential<'a>(
    sf: &'a SecretsFile,
    project_slug: Option<&str>,
    key: &str,
) -> Result<&'a Credential> {
    let idx = resolve_project_index(sf, project_slug)?;
    let project = &sf.projects[idx];
    project
        .credentials
        .get(key)
        .ok_or_else(|| SeclusorError::CredentialNotFound {
            project: project.project_slug.clone(),
            key: key.to_string(),
        })
}

/// Set a credential in a project.
///
/// If `create_project` is true and the file is empty, a new project is created
/// with the given slug (or "default" if no slug specified). If the file is
/// non-empty and the project doesn't exist, returns an error.
pub fn set_credential(
    sf: &mut SecretsFile,
    project_slug: Option<&str>,
    key: &str,
    credential: Credential,
    create_project: bool,
) -> Result<()> {
    if !is_valid_credential_key(key) {
        return Err(SeclusorError::Validation(format!(
            "invalid credential key {:?} (must match ^[A-Z_][A-Z0-9_]*$)",
            key
        )));
    }

    let idx = match resolve_project_index(sf, project_slug) {
        Ok(idx) => idx,
        Err(SeclusorError::ProjectNotFound(slug)) if create_project => {
            if !sf.projects.is_empty() {
                return Err(SeclusorError::CannotAutoCreateProject);
            }
            let slug = if slug.is_empty() {
                "default".to_string()
            } else {
                slug
            };
            sf.projects.push(Project {
                project_slug: slug,
                description: None,
                credentials: BTreeMap::new(),
            });
            sf.projects.len() - 1
        }
        Err(e) => return Err(e),
    };

    sf.projects[idx]
        .credentials
        .insert(key.to_string(), credential);
    Ok(())
}

/// Remove a credential from a project. Returns true if the credential existed.
pub fn unset_credential(
    sf: &mut SecretsFile,
    project_slug: Option<&str>,
    key: &str,
) -> Result<bool> {
    let idx = resolve_project_index(sf, project_slug)?;
    Ok(sf.projects[idx].credentials.remove(key).is_some())
}

/// List all credential keys in a project, sorted alphabetically.
///
/// Keys are naturally sorted because credentials use `BTreeMap`.
pub fn list_credential_keys(sf: &SecretsFile, project_slug: Option<&str>) -> Result<Vec<String>> {
    let idx = resolve_project_index(sf, project_slug)?;
    Ok(sf.projects[idx].credentials.keys().cloned().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::SecretsFile;

    fn test_file() -> SecretsFile {
        let mut sf = SecretsFile::new("myapp");
        sf.projects[0].credentials.insert(
            "API_KEY".to_string(),
            Credential::with_value("secret", "sk-123"),
        );
        sf.projects[0].credentials.insert(
            "DB_URL".to_string(),
            Credential::with_ref("dsn", "postgres://..."),
        );
        sf
    }

    #[test]
    fn resolve_single_project() {
        let sf = test_file();
        assert_eq!(resolve_project_index(&sf, None).unwrap(), 0);
        assert_eq!(resolve_project_index(&sf, Some("myapp")).unwrap(), 0);
    }

    #[test]
    fn resolve_project_not_found() {
        let sf = test_file();
        let err = resolve_project_index(&sf, Some("missing")).unwrap_err();
        assert!(matches!(err, SeclusorError::ProjectNotFound(_)));
    }

    #[test]
    fn resolve_ambiguous_project() {
        let mut sf = test_file();
        sf.projects.push(Project {
            project_slug: "other".to_string(),
            description: None,
            credentials: BTreeMap::new(),
        });
        let err = resolve_project_index(&sf, None).unwrap_err();
        assert!(matches!(err, SeclusorError::AmbiguousProject(2)));
    }

    #[test]
    fn resolve_empty_file() {
        let sf = SecretsFile {
            schema_version: "v1.0.0".to_string(),
            env_prefix: None,
            description: None,
            projects: vec![],
        };
        let err = resolve_project_index(&sf, None).unwrap_err();
        assert!(matches!(err, SeclusorError::ProjectNotFound(_)));
    }

    #[test]
    fn get_existing_credential() {
        let sf = test_file();
        let cred = get_credential(&sf, None, "API_KEY").unwrap();
        assert_eq!(cred.value.as_deref(), Some("sk-123"));
    }

    #[test]
    fn get_missing_credential() {
        let sf = test_file();
        let err = get_credential(&sf, None, "MISSING").unwrap_err();
        assert!(matches!(err, SeclusorError::CredentialNotFound { .. }));
    }

    #[test]
    fn set_new_credential() {
        let mut sf = test_file();
        set_credential(
            &mut sf,
            None,
            "NEW_KEY",
            Credential::with_value("token", "tok-abc"),
            false,
        )
        .unwrap();
        assert!(sf.projects[0].credentials.contains_key("NEW_KEY"));
    }

    #[test]
    fn set_overwrites_existing() {
        let mut sf = test_file();
        set_credential(
            &mut sf,
            None,
            "API_KEY",
            Credential::with_value("secret", "sk-new"),
            false,
        )
        .unwrap();
        let cred = &sf.projects[0].credentials["API_KEY"];
        assert_eq!(cred.value.as_deref(), Some("sk-new"));
    }

    #[test]
    fn set_invalid_key_rejected() {
        let mut sf = test_file();
        let err = set_credential(
            &mut sf,
            None,
            "bad-key",
            Credential::with_value("secret", "v"),
            false,
        )
        .unwrap_err();
        assert!(matches!(err, SeclusorError::Validation(_)));
    }

    #[test]
    fn set_auto_create_project_on_empty() {
        let mut sf = SecretsFile {
            schema_version: "v1.0.0".to_string(),
            env_prefix: None,
            description: None,
            projects: vec![],
        };
        set_credential(
            &mut sf,
            Some("newproj"),
            "KEY",
            Credential::with_value("secret", "val"),
            true,
        )
        .unwrap();
        assert_eq!(sf.projects.len(), 1);
        assert_eq!(sf.projects[0].project_slug, "newproj");
    }

    #[test]
    fn set_auto_create_project_default_slug() {
        let mut sf = SecretsFile {
            schema_version: "v1.0.0".to_string(),
            env_prefix: None,
            description: None,
            projects: vec![],
        };
        set_credential(
            &mut sf,
            None,
            "KEY",
            Credential::with_value("secret", "val"),
            true,
        )
        .unwrap();
        assert_eq!(sf.projects[0].project_slug, "default");
    }

    #[test]
    fn set_cannot_auto_create_on_nonempty() {
        let mut sf = test_file();
        let err = set_credential(
            &mut sf,
            Some("missing"),
            "KEY",
            Credential::with_value("secret", "val"),
            true,
        )
        .unwrap_err();
        assert!(matches!(err, SeclusorError::CannotAutoCreateProject));
    }

    #[test]
    fn unset_existing() {
        let mut sf = test_file();
        assert!(unset_credential(&mut sf, None, "API_KEY").unwrap());
        assert!(!sf.projects[0].credentials.contains_key("API_KEY"));
    }

    #[test]
    fn unset_missing() {
        let mut sf = test_file();
        assert!(!unset_credential(&mut sf, None, "NOPE").unwrap());
    }

    #[test]
    fn list_keys_sorted() {
        let sf = test_file();
        let keys = list_credential_keys(&sf, None).unwrap();
        assert_eq!(keys, vec!["API_KEY", "DB_URL"]);
    }

    #[test]
    fn list_keys_empty_project() {
        let sf = SecretsFile::new("empty");
        let keys = list_credential_keys(&sf, None).unwrap();
        assert!(keys.is_empty());
    }
}
