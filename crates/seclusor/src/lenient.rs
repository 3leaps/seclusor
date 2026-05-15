use std::path::Path;

use seclusor_core::constants::{MAX_SECRETS_DOC_BYTES, SCHEMA_VERSION};
use seclusor_core::validate::validate_strict;
use seclusor_core::{Credential, SeclusorError, SecretsFile};

use crate::cli::UnsetArgs;
use crate::error::{CliError, CliResult};
use crate::io::{read_file_with_limit, read_secrets_file, write_json_value_file};

pub(crate) fn handle_unset_lenient(args: UnsetArgs) -> CliResult<()> {
    eprintln!("warning: file contains malformed credentials; using lenient parse");

    let bytes = read_file_with_limit(&args.file, MAX_SECRETS_DOC_BYTES)?;
    let mut root: serde_json::Value = serde_json::from_slice(&bytes)?;
    remove_credential_lenient(&mut root, args.project.as_deref(), &args.key)?;
    write_json_value_file(&args.file, &root)?;

    if let Err(err) = read_secrets_file(&args.file) {
        eprintln!(
            "warning: file was updated, but malformed credentials remain after removing {:?}: {}",
            args.key, err
        );
        return Err(CliError::Message(format!(
            "file was updated, but malformed credentials remain after removing {:?}",
            args.key
        )));
    }

    println!("ok");
    Ok(())
}

pub(crate) fn should_use_lenient_unset(
    path: &Path,
    project_slug: Option<&str>,
    key: &str,
    err: &CliError,
) -> bool {
    match err {
        CliError::Json(_) => true,
        CliError::Core(SeclusorError::Validation(_)) => {
            target_credential_requires_lenient_repair(path, project_slug, key).unwrap_or(false)
        }
        _ => false,
    }
}

fn target_credential_requires_lenient_repair(
    path: &Path,
    project_slug: Option<&str>,
    key: &str,
) -> CliResult<bool> {
    let bytes = read_file_with_limit(path, MAX_SECRETS_DOC_BYTES)?;
    let root: serde_json::Value = serde_json::from_slice(&bytes)?;
    let Some(raw_credential) = target_credential_value(&root, project_slug, key)? else {
        return Ok(false);
    };

    if !raw_credential.is_object() {
        return Ok(true);
    }

    let credential = match serde_json::from_value::<Credential>(raw_credential.clone()) {
        Ok(credential) => credential,
        Err(_) => return Ok(true),
    };

    let mut probe = SecretsFile::new("lenient-unset-probe");
    probe.schema_version = SCHEMA_VERSION.to_string();
    probe.projects[0]
        .credentials
        .insert(key.to_string(), credential);
    Ok(validate_strict(&probe).is_err())
}

fn target_credential_value<'a>(
    root: &'a serde_json::Value,
    project_slug: Option<&str>,
    key: &str,
) -> CliResult<Option<&'a serde_json::Value>> {
    let projects = root
        .get("projects")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            CliError::Message("lenient unset requires a top-level projects array".to_string())
        })?;

    let project_index = resolve_lenient_project_index(projects, project_slug)?;
    let project = &projects[project_index];
    let credentials = project
        .get("credentials")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            CliError::Message(
                "lenient unset requires each project to contain a credentials object".to_string(),
            )
        })?;

    Ok(credentials.get(key))
}

fn remove_credential_lenient(
    root: &mut serde_json::Value,
    project_slug: Option<&str>,
    key: &str,
) -> CliResult<()> {
    let projects = root
        .get_mut("projects")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or_else(|| {
            CliError::Message("lenient unset requires a top-level projects array".to_string())
        })?;

    let project_index = resolve_lenient_project_index(projects, project_slug)?;
    let project = &mut projects[project_index];
    let credentials = project
        .get_mut("credentials")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| {
            CliError::Message(
                "lenient unset requires each project to contain a credentials object".to_string(),
            )
        })?;

    if credentials.remove(key).is_some() {
        return Ok(());
    }

    let available = available_credential_keys(credentials);
    if available.is_empty() {
        return Err(CliError::Message(format!(
            "credential {key:?} not found; project has no credential keys"
        )));
    }

    Err(CliError::Message(format!(
        "credential {key:?} not found; available keys: {}",
        available.join(", ")
    )))
}

fn resolve_lenient_project_index(
    projects: &[serde_json::Value],
    requested_slug: Option<&str>,
) -> CliResult<usize> {
    if let Some(slug) = requested_slug {
        return projects
            .iter()
            .position(|project| {
                project
                    .get("project_slug")
                    .and_then(serde_json::Value::as_str)
                    == Some(slug)
            })
            .ok_or_else(|| CliError::Core(SeclusorError::ProjectNotFound(slug.to_string())));
    }

    if projects.len() == 1 {
        return Ok(0);
    }

    Err(CliError::Core(SeclusorError::AmbiguousProject(
        projects.len(),
    )))
}

fn available_credential_keys(
    credentials: &serde_json::Map<String, serde_json::Value>,
) -> Vec<String> {
    credentials.keys().cloned().collect()
}
