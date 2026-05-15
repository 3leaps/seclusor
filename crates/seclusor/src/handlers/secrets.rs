use seclusor_core::constants::MAX_SECRETS_DOC_BYTES;
use seclusor_core::crud::{
    get_credential, list_credential_keys, resolve_project_index, set_credential, unset_credential,
};
use seclusor_core::env::{format_env_vars, import_env_vars, parse_dotenv};
use seclusor_core::validate::{normalize_description, validate_strict};
use seclusor_core::{Credential, SeclusorError, SecretsFile};

use crate::cli::{
    ExportEnvArgs, GetArgs, ImportEnvArgs, InitArgs, ListArgs, SetArgs, UnsetArgs, ValidateArgs,
};
use crate::env_support::resolve_export_env_vars;
use crate::error::{CliError, CliResult};
use crate::io::{
    read_file_with_limit, read_runtime_secrets_file, read_secrets_file, write_secrets_file,
};
use crate::lenient::{handle_unset_lenient, should_use_lenient_unset};
use crate::resolve::resolve_identities;
use crate::REDACTED_OUTPUT;

pub(crate) fn handle_init(args: InitArgs) -> CliResult<()> {
    if args.file.exists() && !args.force {
        return Err(CliError::Message(format!(
            "secrets file already exists at {}; use --force to overwrite",
            args.file.display()
        )));
    }

    let mut secrets = SecretsFile::new(&args.project);
    secrets.env_prefix = args.env_prefix;
    secrets.description = normalize_description(args.description.as_deref());
    validate_strict(&secrets)?;
    write_secrets_file(&args.file, &secrets, !args.force)?;
    println!("{}", args.file.display());
    Ok(())
}

pub(crate) fn handle_set(args: SetArgs) -> CliResult<()> {
    let mut secrets = read_secrets_file(&args.file)?;
    let existing_description = get_credential(&secrets, args.project.as_deref(), &args.key)
        .ok()
        .and_then(|credential| credential.description.clone());
    let credential = credential_from_set_args(&args, existing_description)?;
    set_credential(
        &mut secrets,
        args.project.as_deref(),
        &args.key,
        credential,
        args.create_project,
    )?;
    validate_strict(&secrets)?;
    write_secrets_file(&args.file, &secrets, false)?;
    println!("ok");
    Ok(())
}

pub(crate) fn handle_get(args: GetArgs) -> CliResult<()> {
    let identities = resolve_identities(&args.identities, &args.passphrase, false)?;
    let secrets = read_runtime_secrets_file(&args.file, &identities)?;
    let credential = get_credential(&secrets, args.project.as_deref(), &args.key)?;
    match get_output_mode(&args) {
        GetOutputMode::Redacted => {
            println!("{REDACTED_OUTPUT}");
            Ok(())
        }
        GetOutputMode::Reveal => {
            if let Some(value) = &credential.value {
                if value.starts_with(seclusor_core::constants::INLINE_CIPHERTEXT_PREFIX) {
                    return Err(CliError::Core(SeclusorError::InlineEncrypted(
                        args.key.clone(),
                    )));
                }
                println!("{value}");
                return Ok(());
            }
            if let Some(reference) = &credential.reference {
                println!("{reference}");
                return Ok(());
            }
            Err(CliError::Message(
                "credential has neither value nor ref".to_string(),
            ))
        }
        GetOutputMode::Description => {
            if let Some(description) = &credential.description {
                println!("{description}");
            }
            Ok(())
        }
    }
}

pub(crate) fn handle_list(args: ListArgs) -> CliResult<()> {
    let secrets = read_secrets_file(&args.file)?;
    if !args.verbose {
        let keys = list_credential_keys(&secrets, args.project.as_deref())?;
        for key in keys {
            println!("{key}");
        }
        return Ok(());
    }

    let project_index = resolve_project_index(&secrets, args.project.as_deref())?;
    let project = &secrets.projects[project_index];
    for (key, credential) in &project.credentials {
        if let Some(description) = credential.description.as_deref() {
            println!("{key}\t{description}");
        } else {
            println!("{key}");
        }
    }

    Ok(())
}

pub(crate) fn handle_unset(args: UnsetArgs) -> CliResult<()> {
    match read_secrets_file(&args.file) {
        Ok(mut secrets) => {
            let _ = get_credential(&secrets, args.project.as_deref(), &args.key)?;
            let removed = unset_credential(&mut secrets, args.project.as_deref(), &args.key)?;
            if !removed {
                return Err(CliError::Message("credential was not removed".to_string()));
            }
            validate_strict(&secrets)?;
            write_secrets_file(&args.file, &secrets, false)?;
            println!("ok");
            Ok(())
        }
        Err(err)
            if should_use_lenient_unset(&args.file, args.project.as_deref(), &args.key, &err) =>
        {
            handle_unset_lenient(args)
        }
        Err(err) => Err(err),
    }
}

pub(crate) fn handle_validate(args: ValidateArgs) -> CliResult<()> {
    let secrets = read_secrets_file(&args.file)?;
    validate_strict(&secrets)?;
    println!("valid");
    Ok(())
}

pub(crate) fn handle_export_env(args: ExportEnvArgs) -> CliResult<()> {
    let identities = resolve_identities(&args.identities, &args.passphrase, false)?;
    let secrets = read_runtime_secrets_file(&args.file, &identities)?;
    let output = render_export_env_output(&secrets, args.project.as_deref(), &args)?;
    println!("{output}");
    Ok(())
}

pub(crate) fn handle_import_env(args: ImportEnvArgs) -> CliResult<()> {
    let mut secrets = read_secrets_file(&args.file)?;

    let prefix = args
        .prefix
        .clone()
        .or_else(|| secrets.env_prefix.clone())
        .ok_or_else(|| {
            CliError::Message(
                "import-env requires --prefix or secrets file env_prefix for safe filtering"
                    .to_string(),
            )
        })?;

    let source = read_import_source(&args)?;
    let filtered: Vec<(String, String)> = source
        .into_iter()
        .filter(|(key, _)| key.starts_with(&prefix))
        .collect();

    if filtered.is_empty() {
        return Err(CliError::Message(format!(
            "no environment variables matched prefix {:?}",
            prefix
        )));
    }

    let strip_prefix = if args.strip_prefix {
        Some(prefix.as_str())
    } else {
        None
    };

    let imported = import_env_vars(&filtered, Some(&args.credential_type), strip_prefix);
    if imported.is_empty() {
        return Err(CliError::Message(
            "no credentials were imported from source variables".to_string(),
        ));
    }

    let mut count = 0usize;
    for (key, credential) in imported {
        set_credential(
            &mut secrets,
            args.project.as_deref(),
            &key,
            credential,
            args.create_project,
        )?;
        count += 1;
    }

    validate_strict(&secrets)?;
    write_secrets_file(&args.file, &secrets, false)?;
    println!("{count}");
    Ok(())
}

fn render_export_env_output(
    secrets: &SecretsFile,
    project_slug: Option<&str>,
    args: &ExportEnvArgs,
) -> CliResult<String> {
    let vars = resolve_export_env_vars(
        secrets,
        project_slug,
        args.prefix.as_deref(),
        args.emit_ref,
        &args.allow,
        &args.deny,
    )?;
    Ok(format_env_vars(&vars, args.format.into()))
}

fn read_import_source(args: &ImportEnvArgs) -> CliResult<Vec<(String, String)>> {
    if let Some(path) = &args.dotenv_file {
        let bytes = read_file_with_limit(path, MAX_SECRETS_DOC_BYTES)?;
        let contents = String::from_utf8(bytes).map_err(|_| {
            CliError::Message(format!(
                "dotenv file must be utf-8 encoded: {}",
                path.display()
            ))
        })?;
        return Ok(parse_dotenv(&contents));
    }

    Ok(std::env::vars().collect())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GetOutputMode {
    Redacted,
    Reveal,
    Description,
}

fn get_output_mode(args: &GetArgs) -> GetOutputMode {
    if args.show_description {
        GetOutputMode::Description
    } else if args.reveal {
        GetOutputMode::Reveal
    } else {
        GetOutputMode::Redacted
    }
}

fn credential_from_set_args(
    args: &SetArgs,
    existing_description: Option<String>,
) -> CliResult<Credential> {
    let description = match args.description.as_deref() {
        Some(input) => normalize_description(Some(input)),
        None => existing_description,
    };

    match (&args.value, &args.reference) {
        (Some(value), None) => {
            let mut credential = Credential::with_value(&args.credential_type, value);
            credential.description = description;
            Ok(credential)
        }
        (None, Some(reference)) => {
            let mut credential = Credential::with_ref(&args.credential_type, reference);
            credential.description = description;
            Ok(credential)
        }
        (Some(_), Some(_)) => Err(CliError::Message(
            "set requires exactly one of --value or --ref".to_string(),
        )),
        (None, None) => Err(CliError::Message(
            "set requires exactly one of --value or --ref".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    use seclusor_core::SeclusorError;
    use seclusor_crypto::Identity;

    use crate::cli::*;
    use crate::error::CliError;
    use crate::handlers::bundle::handle_bundle_encrypt;
    use crate::io::{read_secrets_file, write_secrets_file};
    use crate::test_support::*;

    #[test]
    fn credential_from_set_args_requires_exactly_one_value_source() {
        let both = SetArgs {
            file: PathBuf::from("x"),
            project: None,
            key: "API_KEY".to_string(),
            credential_type: "secret".to_string(),
            value: Some("a".to_string()),
            reference: Some("b".to_string()),
            description: None,
            create_project: false,
        };
        assert!(credential_from_set_args(&both, None).is_err());

        let neither = SetArgs {
            value: None,
            reference: None,
            ..both
        };
        assert!(credential_from_set_args(&neither, None).is_err());
    }

    #[test]
    fn credential_from_set_args_preserves_replaces_and_clears_description() {
        let base = SetArgs {
            file: PathBuf::from("x"),
            project: None,
            key: "API_KEY".to_string(),
            credential_type: "secret".to_string(),
            value: Some("a".to_string()),
            reference: None,
            description: None,
            create_project: false,
        };

        let preserved = credential_from_set_args(&base, Some("existing note".to_string())).unwrap();
        assert_eq!(preserved.description.as_deref(), Some("existing note"));

        let replaced = credential_from_set_args(
            &SetArgs {
                description: Some("  new note  ".to_string()),
                ..base.clone()
            },
            Some("existing note".to_string()),
        )
        .unwrap();
        assert_eq!(replaced.description.as_deref(), Some("new note"));

        let cleared = credential_from_set_args(
            &SetArgs {
                description: Some("   ".to_string()),
                ..base
            },
            Some("existing note".to_string()),
        )
        .unwrap();
        assert!(cleared.description.is_none());
    }

    #[test]
    fn handle_unset_removes_existing_key() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("secrets.json");
        let secrets = fixture_secrets();
        write_secrets_file(&path, &secrets, true).expect("write");

        handle_unset(UnsetArgs {
            file: path.clone(),
            project: Some("demo".to_string()),
            key: "API_KEY".to_string(),
        })
        .expect("unset");

        let loaded = read_secrets_file(&path).expect("reload");
        assert!(!loaded.projects[0].credentials.contains_key("API_KEY"));
    }

    #[test]
    fn handle_get_rejects_invalid_document() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("invalid.json");
        write_raw_json(
            &path,
            r#"{"schema_version":"v9.9.9","projects":[{"project_slug":"demo","credentials":{"API_KEY":{"type":"secret","value":"x"}}}]}"#,
        );

        let err = handle_get(GetArgs {
            file: path,
            project: Some("demo".to_string()),
            key: "API_KEY".to_string(),
            reveal: false,
            show_description: false,
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("must reject invalid document");
        assert!(matches!(
            err,
            CliError::Codec(seclusor_codec::CodecError::Core(SeclusorError::Validation(
                _
            )))
        ));
    }

    #[test]
    fn handle_get_bundle_redacted_and_reveal() {
        let dir = tempfile::tempdir().expect("temp dir");
        let input = dir.path().join("input.json");
        let bundle = dir.path().join("secrets.age");
        let identity_file = dir.path().join("identity.txt");
        let secrets = fixture_secrets();
        write_secrets_file(&input, &secrets, true).expect("write input");
        write_identity_file(&identity_file, TEST_IDENTITY);

        handle_bundle_encrypt(BundleEncryptArgs {
            input,
            output: bundle.clone(),
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
        })
        .expect("bundle encrypt");

        handle_get(GetArgs {
            file: bundle.clone(),
            project: Some("demo".to_string()),
            key: "API_KEY".to_string(),
            reveal: false,
            show_description: false,
            identities: IdentityArgs {
                identity_files: vec![identity_file.clone()],
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect("get redacted from bundle");

        handle_get(GetArgs {
            file: bundle,
            project: Some("demo".to_string()),
            key: "API_KEY".to_string(),
            reveal: true,
            show_description: false,
            identities: IdentityArgs {
                identity_files: vec![identity_file],
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect("get reveal from bundle");
    }

    #[test]
    fn handle_get_bundle_requires_identity_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let input = dir.path().join("input.json");
        let bundle = dir.path().join("secrets.age");
        let secrets = fixture_secrets();
        write_secrets_file(&input, &secrets, true).expect("write input");

        handle_bundle_encrypt(BundleEncryptArgs {
            input,
            output: bundle.clone(),
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
        })
        .expect("bundle encrypt");

        let err = handle_get(GetArgs {
            file: bundle,
            project: Some("demo".to_string()),
            key: "API_KEY".to_string(),
            reveal: false,
            show_description: false,
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("bundle runtime must require identities");

        assert!(matches!(
            err,
            CliError::Codec(seclusor_codec::CodecError::BundleIdentityRequired)
        ));
    }

    #[test]
    fn handle_get_bundle_wrong_identity_does_not_disclose_secret() {
        let dir = tempfile::tempdir().expect("temp dir");
        let input = dir.path().join("input.json");
        let bundle = dir.path().join("secrets.age");
        let wrong_identity_file = dir.path().join("wrong-identity.txt");
        let secrets = fixture_secrets();
        write_secrets_file(&input, &secrets, true).expect("write input");
        let wrong_identity = seclusor_crypto::identity_to_string(&Identity::generate());
        write_identity_file(&wrong_identity_file, &wrong_identity);

        handle_bundle_encrypt(BundleEncryptArgs {
            input,
            output: bundle.clone(),
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
        })
        .expect("bundle encrypt");

        let err = handle_get(GetArgs {
            file: bundle,
            project: Some("demo".to_string()),
            key: "API_KEY".to_string(),
            reveal: false,
            show_description: false,
            identities: IdentityArgs {
                identity_files: vec![wrong_identity_file],
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("wrong identity should fail");

        let rendered = format!("{err}");
        assert!(!rendered.contains("sk-123"));
    }

    #[test]
    fn handle_list_rejects_invalid_document() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("invalid.json");
        write_raw_json(
            &path,
            r#"{"schema_version":"v9.9.9","projects":[{"project_slug":"demo","credentials":{"API_KEY":{"type":"secret","value":"x"}}}]}"#,
        );

        let err = handle_list(ListArgs {
            file: path,
            project: Some("demo".to_string()),
            verbose: false,
        })
        .expect_err("must reject invalid document");
        assert!(matches!(err, CliError::Core(SeclusorError::Validation(_))));
    }

    #[test]
    fn handle_set_rejects_invalid_document() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("invalid.json");
        write_raw_json(
            &path,
            r#"{"schema_version":"v9.9.9","projects":[{"project_slug":"demo","credentials":{"API_KEY":{"type":"secret","value":"x"}}}]}"#,
        );

        let err = handle_set(SetArgs {
            file: path,
            project: Some("demo".to_string()),
            key: "NEW_KEY".to_string(),
            credential_type: "secret".to_string(),
            value: Some("new-value".to_string()),
            reference: None,
            description: None,
            create_project: false,
        })
        .expect_err("must reject invalid document");
        assert!(matches!(err, CliError::Core(SeclusorError::Validation(_))));
    }

    #[test]
    fn handle_set_redacts_plaintext_strings_in_json_errors() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("invalid.json");
        write_raw_json(
            &path,
            r#"{"schema_version":"v1.0.0","projects":"cfat_secret_token"}"#,
        );

        let err = handle_set(SetArgs {
            file: path,
            project: Some("demo".to_string()),
            key: "NEW_KEY".to_string(),
            credential_type: "secret".to_string(),
            value: Some("new-value".to_string()),
            reference: None,
            description: None,
            create_project: false,
        })
        .expect_err("must reject malformed document");

        let rendered = err.to_string();
        assert!(!rendered.contains("cfat_secret_token"));
        assert!(rendered.contains("string \"<redacted>\""));
    }

    #[test]
    fn handle_set_preserves_replaces_and_clears_description_for_existing_value_credential() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("secrets.json");
        let mut secrets = fixture_secrets();
        secrets.projects[0]
            .credentials
            .get_mut("API_KEY")
            .unwrap()
            .description = Some("existing value description".to_string());
        write_fixture_secrets(&path, &secrets);

        handle_set(SetArgs {
            file: path.clone(),
            project: Some("demo".to_string()),
            key: "API_KEY".to_string(),
            credential_type: "secret".to_string(),
            value: Some("updated-value".to_string()),
            reference: None,
            description: None,
            create_project: false,
        })
        .expect("preserve existing description");
        let loaded = read_secrets_file(&path).unwrap();
        assert_eq!(
            loaded.projects[0].credentials["API_KEY"]
                .description
                .as_deref(),
            Some("existing value description")
        );

        handle_set(SetArgs {
            file: path.clone(),
            project: Some("demo".to_string()),
            key: "API_KEY".to_string(),
            credential_type: "secret".to_string(),
            value: None,
            reference: Some("vault://rotated".to_string()),
            description: Some("  replacement value description  ".to_string()),
            create_project: false,
        })
        .expect("replace description");
        let loaded = read_secrets_file(&path).unwrap();
        assert_eq!(
            loaded.projects[0].credentials["API_KEY"]
                .description
                .as_deref(),
            Some("replacement value description")
        );
        assert_eq!(
            loaded.projects[0].credentials["API_KEY"]
                .reference
                .as_deref(),
            Some("vault://rotated")
        );

        handle_set(SetArgs {
            file: path.clone(),
            project: Some("demo".to_string()),
            key: "API_KEY".to_string(),
            credential_type: "secret".to_string(),
            value: Some("final-value".to_string()),
            reference: None,
            description: Some("".to_string()),
            create_project: false,
        })
        .expect("clear description");
        let loaded = read_secrets_file(&path).unwrap();
        assert!(loaded.projects[0].credentials["API_KEY"]
            .description
            .is_none());
    }

    #[test]
    fn handle_set_preserves_replaces_and_clears_description_for_existing_ref_credential() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("secrets.json");
        let mut secrets = fixture_secrets();
        secrets.projects[0]
            .credentials
            .get_mut("VAULT")
            .unwrap()
            .description = Some("existing ref description".to_string());
        write_fixture_secrets(&path, &secrets);

        handle_set(SetArgs {
            file: path.clone(),
            project: Some("demo".to_string()),
            key: "VAULT".to_string(),
            credential_type: "ref".to_string(),
            value: None,
            reference: Some("vault://preserved".to_string()),
            description: None,
            create_project: false,
        })
        .expect("preserve existing description");
        let loaded = read_secrets_file(&path).unwrap();
        assert_eq!(
            loaded.projects[0].credentials["VAULT"]
                .description
                .as_deref(),
            Some("existing ref description")
        );

        handle_set(SetArgs {
            file: path.clone(),
            project: Some("demo".to_string()),
            key: "VAULT".to_string(),
            credential_type: "secret".to_string(),
            value: Some("plain-secret".to_string()),
            reference: None,
            description: Some("  replacement ref description  ".to_string()),
            create_project: false,
        })
        .expect("replace description");
        let loaded = read_secrets_file(&path).unwrap();
        assert_eq!(
            loaded.projects[0].credentials["VAULT"]
                .description
                .as_deref(),
            Some("replacement ref description")
        );
        assert_eq!(
            loaded.projects[0].credentials["VAULT"].value.as_deref(),
            Some("plain-secret")
        );

        handle_set(SetArgs {
            file: path.clone(),
            project: Some("demo".to_string()),
            key: "VAULT".to_string(),
            credential_type: "ref".to_string(),
            value: None,
            reference: Some("vault://cleared".to_string()),
            description: Some("   ".to_string()),
            create_project: false,
        })
        .expect("clear description");
        let loaded = read_secrets_file(&path).unwrap();
        assert!(loaded.projects[0].credentials["VAULT"]
            .description
            .is_none());
    }

    #[test]
    fn handle_unset_rejects_invalid_document() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("invalid.json");
        write_raw_json(
            &path,
            r#"{"schema_version":"v9.9.9","projects":[{"project_slug":"demo","credentials":{"API_KEY":{"type":"secret","value":"x"}}}]}"#,
        );

        let err = handle_unset(UnsetArgs {
            file: path,
            project: Some("demo".to_string()),
            key: "API_KEY".to_string(),
        })
        .expect_err("must reject invalid document");
        assert!(matches!(err, CliError::Core(SeclusorError::Validation(_))));
    }

    #[test]
    fn handle_unset_leniently_removes_malformed_credential() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("invalid.json");
        write_raw_json(
            &path,
            r#"{"schema_version":"v1.0.0","projects":[{"project_slug":"demo","credentials":{"CLOUDFLARE_API_TOKEN":"cfat_secret_token","API_KEY":{"type":"secret","value":"sk-123"}}}]}"#,
        );

        handle_unset(UnsetArgs {
            file: path.clone(),
            project: Some("demo".to_string()),
            key: "CLOUDFLARE_API_TOKEN".to_string(),
        })
        .expect("lenient unset should succeed");

        let secrets = read_secrets_file(&path).expect("file should be valid after removal");
        assert!(!secrets.projects[0]
            .credentials
            .contains_key("CLOUDFLARE_API_TOKEN"));
        assert!(secrets.projects[0].credentials.contains_key("API_KEY"));
    }

    #[test]
    fn handle_unset_leniently_repairs_validation_failure_credentials() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("invalid.json");
        write_raw_json(
            &path,
            r#"{"schema_version":"v1.0.0","projects":[{"project_slug":"demo","credentials":{"BAD":{"type":"secret"},"API_KEY":{"type":"secret","value":"sk-123"}}}]}"#,
        );

        handle_unset(UnsetArgs {
            file: path.clone(),
            project: Some("demo".to_string()),
            key: "BAD".to_string(),
        })
        .expect("lenient unset should repair validation failure");

        let secrets = read_secrets_file(&path).expect("file should be valid after removal");
        assert!(!secrets.projects[0].credentials.contains_key("BAD"));
        assert!(secrets.projects[0].credentials.contains_key("API_KEY"));
    }

    #[test]
    fn handle_unset_lenient_returns_error_if_file_still_invalid() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("invalid.json");
        write_raw_json(
            &path,
            r#"{"schema_version":"v1.0.0","projects":[{"project_slug":"demo","credentials":{"BAD_ONE":"cfat_one","BAD_TWO":"cfat_two"}}]}"#,
        );

        let err = handle_unset(UnsetArgs {
            file: path.clone(),
            project: Some("demo".to_string()),
            key: "BAD_ONE".to_string(),
        })
        .expect_err("must fail if file remains invalid");

        let rendered = err.to_string();
        assert!(rendered.contains("file was updated, but malformed credentials remain"));
        assert!(!rendered.contains("cfat_one"));
        assert!(!rendered.contains("cfat_two"));
    }

    #[test]
    fn render_export_env_output_honors_format_and_filter() {
        let secrets = fixture_secrets();
        let args = ExportEnvArgs {
            file: PathBuf::from("ignored.json"),
            project: Some("demo".to_string()),
            format: EnvFormatArg::Dotenv,
            prefix: Some("APP_".to_string()),
            emit_ref: false,
            allow: vec!["APP_API_*".to_string()],
            deny: vec![],
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        };

        let output = render_export_env_output(&secrets, Some("demo"), &args).expect("export");
        assert_eq!(output, "APP_API_KEY=sk-123");
    }

    #[test]
    fn handle_export_env_accepts_bundle_with_identity_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let input = dir.path().join("input.json");
        let bundle = dir.path().join("secrets.age");
        let identity_file = dir.path().join("identity.txt");
        let secrets = fixture_secrets();
        write_secrets_file(&input, &secrets, true).expect("write input");
        write_identity_file(&identity_file, TEST_IDENTITY);

        handle_bundle_encrypt(BundleEncryptArgs {
            input,
            output: bundle.clone(),
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
        })
        .expect("bundle encrypt");

        handle_export_env(ExportEnvArgs {
            file: bundle,
            project: Some("demo".to_string()),
            format: EnvFormatArg::Dotenv,
            prefix: None,
            emit_ref: false,
            allow: vec!["APP_API_*".to_string()],
            deny: vec![],
            identities: IdentityArgs {
                identity_files: vec![identity_file],
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect("export env from bundle");
    }

    #[test]
    fn handle_export_env_bundle_requires_identity_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let input = dir.path().join("input.json");
        let bundle = dir.path().join("secrets.age");
        let secrets = fixture_secrets();
        write_secrets_file(&input, &secrets, true).expect("write input");

        handle_bundle_encrypt(BundleEncryptArgs {
            input,
            output: bundle.clone(),
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
        })
        .expect("bundle encrypt");

        let err = handle_export_env(ExportEnvArgs {
            file: bundle,
            project: Some("demo".to_string()),
            format: EnvFormatArg::Dotenv,
            prefix: None,
            emit_ref: false,
            allow: vec!["*".to_string()],
            deny: vec![],
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("bundle runtime must require identities");

        assert!(matches!(
            err,
            CliError::Codec(seclusor_codec::CodecError::BundleIdentityRequired)
        ));
    }

    #[test]
    fn handle_export_env_bundle_wrong_identity_does_not_disclose_secret() {
        let dir = tempfile::tempdir().expect("temp dir");
        let input = dir.path().join("input.json");
        let bundle = dir.path().join("secrets.age");
        let wrong_identity_file = dir.path().join("wrong-identity.txt");
        let secrets = fixture_secrets();
        write_secrets_file(&input, &secrets, true).expect("write input");
        let wrong_identity = seclusor_crypto::identity_to_string(&Identity::generate());
        write_identity_file(&wrong_identity_file, &wrong_identity);

        handle_bundle_encrypt(BundleEncryptArgs {
            input,
            output: bundle.clone(),
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
        })
        .expect("bundle encrypt");

        let err = handle_export_env(ExportEnvArgs {
            file: bundle,
            project: Some("demo".to_string()),
            format: EnvFormatArg::Dotenv,
            prefix: None,
            emit_ref: false,
            allow: vec!["APP_API_KEY".to_string()],
            deny: vec![],
            identities: IdentityArgs {
                identity_files: vec![wrong_identity_file],
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("wrong identity should fail");

        let rendered = format!("{err}");
        assert!(!rendered.contains("sk-123"));
    }

    #[test]
    fn handle_import_env_from_dotenv_filters_and_strips_prefix() {
        let dir = tempfile::tempdir().expect("temp dir");
        let secrets_path = dir.path().join("secrets.json");
        let dotenv_path = dir.path().join("vars.env");

        write_secrets_file(&secrets_path, &SecretsFile::new("demo"), true).expect("write file");
        fs::write(
            &dotenv_path,
            "APP_NEW_TOKEN=abc\nAPP_DB_URL=postgres://x\nIGNORED=1\n",
        )
        .expect("write dotenv");

        handle_import_env(ImportEnvArgs {
            file: secrets_path.clone(),
            project: Some("demo".to_string()),
            credential_type: "secret".to_string(),
            prefix: Some("APP_".to_string()),
            strip_prefix: true,
            dotenv_file: Some(dotenv_path),
            create_project: false,
        })
        .expect("import env");

        let secrets = read_secrets_file(&secrets_path).expect("reload");
        let project = &secrets.projects[0];
        assert!(project.credentials.contains_key("NEW_TOKEN"));
        assert!(project.credentials.contains_key("DB_URL"));
        assert!(!project.credentials.contains_key("IGNORED"));
    }

    #[test]
    fn handle_get_inline_encrypted_with_identity_reveals_value() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (inline, identity_file) = write_inline_encrypted_file(dir.path());

        // Verify redacted mode works (doesn't need to decrypt)
        handle_get(GetArgs {
            file: inline.clone(),
            project: Some("demo".to_string()),
            key: "API_KEY".to_string(),
            reveal: false,
            show_description: false,
            identities: IdentityArgs {
                identity_files: vec![identity_file.clone()],
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect("get redacted should work");

        // Verify reveal mode decrypts (not just prints ciphertext)
        handle_get(GetArgs {
            file: inline,
            project: Some("demo".to_string()),
            key: "API_KEY".to_string(),
            reveal: true,
            show_description: false,
            identities: IdentityArgs {
                identity_files: vec![identity_file],
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect("get reveal should work with identity");
    }

    #[test]
    fn handle_get_inline_encrypted_without_identity_errors_on_reveal() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (inline, _identity_file) = write_inline_encrypted_file(dir.path());

        let err = handle_get(GetArgs {
            file: inline,
            project: Some("demo".to_string()),
            key: "API_KEY".to_string(),
            reveal: true,
            show_description: false,
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("get reveal without identity should fail");

        let msg = err.to_string();
        assert!(msg.contains("inline-encrypted"), "error: {msg}");
    }

    #[test]
    fn handle_export_env_inline_encrypted_with_identity() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (inline, identity_file) = write_inline_encrypted_file(dir.path());

        let result = handle_export_env(ExportEnvArgs {
            file: inline,
            project: Some("demo".to_string()),
            format: EnvFormatArg::Dotenv,
            prefix: None,
            emit_ref: true,
            allow: vec![],
            deny: vec![],
            identities: IdentityArgs {
                identity_files: vec![identity_file],
            },
            passphrase: PassphraseArgs::default(),
        });
        assert!(result.is_ok(), "export-env failed: {}", result.unwrap_err());
    }
}
