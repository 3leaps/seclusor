use std::process::Command;

use crate::child_env::{BasePolicy, ChildEnv, ExcludedNames};
use crate::cli::RunArgs;
use crate::env_support::resolve_export_env_vars;
use crate::error::{CliError, CliResult};
use crate::io::read_runtime_secrets_file;
use crate::resolve::resolve_identities_with_passphrase;

pub(crate) fn handle_run(args: RunArgs) -> CliResult<()> {
    // Resolve once; retain passphrase only until the child env is verified.
    let (identities, passphrase) =
        resolve_identities_with_passphrase(&args.identities, &args.passphrase, false)?;
    let secrets = read_runtime_secrets_file(&args.file, &identities)?;
    let env_vars = resolve_export_env_vars(
        &secrets,
        args.project.as_deref(),
        args.prefix.as_deref(),
        args.emit_ref,
        &args.allow,
        &args.deny,
    )?;

    // Exclusion names come only from the explicit `--passphrase-env` channel.
    let excluded = match &args.passphrase.passphrase_env {
        Some(name) => ExcludedNames::from_names([name.clone()]),
        None => ExcludedNames::none(),
    };
    let child_env = ChildEnv::build(
        BasePolicy::InheritAmbient,
        &env_vars,
        &excluded,
        passphrase.as_ref(),
    )
    .map_err(|e| CliError::Message(e.to_string()))?;
    // Drop the resolved passphrase after env verification. Identities and
    // injected credential values necessarily remain until spawn.
    drop(passphrase);

    // child-env-callsite: run-spawn
    let mut command = Command::new(&args.command[0]);
    command.args(&args.command[1..]);
    // Apply freezes the verified snapshot (env_clear + explicit sets); does not
    // re-inherit a live ambient that could change after build.
    child_env.apply(&mut command);

    let status = command.status()?;
    if !status.success() {
        let code = status.code().unwrap_or(1);
        return Err(CliError::CommandFailed(code));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use seclusor_core::{Credential, SecretsFile};
    use seclusor_crypto::Identity;

    use crate::cli::*;
    use crate::error::CliError;
    use crate::handlers::bundle::handle_bundle_encrypt;
    use crate::io::write_secrets_file;
    use crate::test_support::*;

    #[test]
    fn handle_run_propagates_nonzero_exit_code() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("secrets.json");
        let mut secrets = SecretsFile::new("demo");
        secrets.projects[0].credentials.insert(
            "API_KEY".to_string(),
            Credential::with_value("secret", "plain-value"),
        );
        write_secrets_file(&path, &secrets, true).expect("write file");

        #[cfg(unix)]
        let command = vec!["sh".to_string(), "-c".to_string(), "exit 42".to_string()];
        #[cfg(windows)]
        let command = vec!["cmd".to_string(), "/C".to_string(), "exit 42".to_string()];

        let err = handle_run(RunArgs {
            file: path,
            project: Some("demo".to_string()),
            prefix: None,
            emit_ref: false,
            allow: vec![],
            deny: vec![],
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
            command,
        })
        .expect_err("run should fail with command exit status");
        assert!(matches!(err, CliError::CommandFailed(42)));
    }

    #[test]
    fn handle_run_accepts_bundle_with_identity_file() {
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

        #[cfg(unix)]
        let command = vec![
            "sh".to_string(),
            "-c".to_string(),
            r#"test "${APP_API_KEY}" = "sk-123""#.to_string(),
        ];
        #[cfg(windows)]
        let command = vec![
            "cmd".to_string(),
            "/C".to_string(),
            r#"if "%APP_API_KEY%"=="sk-123" (exit 0) else (exit 33)"#.to_string(),
        ];

        handle_run(RunArgs {
            file: bundle,
            project: Some("demo".to_string()),
            prefix: None,
            emit_ref: false,
            allow: vec!["APP_API_KEY".to_string()],
            deny: vec![],
            identities: IdentityArgs {
                identity_files: vec![identity_file],
                identity_public_key: None,
            },
            passphrase: PassphraseArgs::default(),
            command,
        })
        .expect("run from bundle");
    }

    #[test]
    fn handle_run_bundle_wrong_identity_does_not_disclose_secret() {
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

        #[cfg(unix)]
        let command = vec!["sh".to_string(), "-c".to_string(), "exit 0".to_string()];
        #[cfg(windows)]
        let command = vec!["cmd".to_string(), "/C".to_string(), "exit 0".to_string()];

        let err = handle_run(RunArgs {
            file: bundle,
            project: Some("demo".to_string()),
            prefix: None,
            emit_ref: false,
            allow: vec!["APP_API_KEY".to_string()],
            deny: vec![],
            identities: IdentityArgs {
                identity_files: vec![wrong_identity_file],
                identity_public_key: None,
            },
            passphrase: PassphraseArgs::default(),
            command,
        })
        .expect_err("wrong identity should fail");

        let rendered = format!("{err}");
        assert!(!rendered.contains("sk-123"));
    }

    #[test]
    fn handle_run_inline_encrypted_with_identity() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (inline, identity_file) = write_inline_encrypted_file(dir.path());

        #[cfg(unix)]
        let command = vec!["sh".to_string(), "-c".to_string(), "exit 0".to_string()];
        #[cfg(windows)]
        let command = vec!["cmd".to_string(), "/C".to_string(), "exit 0".to_string()];

        let result = handle_run(RunArgs {
            file: inline,
            project: Some("demo".to_string()),
            prefix: None,
            emit_ref: true,
            allow: vec![],
            deny: vec![],
            identities: IdentityArgs {
                identity_files: vec![identity_file],
                identity_public_key: None,
            },
            passphrase: PassphraseArgs::default(),
            command,
        });
        assert!(result.is_ok(), "run failed: {}", result.unwrap_err());
    }

    #[test]
    fn handle_run_inline_encrypted_without_identity_errors() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (inline, _identity_file) = write_inline_encrypted_file(dir.path());

        #[cfg(unix)]
        let command = vec!["sh".to_string(), "-c".to_string(), "exit 0".to_string()];
        #[cfg(windows)]
        let command = vec!["cmd".to_string(), "/C".to_string(), "exit 0".to_string()];

        let err = handle_run(RunArgs {
            file: inline,
            project: Some("demo".to_string()),
            prefix: None,
            emit_ref: false,
            allow: vec![],
            deny: vec![],
            identities: IdentityArgs::default(),
            passphrase: PassphraseArgs::default(),
            command,
        })
        .expect_err("should fail without identity");

        let msg = err.to_string();
        assert!(msg.contains("inline-encrypted"));
    }
}
