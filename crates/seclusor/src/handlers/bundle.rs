use seclusor_codec::{decrypt_bundle_from_file, encrypt_bundle_to_file};

use crate::cli::{BundleDecryptArgs, BundleEncryptArgs, BundleSubcommand};
use crate::error::CliResult;
use crate::io::{read_secrets_file, write_secrets_file};
use crate::resolve::{resolve_identities, resolve_recipients};

pub(crate) fn handle_bundle_command(command: BundleSubcommand) -> CliResult<()> {
    match command {
        BundleSubcommand::Encrypt(args) => handle_bundle_encrypt(args),
        BundleSubcommand::Decrypt(args) => handle_bundle_decrypt(args),
    }
}

pub(crate) fn handle_bundle_encrypt(args: BundleEncryptArgs) -> CliResult<()> {
    let secrets = read_secrets_file(&args.input)?;
    let recipients = resolve_recipients(&args.recipients)?;
    encrypt_bundle_to_file(&secrets, &recipients, &args.output)?;
    println!("{}", args.output.display());
    Ok(())
}

pub(crate) fn handle_bundle_decrypt(args: BundleDecryptArgs) -> CliResult<()> {
    let identities = resolve_identities(&args.identities, &args.passphrase, true)?;
    let secrets = decrypt_bundle_from_file(&args.input, &identities)?;
    write_secrets_file(&args.output, &secrets, false)?;
    println!("{}", args.output.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::cli::*;
    use crate::error::CliError;
    use crate::io::{read_secrets_file, write_secrets_file};
    use crate::test_support::*;

    #[test]
    fn handle_bundle_encrypt_bare_string_credential_has_helpful_error() {
        let dir = tempfile::tempdir().expect("temp dir");
        let input = dir.path().join("invalid.json");
        let output = dir.path().join("secrets.age");
        write_raw_json(
            &input,
            r#"{"schema_version":"v1.0.0","projects":[{"project_slug":"demo","credentials":{"CLOUDFLARE_API_TOKEN":"cfat_secret_token"}}]}"#,
        );

        let err = handle_bundle_encrypt(BundleEncryptArgs {
            input,
            output,
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
        })
        .expect_err("must reject malformed credential");

        let rendered = err.to_string();
        assert!(!rendered.contains("cfat_secret_token"));
        assert!(rendered.contains(r#"credential "CLOUDFLARE_API_TOKEN" must be an object"#));
        assert!(rendered
            .contains("Use: seclusor secrets set --key CLOUDFLARE_API_TOKEN --value <value>"));
    }

    #[test]
    fn bundle_encrypt_then_decrypt_roundtrip() {
        let dir = tempfile::tempdir().expect("temp dir");
        let input = dir.path().join("input.json");
        let bundle = dir.path().join("secrets.age");
        let output = dir.path().join("output.json");
        let identity_file = dir.path().join("identity.txt");

        let secrets = fixture_secrets();
        write_secrets_file(&input, &secrets, true).expect("write input");
        write_identity_file(&identity_file, TEST_IDENTITY);

        handle_bundle_encrypt(BundleEncryptArgs {
            input: input.clone(),
            output: bundle.clone(),
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
        })
        .expect("bundle encrypt");

        handle_bundle_decrypt(BundleDecryptArgs {
            input: bundle,
            output: output.clone(),
            identities: IdentityArgs {
                identity_files: vec![identity_file],
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect("bundle decrypt");

        let loaded = read_secrets_file(&output).expect("read output");
        assert_eq!(loaded, secrets);
    }

    #[test]
    fn bundle_decrypt_requires_identity_file() {
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

        let err = handle_bundle_decrypt(BundleDecryptArgs {
            input: bundle,
            output: dir.path().join("output.json"),
            identities: IdentityArgs {
                identity_files: vec![],
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("missing identity-file should fail");

        assert!(matches!(err, CliError::Message(_)));
        assert!(format!("{err}").contains("--identity-file"));
    }
}
