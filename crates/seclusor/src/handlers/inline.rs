use seclusor_codec::{decrypt_inline, encrypt_inline};

use crate::cli::{InlineDecryptArgs, InlineEncryptArgs, InlineSubcommand};
use crate::error::CliResult;
use crate::io::{read_secrets_file, write_secrets_file};
use crate::resolve::{resolve_identities, resolve_recipients};

pub(crate) fn handle_inline_command(command: InlineSubcommand) -> CliResult<()> {
    match command {
        InlineSubcommand::Encrypt(args) => handle_inline_encrypt(args),
        InlineSubcommand::Decrypt(args) => handle_inline_decrypt(args),
    }
}

pub(crate) fn handle_inline_encrypt(args: InlineEncryptArgs) -> CliResult<()> {
    let secrets = read_secrets_file(&args.input)?;
    let recipients = resolve_recipients(&args.recipients)?;
    let encrypted = encrypt_inline(&secrets, &recipients)?;
    write_secrets_file(&args.output, &encrypted, false)?;
    println!("{}", args.output.display());
    Ok(())
}

pub(crate) fn handle_inline_decrypt(args: InlineDecryptArgs) -> CliResult<()> {
    let secrets = read_secrets_file(&args.input)?;
    let identities = resolve_identities(&args.identities, &args.passphrase, false)?;
    let decrypted = decrypt_inline(&secrets, &identities)?;
    write_secrets_file(&args.output, &decrypted, false)?;
    println!("{}", args.output.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use seclusor_core::{Credential, SecretsFile};

    use crate::cli::*;
    use crate::io::{read_secrets_file, write_secrets_file};
    use crate::test_support::*;

    #[test]
    fn inline_encrypt_then_decrypt_roundtrip() {
        let dir = tempfile::tempdir().expect("temp dir");
        let input = dir.path().join("input.json");
        let inline = dir.path().join("inline.json");
        let output = dir.path().join("output.json");
        let identity_file = dir.path().join("identity.txt");

        let mut secrets = SecretsFile::new("demo");
        secrets.projects[0].credentials.insert(
            "API_KEY".to_string(),
            Credential::with_value("secret", "plain-value"),
        );
        write_secrets_file(&input, &secrets, true).expect("write input");
        write_identity_file(&identity_file, TEST_IDENTITY);

        handle_inline_encrypt(InlineEncryptArgs {
            input: input.clone(),
            output: inline.clone(),
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
        })
        .expect("inline encrypt");

        handle_inline_decrypt(InlineDecryptArgs {
            input: inline,
            output: output.clone(),
            identities: IdentityArgs {
                identity_files: vec![identity_file],
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect("inline decrypt");

        let loaded = read_secrets_file(&output).expect("read output");
        assert_eq!(loaded, secrets);
    }
}
