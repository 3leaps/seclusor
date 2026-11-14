use std::io::{self, Read, Write};
use std::path::Path;

use seclusor_codec::{
    decrypt_inline, encrypt_inline, ensure_no_plaintext_credential_values,
    project_plaintext_at_rest,
};
use seclusor_core::constants::MAX_SECRETS_DOC_BYTES;
use seclusor_core::validate::validate_strict;
use seclusor_core::{SeclusorError, SecretsFile};
use zeroize::Zeroizing;

use crate::cli::{InlineDecryptArgs, InlineEncryptArgs, InlineSubcommand};
use crate::error::{CliError, CliResult};
use crate::io::{read_secrets_file, secrets_from_bytes, write_secrets_file};
use crate::resolve::{resolve_identities, resolve_recipients};

pub(crate) fn handle_inline_command(command: InlineSubcommand) -> CliResult<()> {
    match command {
        InlineSubcommand::Encrypt(args) => handle_inline_encrypt(args),
        InlineSubcommand::Decrypt(args) => handle_inline_decrypt(args),
    }
}

pub(crate) fn handle_inline_encrypt(args: InlineEncryptArgs) -> CliResult<()> {
    // Resolve recipients before consuming stdin or reading input files so
    // invalid/missing recipient options fail fast without blocking on a pipe.
    let recipients = resolve_recipients(&args.recipients)?;
    let secrets = if args.input == Path::new("-") {
        read_secrets_stdin_bounded()?
    } else {
        read_secrets_file(&args.input)?
    };
    let encrypted = encrypt_inline(&secrets, &recipients)?;
    validate_strict(&encrypted)?;
    ensure_no_plaintext_credential_values(&encrypted)?;

    if args.output == Path::new("-") {
        let mut out = serde_json::to_vec_pretty(&encrypted)?;
        if !out.ends_with(b"\n") {
            out.push(b'\n');
        }
        if out.len() > MAX_SECRETS_DOC_BYTES {
            return Err(CliError::Core(SeclusorError::DocumentTooLarge {
                actual: out.len(),
                max: MAX_SECRETS_DOC_BYTES,
            }));
        }
        let mut stdout = io::stdout().lock();
        stdout.write_all(&out)?;
        stdout.flush()?;
    } else {
        write_secrets_file(&args.output, &encrypted, false)?;
        println!("{}", args.output.display());
    }
    Ok(())
}

fn read_secrets_stdin_bounded() -> CliResult<SecretsFile> {
    let mut reader = io::stdin().lock();
    read_secrets_reader_bounded(&mut reader)
}

fn read_secrets_reader_bounded<R: Read>(reader: &mut R) -> CliResult<SecretsFile> {
    let mut buf = Zeroizing::new(Vec::new());
    reader
        .take((MAX_SECRETS_DOC_BYTES as u64) + 1)
        .read_to_end(&mut buf)?;
    if buf.len() > MAX_SECRETS_DOC_BYTES {
        return Err(CliError::Core(SeclusorError::DocumentTooLarge {
            actual: buf.len(),
            max: MAX_SECRETS_DOC_BYTES,
        }));
    }
    secrets_from_bytes(&buf)
}

pub(crate) fn handle_inline_decrypt(args: InlineDecryptArgs) -> CliResult<()> {
    let secrets = read_secrets_file(&args.input)?;
    let identities = resolve_identities(&args.identities, &args.passphrase, false)?;
    let decrypted = decrypt_inline(&secrets, &identities)?;
    // Persistence boundary: strip recipients so plaintext JSON is at-rest valid.
    let at_rest = project_plaintext_at_rest(&decrypted)?;
    write_secrets_file(&args.output, &at_rest, false)?;
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
                recipient_files: vec![],
                recipient_env_var: None,
            },
        })
        .expect("inline encrypt");

        handle_inline_decrypt(InlineDecryptArgs {
            input: inline,
            output: output.clone(),
            identities: IdentityArgs {
                identity_files: vec![identity_file],
                identity_public_key: None,
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect("inline decrypt");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let loaded = read_secrets_file(&output).expect("read output");
        // CLI decrypt projects to JSON-at-rest: no recipients, plaintext values.
        assert_eq!(loaded.projects, secrets.projects);
        assert!(loaded.recipients.is_none());
        assert_eq!(
            loaded.projects[0].credentials["API_KEY"].value.as_deref(),
            Some("plain-value")
        );
    }

    #[test]
    fn inline_decrypt_cli_omits_recipients_on_disk() {
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
            input,
            output: inline.clone(),
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_files: vec![],
                recipient_env_var: None,
            },
        })
        .expect("encrypt");
        let encrypted = read_secrets_file(&inline).expect("read inline");
        assert!(encrypted.recipients.is_some());

        // Public API working copy still has recipients.
        let working =
            seclusor_codec::decrypt_inline(&encrypted, std::slice::from_ref(&fixture_identity()))
                .expect("decrypt working");
        assert!(working.recipients.is_some());

        handle_inline_decrypt(InlineDecryptArgs {
            input: inline,
            output: output.clone(),
            identities: IdentityArgs {
                identity_files: vec![identity_file],
                identity_public_key: None,
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect("cli decrypt");
        let on_disk = read_secrets_file(&output).expect("read disk");
        assert!(on_disk.recipients.is_none());
        seclusor_core::validate::validate_strict(&on_disk).expect("at-rest valid");
    }
}
