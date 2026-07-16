use std::fs;

use seclusor_codec::{
    convert_inline_to_bundle, decrypt_bundle_from_file, encrypt_inline, StorageCodec,
};

use crate::cli::ConvertArgs;
use crate::error::{CliError, CliResult};
use crate::io::{read_secrets_file, write_secrets_file};
use crate::resolve::{resolve_identities, resolve_recipients};

pub(crate) fn handle_convert(args: ConvertArgs) -> CliResult<()> {
    let from: StorageCodec = args.from.into();
    let to: StorageCodec = args.to.into();
    if from == to {
        return Err(CliError::Message(
            "convert requires distinct --from and --to codecs".to_string(),
        ));
    }

    let recipients = resolve_recipients(&args.recipients)?;
    let identities = resolve_identities(&args.identities, &args.passphrase, true)?;

    match (from, to) {
        (StorageCodec::Bundle, StorageCodec::Inline) => {
            let decrypted = decrypt_bundle_from_file(&args.input, &identities)?;
            let inline = encrypt_inline(&decrypted, &recipients)?;
            write_secrets_file(&args.output, &inline, false)?;
        }
        (StorageCodec::Inline, StorageCodec::Bundle) => {
            let inline = read_secrets_file(&args.input)?;
            let bundle = convert_inline_to_bundle(&inline, &identities, &recipients)?;
            fs::write(&args.output, bundle)?;
        }
        _ => {
            return Err(CliError::Message(
                "unsupported conversion codec combination".to_string(),
            ));
        }
    }

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
    fn convert_inline_to_bundle_then_back_to_inline() {
        let dir = tempfile::tempdir().expect("temp dir");
        let source = dir.path().join("source-inline.json");
        let bundle = dir.path().join("bundle.age");
        let reconverted = dir.path().join("reconverted-inline.json");
        let identity_file = dir.path().join("identity.txt");

        let mut secrets = SecretsFile::new("demo");
        secrets.projects[0].credentials.insert(
            "API_KEY".to_string(),
            Credential::with_value("secret", "plain-value"),
        );
        let inline = encrypt_inline(&secrets, &[fixture_identity().to_public()]).expect("encrypt");
        write_secrets_file(&source, &inline, true).expect("write source");
        write_identity_file(&identity_file, TEST_IDENTITY);

        handle_convert(ConvertArgs {
            input: source,
            output: bundle.clone(),
            from: StorageCodecArg::Inline,
            to: StorageCodecArg::Bundle,
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
            identities: IdentityArgs {
                identity_files: vec![identity_file.clone()],
                identity_public_key: None,
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect("inline->bundle");

        handle_convert(ConvertArgs {
            input: bundle,
            output: reconverted.clone(),
            from: StorageCodecArg::Bundle,
            to: StorageCodecArg::Inline,
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
            identities: IdentityArgs {
                identity_files: vec![identity_file],
                identity_public_key: None,
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect("bundle->inline");

        let roundtrip = read_secrets_file(&reconverted).expect("read reconverted");
        assert!(roundtrip.has_inline_ciphertext());
        assert_eq!(
            roundtrip.recipients.as_deref(),
            Some(std::slice::from_ref(&fixture_recipient_string())),
            "conversion rewrites recipients metadata to the target set"
        );
    }

    #[test]
    fn convert_recipients_bearing_bundle_to_inline_via_cli() {
        let dir = tempfile::tempdir().expect("temp dir");
        let bundle = dir.path().join("secrets.age");
        let inline_out = dir.path().join("out.json");
        let identity_file = dir.path().join("identity.txt");
        write_identity_file(&identity_file, TEST_IDENTITY);

        let mut secrets = SecretsFile::new("demo");
        secrets.projects[0].credentials.insert(
            "API_KEY".to_string(),
            Credential::with_value("secret", "plain-value"),
        );
        secrets
            .establish_recipients(vec![fixture_recipient_string()])
            .expect("establish");
        let ct = seclusor_codec::encrypt_bundle(
            &secrets,
            std::slice::from_ref(&fixture_identity().to_public()),
        )
        .expect("encrypt bundle");
        fs::write(&bundle, ct).expect("write bundle");

        handle_convert(ConvertArgs {
            input: bundle,
            output: inline_out.clone(),
            from: StorageCodecArg::Bundle,
            to: StorageCodecArg::Inline,
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
            identities: IdentityArgs {
                identity_files: vec![identity_file],
                identity_public_key: None,
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect("bundle->inline with recipients metadata");

        let out = read_secrets_file(&inline_out).expect("read");
        assert!(out.has_inline_ciphertext());
        assert_eq!(
            out.recipients.as_deref(),
            Some(std::slice::from_ref(&fixture_recipient_string()))
        );
    }
}
