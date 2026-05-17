use seclusor_keyring::{generate_identity_file, generate_identity_file_with_passphrase};
use seclusor_sign::{encode_base64url, generate_signing_key_file};

use crate::cli::{
    AgeSubcommand, IdentityGenerateArgs, IdentitySubcommand, KeysSubcommand, SigningGenerateArgs,
    SigningSubcommand,
};
use crate::error::CliResult;
use crate::resolve::{resolve_passphrase, resolve_recipients};

pub(crate) fn handle_keys_command(command: KeysSubcommand) -> CliResult<()> {
    match command {
        KeysSubcommand::Age(age) => match age.command {
            AgeSubcommand::Identity(identity) => match identity.command {
                IdentitySubcommand::Generate(args) => handle_identity_generate(args),
            },
        },
        KeysSubcommand::Signing(signing) => match signing.command {
            SigningSubcommand::Generate(args) => handle_signing_generate(args),
        },
    }
}

pub(crate) fn handle_identity_generate(args: IdentityGenerateArgs) -> CliResult<()> {
    let passphrase = resolve_passphrase(&args.passphrase, true)?;
    let generated = match passphrase {
        Some(pp) => generate_identity_file_with_passphrase(&args.output, &pp)?,
        None => generate_identity_file(&args.output)?,
    };
    println!("{}", generated.recipient);
    Ok(())
}

pub(crate) fn handle_signing_generate(args: SigningGenerateArgs) -> CliResult<()> {
    let recipients = resolve_recipients(&args.recipients)?;
    let generated = generate_signing_key_file(&args.output, &recipients)?;
    println!("public_key={}", encode_base64url(&generated.public_key));
    println!(
        "key_fingerprint={}",
        encode_base64url(&generated.key_fingerprint)
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    use crate::cli::*;

    #[test]
    fn identity_generate_writes_identity_file_outside_repo_root() {
        let dir = tempfile::tempdir().expect("temp dir");
        let output = dir.path().join("identity.txt");

        handle_identity_generate(IdentityGenerateArgs {
            output: output.clone(),
            passphrase: PassphraseArgs::default(),
        })
        .expect("generate identity");

        assert!(output.exists());
        let contents = fs::read_to_string(output).expect("read identity file");
        assert!(contents.contains("AGE-SECRET-KEY-"));
        assert!(contents.contains("# public key:"));
    }

    #[test]
    fn signing_generate_writes_protected_key_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let output = dir.path().join("signing.key.age");
        let identity = seclusor_crypto::Identity::generate();
        let recipient = identity.to_public();

        handle_signing_generate(SigningGenerateArgs {
            output: output.clone(),
            recipients: RecipientArgs {
                recipients: vec![recipient.to_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
        })
        .expect("generate signing key");

        assert!(output.exists());
        let key = seclusor_sign::load_signing_key_file(&output, &[identity]).expect("load key");
        let public_key = seclusor_crypto::signing_public_key_to_bytes(
            &seclusor_crypto::signing_public_key(&key),
        );
        assert_eq!(public_key.len(), seclusor_crypto::SIGNING_PUBLIC_KEY_LEN);
    }
}
