use seclusor_keyring::{generate_identity_file, generate_identity_file_with_passphrase};

use crate::cli::{AgeSubcommand, IdentityGenerateArgs, IdentitySubcommand, KeysSubcommand};
use crate::error::CliResult;
use crate::resolve::resolve_passphrase;

pub(crate) fn handle_keys_command(command: KeysSubcommand) -> CliResult<()> {
    match command {
        KeysSubcommand::Age(age) => match age.command {
            AgeSubcommand::Identity(identity) => match identity.command {
                IdentitySubcommand::Generate(args) => handle_identity_generate(args),
            },
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
}
