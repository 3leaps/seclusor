pub(crate) mod assets;
pub(crate) mod blob;
pub(crate) mod bundle;
pub(crate) mod convert;
pub(crate) mod docs;
pub(crate) mod encrypted_write;
pub(crate) mod inline;
pub(crate) mod keys;
#[cfg(test)]
mod packaging_matrix;
pub(crate) mod rekey;
pub(crate) mod run;
pub(crate) mod secrets;

use crate::cli::{AssetsSubcommand, SecretsSubcommand};
use crate::error::{CliError, CliResult};

fn reject_recipient_mismatch_override(allow_recipient_mismatch: bool) -> CliResult<()> {
    if allow_recipient_mismatch {
        return Err(CliError::Message(
            "--allow-recipient-mismatch is only valid for `set`, `import-env`, \
             `rekey`, and `bundle encrypt`"
                .to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn handle_secrets_command(
    command: SecretsSubcommand,
    allow_recipient_mismatch: bool,
) -> CliResult<()> {
    match command {
        SecretsSubcommand::Init(args) => {
            reject_recipient_mismatch_override(allow_recipient_mismatch)?;
            secrets::handle_init(args)
        }
        SecretsSubcommand::Set(args) => {
            secrets::handle_set_with_policy(args, allow_recipient_mismatch)
        }
        SecretsSubcommand::Get(args) => {
            reject_recipient_mismatch_override(allow_recipient_mismatch)?;
            secrets::handle_get(args)
        }
        SecretsSubcommand::List(args) => {
            reject_recipient_mismatch_override(allow_recipient_mismatch)?;
            secrets::handle_list(args)
        }
        SecretsSubcommand::Unset(args) => {
            reject_recipient_mismatch_override(allow_recipient_mismatch)?;
            secrets::handle_unset(args)
        }
        SecretsSubcommand::Validate(args) => {
            reject_recipient_mismatch_override(allow_recipient_mismatch)?;
            secrets::handle_validate(args)
        }
        SecretsSubcommand::ExportEnv(args) => {
            reject_recipient_mismatch_override(allow_recipient_mismatch)?;
            secrets::handle_export_env(args)
        }
        SecretsSubcommand::ImportEnv(args) => {
            secrets::handle_import_env_with_policy(args, allow_recipient_mismatch)
        }
        SecretsSubcommand::Rekey(args) => {
            rekey::handle_rekey_with_policy(args, allow_recipient_mismatch)
        }
        SecretsSubcommand::Run(args) => {
            reject_recipient_mismatch_override(allow_recipient_mismatch)?;
            run::handle_run(args)
        }
        SecretsSubcommand::Bundle(args) => {
            bundle::handle_bundle_command_with_policy(args.command, allow_recipient_mismatch)
        }
        SecretsSubcommand::Inline(args) => {
            reject_recipient_mismatch_override(allow_recipient_mismatch)?;
            inline::handle_inline_command(args.command)
        }
        SecretsSubcommand::Blob(args) => {
            reject_recipient_mismatch_override(allow_recipient_mismatch)?;
            blob::handle_blob_command(args.command)
        }
        SecretsSubcommand::Convert(args) => {
            reject_recipient_mismatch_override(allow_recipient_mismatch)?;
            convert::handle_convert(args)
        }
    }
}

pub(crate) fn handle_assets_command(command: AssetsSubcommand) -> CliResult<()> {
    match command {
        AssetsSubcommand::Sign(args) => assets::handle_asset_sign(args),
        AssetsSubcommand::Verify(args) => assets::handle_asset_verify(args),
    }
}
