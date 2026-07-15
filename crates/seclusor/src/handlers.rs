pub(crate) mod assets;
pub(crate) mod blob;
pub(crate) mod bundle;
pub(crate) mod convert;
pub(crate) mod docs;
pub(crate) mod encrypted_write;
pub(crate) mod inline;
pub(crate) mod keys;
pub(crate) mod rekey;
pub(crate) mod run;
pub(crate) mod secrets;

use crate::cli::{AssetsSubcommand, SecretsSubcommand};
use crate::error::CliResult;

pub(crate) fn handle_secrets_command(command: SecretsSubcommand) -> CliResult<()> {
    match command {
        SecretsSubcommand::Init(args) => secrets::handle_init(args),
        SecretsSubcommand::Set(args) => secrets::handle_set(args),
        SecretsSubcommand::Get(args) => secrets::handle_get(args),
        SecretsSubcommand::List(args) => secrets::handle_list(args),
        SecretsSubcommand::Unset(args) => secrets::handle_unset(args),
        SecretsSubcommand::Validate(args) => secrets::handle_validate(args),
        SecretsSubcommand::ExportEnv(args) => secrets::handle_export_env(args),
        SecretsSubcommand::ImportEnv(args) => secrets::handle_import_env(args),
        SecretsSubcommand::Rekey(args) => rekey::handle_rekey(args),
        SecretsSubcommand::Run(args) => run::handle_run(args),
        SecretsSubcommand::Bundle(args) => bundle::handle_bundle_command(args.command),
        SecretsSubcommand::Inline(args) => inline::handle_inline_command(args.command),
        SecretsSubcommand::Blob(args) => blob::handle_blob_command(args.command),
        SecretsSubcommand::Convert(args) => convert::handle_convert(args),
    }
}

pub(crate) fn handle_assets_command(command: AssetsSubcommand) -> CliResult<()> {
    match command {
        AssetsSubcommand::Sign(args) => assets::handle_asset_sign(args),
        AssetsSubcommand::Verify(args) => assets::handle_asset_verify(args),
    }
}
