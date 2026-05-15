use seclusor_core::env::{export_env, EnvExportOptions, EnvFilter, EnvVar};
use seclusor_core::SecretsFile;

use crate::error::CliResult;

pub(crate) fn resolve_export_env_vars(
    secrets: &SecretsFile,
    project_slug: Option<&str>,
    prefix: Option<&str>,
    emit_ref: bool,
    allow: &[String],
    deny: &[String],
) -> CliResult<Vec<EnvVar>> {
    let filter = EnvFilter {
        allow: if allow.is_empty() {
            vec!["*".to_string()]
        } else {
            allow.to_vec()
        },
        deny: deny.to_vec(),
    };
    let opts = EnvExportOptions {
        prefix: prefix.map(ToOwned::to_owned),
        emit_ref,
        filter,
    };
    Ok(export_env(secrets, project_slug, &opts)?)
}
