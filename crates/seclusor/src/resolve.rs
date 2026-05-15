use std::collections::HashSet;
use std::fs;
use std::path::Path;

use seclusor_crypto::{parse_recipients, Identity};
use seclusor_keyring::{
    discover_recipients, is_passphrase_protected_identity, load_identity_file_auto, KeyringError,
    Recipient, RecipientDiscoveryOptions, DEFAULT_RECIPIENTS_ENV_VAR,
};
use secrecy::{ExposeSecret, SecretString};

use crate::cli::{IdentityArgs, PassphraseArgs, RecipientArgs};
use crate::error::{CliError, CliResult};

pub(crate) fn resolve_recipients(args: &RecipientArgs) -> CliResult<Vec<Recipient>> {
    let mut recipients = Vec::new();

    if !args.recipients.is_empty() {
        recipients.extend(parse_recipients(
            args.recipients.iter().map(String::as_str),
        )?);
    }

    if args.recipient_file.is_some() || args.recipient_env_var.is_some() {
        let discovered = discover_recipients(&RecipientDiscoveryOptions {
            recipient_file: args.recipient_file.clone(),
            recipient_env_var: args.recipient_env_var.clone(),
        })?;
        recipients.extend(discovered);
    } else if recipients.is_empty() && std::env::var(DEFAULT_RECIPIENTS_ENV_VAR).is_ok() {
        let discovered = discover_recipients(&RecipientDiscoveryOptions {
            recipient_file: None,
            recipient_env_var: Some(DEFAULT_RECIPIENTS_ENV_VAR.to_string()),
        })?;
        recipients.extend(discovered);
    }

    if recipients.is_empty() {
        return Err(CliError::Message(
            "no recipients resolved; provide --recipient, --recipient-file, or --recipient-env-var"
                .to_string(),
        ));
    }

    let mut seen = HashSet::new();
    recipients.retain(|recipient| seen.insert(recipient.to_string()));

    Ok(recipients)
}

/// Resolve a passphrase from the configured input channel.
///
/// Returns `None` if no passphrase flags are set. When `confirm` is true
/// (identity generation), the interactive prompt asks twice.
pub(crate) fn resolve_passphrase(
    args: &PassphraseArgs,
    confirm: bool,
) -> CliResult<Option<SecretString>> {
    if args.passphrase {
        let prompt = if confirm {
            "Enter passphrase: "
        } else {
            "Passphrase: "
        };
        eprint!("{prompt}");
        let pp = SecretString::from(rpassword::read_password().map_err(|_| {
            CliError::Message(
                "no interactive terminal available for passphrase prompt. \
                 Provide --passphrase-env, --passphrase-file, or --passphrase-stdin."
                    .to_string(),
            )
        })?);
        if pp.expose_secret().is_empty() {
            return Err(CliError::Message(
                "passphrase must not be empty".to_string(),
            ));
        }
        if confirm {
            eprint!("Confirm passphrase: ");
            let pp2 = SecretString::from(rpassword::read_password().map_err(|_| {
                CliError::Message("failed to read passphrase confirmation".to_string())
            })?);
            if pp.expose_secret() != pp2.expose_secret() {
                return Err(CliError::Message("passphrases do not match".to_string()));
            }
        }
        Ok(Some(pp))
    } else if let Some(var_name) = &args.passphrase_env {
        let pp = SecretString::from(std::env::var(var_name).map_err(|_| {
            CliError::Message(format!(
                "passphrase environment variable {var_name} is not set"
            ))
        })?);
        if pp.expose_secret().is_empty() {
            return Err(CliError::Message(format!(
                "passphrase environment variable {var_name} is set but empty"
            )));
        }
        Ok(Some(pp))
    } else if let Some(path) = &args.passphrase_file {
        seclusor_crypto::assert_secure_permissions(path)?;
        assert_file_owned_by_current_user(path)?;
        // Read file bytes and extract first line directly into SecretString
        let bytes = fs::read(path)?;
        let first_newline = bytes
            .iter()
            .position(|&b| b == b'\n')
            .unwrap_or(bytes.len());
        let line_bytes = &bytes[..first_newline];
        if line_bytes.is_empty() {
            return Err(CliError::Message("passphrase file is empty".to_string()));
        }
        let line_str = std::str::from_utf8(line_bytes)
            .map_err(|_| CliError::Message("passphrase file is not valid UTF-8".to_string()))?;
        Ok(Some(SecretString::from(line_str.to_owned())))
    } else if args.passphrase_stdin {
        // Read directly into SecretString via rpassword's stdin helper
        // to avoid a plain String intermediate
        let pp = SecretString::from({
            let mut buf = String::new();
            std::io::stdin().read_line(&mut buf)?;
            let trimmed = buf.trim_end_matches('\n').trim_end_matches('\r').to_owned();
            buf.clear();
            trimmed
        });
        if pp.expose_secret().is_empty() {
            return Err(CliError::Message(
                "passphrase from stdin is empty".to_string(),
            ));
        }
        Ok(Some(pp))
    } else {
        Ok(None)
    }
}

/// Assert that a file is owned by the current user (Unix only).
fn assert_file_owned_by_current_user(path: &Path) -> CliResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = fs::metadata(path)?;
        let file_uid = meta.uid();
        let my_uid = unsafe { libc::getuid() };
        if file_uid != my_uid {
            return Err(CliError::Message(format!(
                "passphrase file must be owned by the current user (file uid: {file_uid}, \
                 current uid: {my_uid})"
            )));
        }
    }

    #[cfg(not(unix))]
    {
        let _ = path;
    }

    Ok(())
}

pub(crate) fn resolve_identities(
    args: &IdentityArgs,
    passphrase_args: &PassphraseArgs,
    required: bool,
) -> CliResult<Vec<Identity>> {
    // Per SC-008 settled decision 1: scan all identity files first,
    // error if more than one is passphrase-protected.
    let mut protected_count = 0usize;
    for path in &args.identity_files {
        if is_passphrase_protected_identity(path)? {
            protected_count += 1;
        }
    }
    if protected_count > 1 {
        return Err(CliError::Keyring(KeyringError::MultipleProtectedIdentities));
    }

    // Resolve passphrase only if needed (at least one protected identity)
    let passphrase = if protected_count > 0 {
        let mut pp = resolve_passphrase(passphrase_args, false)?;
        // Auto-prompt if no explicit passphrase channel and terminal available
        if pp.is_none() {
            eprint!("Passphrase: ");
            match rpassword::read_password().map(SecretString::from) {
                Ok(val) if !val.expose_secret().is_empty() => {
                    pp = Some(val);
                }
                Ok(_) => {
                    return Err(CliError::Message(
                        "passphrase must not be empty".to_string(),
                    ));
                }
                Err(_) => {
                    return Err(CliError::Message(
                        "identity file is passphrase-protected but no interactive \
                         terminal is available. Provide --passphrase-env, \
                         --passphrase-file, or --passphrase-stdin."
                            .to_string(),
                    ));
                }
            }
        }
        pp
    } else {
        None
    };

    let mut identities = Vec::new();
    for path in &args.identity_files {
        identities.extend(load_identity_file_auto(path, passphrase.as_ref())?);
    }

    if required && identities.is_empty() {
        return Err(CliError::Message(
            "no identities resolved; provide --identity-file".to_string(),
        ));
    }

    Ok(identities)
}
