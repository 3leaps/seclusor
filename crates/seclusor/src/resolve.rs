use std::collections::HashSet;
use std::fs;
use std::path::Path;

use seclusor_crypto::{assert_identity_file_access, parse_recipients, Identity};
use seclusor_keyring::{
    discover_recipients, find_identity_path_by_public_key, is_passphrase_protected_identity,
    load_identity_by_public_key, load_identity_file_auto, KeyringError, Recipient,
    RecipientDiscoveryOptions, DEFAULT_RECIPIENTS_ENV_VAR,
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

/// True when `rpassword` can open a controlling console.
///
/// rpassword 7.x does **not** read stdin: it opens `/dev/tty` (Unix) or
/// `CONIN$` (Windows). Checking `stdin().is_terminal()` is therefore wrong —
/// it refuses valid interactive use with redirected stdin (pipeline input)
/// while a controlling TTY remains available for the passphrase prompt.
///
/// Preflight here mirrors the device rpassword opens so we fail closed before
/// calling `read_password`, which can block indefinitely on some Windows
/// noninteractive runners instead of returning an error.
fn interactive_console_available() -> bool {
    #[cfg(unix)]
    {
        use std::io::IsTerminal;
        match std::fs::File::open("/dev/tty") {
            Ok(f) => f.is_terminal(),
            Err(_) => false,
        }
    }
    #[cfg(windows)]
    {
        use std::io::IsTerminal;
        // Match rpassword's CreateFileA("CONIN$") + GetConsoleMode path.
        // IsTerminal on Windows uses GetConsoleMode under the hood.
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("CONIN$")
        {
            Ok(f) => f.is_terminal(),
            Err(_) => false,
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

const NO_INTERACTIVE_TERMINAL_MSG: &str =
    "no interactive terminal available for passphrase prompt. \
     Provide --passphrase-env, --passphrase-file, or --passphrase-stdin.";

const PROTECTED_NO_TERMINAL_MSG: &str = "identity file is passphrase-protected but no interactive \
     terminal is available. Provide --passphrase-env, \
     --passphrase-file, or --passphrase-stdin.";

/// Prompt on the controlling console via rpassword, after a device preflight.
fn prompt_passphrase_interactive(prompt: &str, no_console_msg: &str) -> CliResult<SecretString> {
    if !interactive_console_available() {
        return Err(CliError::Message(no_console_msg.to_string()));
    }
    eprint!("{prompt}");
    let pp = SecretString::from(
        rpassword::read_password().map_err(|_| CliError::Message(no_console_msg.to_string()))?,
    );
    if pp.expose_secret().is_empty() {
        return Err(CliError::Message(
            "passphrase must not be empty".to_string(),
        ));
    }
    Ok(pp)
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
        let pp = prompt_passphrase_interactive(prompt, NO_INTERACTIVE_TERMINAL_MSG)?;
        if confirm {
            // Confirmation uses the same console preflight; surface a distinct
            // message if the second read fails closed.
            let pp2 = prompt_passphrase_interactive(
                "Confirm passphrase: ",
                "failed to read passphrase confirmation",
            )?;
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
    // --identity-public-key and --identity-file conflict at clap parse time.
    if let Some(public_key) = &args.identity_public_key {
        let path = find_identity_path_by_public_key(public_key)?;
        // Access preflight before format detection / passphrase probing so
        // insecure files fail closed without reading secret-body material.
        assert_identity_file_access(&path)?;
        let protected = is_passphrase_protected_identity(&path)?;
        let passphrase = if protected {
            resolve_passphrase_for_protected(passphrase_args)?
        } else {
            None
        };
        let identities = load_identity_by_public_key(public_key, passphrase.as_ref())?;
        if required && identities.is_empty() {
            return Err(CliError::Message(
                "no identities resolved; provide --identity-file or --identity-public-key"
                    .to_string(),
            ));
        }
        return Ok(identities);
    }

    // Per SC-008 settled decision 1: scan all identity files first,
    // error if more than one is passphrase-protected.
    // Access preflight runs before any format probe on each path.
    let mut protected_count = 0usize;
    for path in &args.identity_files {
        assert_identity_file_access(path)?;
        if is_passphrase_protected_identity(path)? {
            protected_count += 1;
        }
    }
    if protected_count > 1 {
        return Err(CliError::Keyring(KeyringError::MultipleProtectedIdentities));
    }

    // Resolve passphrase only if needed (at least one protected identity)
    let passphrase = if protected_count > 0 {
        resolve_passphrase_for_protected(passphrase_args)?
    } else {
        None
    };

    let mut identities = Vec::new();
    for path in &args.identity_files {
        identities.extend(load_identity_file_auto(path, passphrase.as_ref())?);
    }

    if required && identities.is_empty() {
        return Err(CliError::Message(
            "no identities resolved; provide --identity-file or --identity-public-key".to_string(),
        ));
    }

    Ok(identities)
}

/// Resolve passphrase for a protected identity, with controlling-console auto-prompt.
fn resolve_passphrase_for_protected(
    passphrase_args: &PassphraseArgs,
) -> CliResult<Option<SecretString>> {
    let mut pp = resolve_passphrase(passphrase_args, false)?;
    // Auto-prompt when no explicit channel and a controlling console is available
    // (same device rpassword opens — not stdin isatty).
    if pp.is_none() {
        pp = Some(prompt_passphrase_interactive(
            "Passphrase: ",
            PROTECTED_NO_TERMINAL_MSG,
        )?);
    }
    Ok(pp)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use seclusor_crypto::CryptoError;
    use seclusor_keyring::generate_identity_file_with_passphrase;
    use secrecy::SecretString;

    use crate::cli::{IdentityArgs, PassphraseArgs};
    use crate::error::CliError;

    #[test]
    fn resolve_identities_insecure_protected_file_fails_before_passphrase_probe() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("protected.txt");
        let pp = SecretString::from("test-passphrase-for-cli-preflight".to_owned());
        generate_identity_file_with_passphrase(&path, &pp).expect("generate protected");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");

        // No passphrase channel: without preflight-first this would prompt or
        // return ProtectedIdentityNoPassphrase after reading the armor header.
        let err = match resolve_identities(
            &IdentityArgs {
                identity_files: vec![path],
                identity_public_key: None,
            },
            &PassphraseArgs::default(),
            false,
        ) {
            Ok(_) => panic!("must fail access before passphrase path"),
            Err(e) => e,
        };

        assert!(
            matches!(
                err,
                CliError::Crypto(CryptoError::InsecureIdentityFilePermissions { .. })
            ),
            "expected insecure permissions, got {err}"
        );
        assert!(!matches!(
            err,
            CliError::Keyring(KeyringError::ProtectedIdentityNoPassphrase)
        ));
    }

    #[test]
    fn resolve_identities_public_key_insecure_protected_fails_before_passphrase_probe() {
        let dir = tempfile::tempdir().expect("temp dir");
        let xdg = dir.path().join("xdg-config");
        let seclusor_cfg = xdg.join("seclusor");
        fs::create_dir_all(&seclusor_cfg).expect("mkdir config");
        let path = seclusor_cfg.join("identity.txt");
        let pp = SecretString::from("test-passphrase-for-cli-pk-preflight".to_owned());
        let generated =
            generate_identity_file_with_passphrase(&path, &pp).expect("generate protected");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");

        let prev = std::env::var_os("XDG_CONFIG_HOME");
        std::env::set_var("XDG_CONFIG_HOME", &xdg);
        let result = resolve_identities(
            &IdentityArgs {
                identity_files: vec![],
                identity_public_key: Some(generated.recipient.clone()),
            },
            &PassphraseArgs::default(),
            false,
        );
        match prev {
            Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
            None => std::env::remove_var("XDG_CONFIG_HOME"),
        }

        let err = match result {
            Ok(_) => panic!("must fail access before passphrase path"),
            Err(e) => e,
        };
        assert!(
            matches!(
                err,
                CliError::Crypto(CryptoError::InsecureIdentityFilePermissions { .. })
            ),
            "expected insecure permissions, got {err}"
        );
        assert!(!matches!(
            err,
            CliError::Keyring(KeyringError::ProtectedIdentityNoPassphrase)
        ));
    }
}
