use std::collections::HashSet;
use std::fs;
use std::path::Path;

use seclusor_crypto::{assert_identity_file_access, parse_recipients, Identity};
use seclusor_keyring::{
    discover_recipients, find_identity_path_by_public_key, is_passphrase_protected_identity,
    load_identity_file_auto, KeyringError, Recipient, RecipientDiscoveryOptions,
    DEFAULT_RECIPIENTS_ENV_VAR,
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

/// True when interactive readers can open a controlling console.
///
/// rpassword 7.x does **not** read stdin: it opens `/dev/tty` (Unix) or
/// `CONIN$` (Windows). Passphrase prompting uses this directly. Hidden value
/// input first classifies with `stdin().is_terminal()` and calls this only
/// after terminal stdin selects the hidden path; this helper must never divert
/// piped value input to a controlling console.
///
/// Preflight here mirrors the device rpassword opens so we fail closed before
/// calling `read_password`, which can block indefinitely on some Windows
/// noninteractive runners instead of returning an error.
pub(crate) fn interactive_console_available() -> bool {
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

/// Normalize the single line read by interactive, file, and stdin channels.
///
/// Environment-sourced passphrases intentionally bypass this helper so an
/// exact legacy value containing a carriage return remains usable for recovery.
fn normalize_passphrase_line_ending(
    mut value: String,
    empty_message: &'static str,
) -> CliResult<SecretString> {
    if value.ends_with('\n') {
        value.pop();
    }
    if value.ends_with('\r') {
        value.pop();
    }
    if value.is_empty() {
        return Err(CliError::Message(empty_message.to_string()));
    }
    Ok(SecretString::from(value))
}

/// Prompt on the controlling console via rpassword, after a device preflight.
fn prompt_passphrase_interactive(prompt: &str, no_console_msg: &str) -> CliResult<SecretString> {
    if !interactive_console_available() {
        return Err(CliError::Message(no_console_msg.to_string()));
    }
    eprint!("{prompt}");
    let value =
        rpassword::read_password().map_err(|_| CliError::Message(no_console_msg.to_string()))?;
    normalize_passphrase_line_ending(value, "passphrase must not be empty")
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
        // Read file bytes and use only the first line.
        let bytes = fs::read(path)?;
        let first_newline = bytes
            .iter()
            .position(|&b| b == b'\n')
            .unwrap_or(bytes.len());
        let line_bytes = &bytes[..first_newline];
        let line_str = std::str::from_utf8(line_bytes)
            .map_err(|_| CliError::Message("passphrase file is not valid UTF-8".to_string()))?;
        Ok(Some(normalize_passphrase_line_ending(
            line_str.to_owned(),
            "passphrase file is empty",
        )?))
    } else if args.passphrase_stdin {
        let mut value = String::new();
        std::io::stdin().read_line(&mut value)?;
        Ok(Some(normalize_passphrase_line_ending(
            value,
            "passphrase from stdin is empty",
        )?))
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
    Ok(resolve_identities_full(args, passphrase_args, required)?.0)
}

/// Resolve identities together with the exact private source paths that were
/// loaded. Callers that must protect those paths from output aliasing must use
/// this single-discovery result rather than repeating keyring lookup.
pub(crate) fn resolve_identities_with_sources(
    args: &IdentityArgs,
    passphrase_args: &PassphraseArgs,
    required: bool,
) -> CliResult<(Vec<Identity>, Vec<std::path::PathBuf>)> {
    let (identities, _passphrase, sources) =
        resolve_identities_full(args, passphrase_args, required)?;
    Ok((identities, sources))
}

/// Resolve identities and retain the passphrase used to unlock them (if any).
///
/// Callers that spawn a credential-consuming child (currently `secrets run`)
/// need the exact resolved passphrase for the child-env value-equality guard.
/// Other handlers should use [`resolve_identities`], which drops it.
///
/// The passphrase is resolved at most once; do not re-read env/file/stdin.
pub(crate) fn resolve_identities_with_passphrase(
    args: &IdentityArgs,
    passphrase_args: &PassphraseArgs,
    required: bool,
) -> CliResult<(Vec<Identity>, Option<SecretString>)> {
    let (identities, passphrase, _sources) =
        resolve_identities_full(args, passphrase_args, required)?;
    Ok((identities, passphrase))
}

fn resolve_identities_full(
    args: &IdentityArgs,
    passphrase_args: &PassphraseArgs,
    required: bool,
) -> CliResult<(Vec<Identity>, Option<SecretString>, Vec<std::path::PathBuf>)> {
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
        let identities = load_identity_file_auto(&path, passphrase.as_ref())?;
        let want = public_key
            .trim()
            .parse::<Recipient>()
            .map_err(|_| CliError::Keyring(KeyringError::InvalidIdentityPublicKey))?
            .to_string();
        if !identities
            .iter()
            .any(|identity| identity.to_public().to_string() == want)
        {
            return Err(CliError::Keyring(KeyringError::IdentityPublicKeyMismatch {
                path,
            }));
        }
        if required && identities.is_empty() {
            return Err(CliError::Message(
                "no identities resolved; provide --identity-file or --identity-public-key"
                    .to_string(),
            ));
        }
        return Ok((identities, passphrase, vec![path]));
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

    Ok((identities, passphrase, args.identity_files.clone()))
}

/// Guard-only passphrase material for the child-env value-equality assertion.
///
/// **Scoped to `--passphrase-env` only.** Other channels are deliberately not
/// resolved here:
/// - `--passphrase-stdin` would consume the child's stdin on an all-unprotected estate
/// - interactive would prompt when no unlock is needed
/// - `--passphrase-file` is not required for the named-env exclusion contract
///
/// Failure semantics are **structural**: this function returns `Option`, not
/// `Result`. An unset or empty environment variable yields `None` (no-op), never
/// an error — distinct from [`resolve_passphrase`] / unlock paths, which hard-error
/// when `--passphrase-env` is named but missing.
///
/// Callers that already unlocked a protected identity should prefer that
/// `SecretString` and only fall back here when unlock produced `None`.
pub(crate) fn resolve_passphrase_for_guard(args: &PassphraseArgs) -> Option<SecretString> {
    let var_name = args.passphrase_env.as_ref()?;
    match std::env::var(var_name) {
        Ok(value) if !value.is_empty() => Some(SecretString::from(value)),
        // Unset, empty, or non-Unicode: no guard material (not an error).
        _ => None,
    }
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
    fn line_oriented_passphrases_normalize_crlf_and_reject_blank_lines() {
        let normalized =
            normalize_passphrase_line_ending("synthetic-value\r\n".to_string(), "empty")
                .expect("normalize CRLF");
        let expected = "synthetic-value";
        assert!(
            normalized.expose_secret() == expected,
            "normalized passphrase mismatch"
        );

        let err = normalize_passphrase_line_ending("\r\n".to_string(), "channel is empty")
            .expect_err("CRLF-only input must be empty after normalization");
        assert!(matches!(err, CliError::Message(ref message) if message == "channel is empty"));
    }

    #[test]
    fn passphrase_file_normalizes_first_line_and_rejects_crlf_blank() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("passphrase.txt");
        fs::write(&path, b"synthetic-value\r\nignored-second-line\n").expect("write file");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");

        let resolved = resolve_passphrase(
            &PassphraseArgs {
                passphrase_file: Some(path.clone()),
                ..PassphraseArgs::default()
            },
            false,
        )
        .expect("resolve file")
        .expect("passphrase");
        let expected = "synthetic-value";
        assert!(
            resolved.expose_secret() == expected,
            "resolved passphrase mismatch"
        );

        fs::write(&path, b"\r\nignored-second-line\n").expect("rewrite file");
        let err = resolve_passphrase(
            &PassphraseArgs {
                passphrase_file: Some(path),
                ..PassphraseArgs::default()
            },
            false,
        )
        .expect_err("CRLF-only first line must be rejected");
        assert!(
            matches!(err, CliError::Message(ref message) if message == "passphrase file is empty")
        );
    }

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
