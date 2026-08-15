//! `secrets rekey` — full-document recipient rewrite.
//!
//! Normalizes all encrypted fields to one canonical recipient set, persists
//! schema v1.1.0 `recipients` metadata, and commits via the atomic ciphertext
//! writer with CAS when rewriting in place.

use std::ffi::OsString;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use crate::atomic_write::{atomic_write_ciphertext, atomic_write_public_data, AtomicWriteOptions};
use crate::cli::RekeyArgs;
use crate::error::{CliError, CliResult};
use crate::handlers::encrypted_write::{
    apply_establishment, emit_establishment_notice, emit_recipient_comparison_indeterminate_notice,
    emit_self_lockout_warning, recipient_strings, refuse_scrypt_bundle_write,
    render_recipient_delta,
};
use crate::io::{probe_write_target, WriteTargetProbe};
use crate::resolve::{resolve_identities_with_sources, resolve_recipients};
use seclusor_codec::{
    ensure_no_plaintext_credential_values, mutate_bundle, reencrypt_all_inline, DocumentSource,
};
use seclusor_core::constants::MAX_SECRETS_DOC_BYTES;
use seclusor_core::validate::{compare_recipient_sets, validate_strict, RecipientSetRelation};
use seclusor_core::SeclusorError;
#[cfg(test)]
use seclusor_crypto::Identity;

#[cfg(test)]
pub(crate) fn handle_rekey(args: RekeyArgs) -> CliResult<()> {
    handle_rekey_with_policy(args, false)
}

pub(crate) fn handle_rekey_with_policy(
    args: RekeyArgs,
    allow_recipient_mismatch: bool,
) -> CliResult<()> {
    // Rekey always requires explicit new recipients and identities.
    if !crate::handlers::encrypted_write::recipient_channels_present(&args.recipients) {
        return Err(CliError::Message(
            "rekey requires at least one of --recipient, --recipient-file, or \
             --recipient-env-var"
                .to_string(),
        ));
    }
    let output_path = args.output.clone().unwrap_or_else(|| args.file.clone());
    let in_place = classify_rekey_output(&args.file, args.output.as_deref())?;
    let input_path = if in_place {
        fs::canonicalize(&args.file).map_err(CliError::Io)?
    } else {
        args.file.clone()
    };

    // Classify target before identity resolution so scrypt data-bundles refuse
    // naming SC-011 even when identity channels are missing/protected.
    let probe = probe_write_target(&input_path)?;
    if let WriteTargetProbe::Encrypted {
        source: DocumentSource::Bundle,
        bytes,
    } = &probe
    {
        refuse_scrypt_bundle_write(bytes)?;
    }

    let (identities, identity_paths) =
        resolve_identities_with_sources(&args.identities, &args.passphrase, true)?;
    let recipient_refresh_target = prepare_recipient_refresh_target(
        args.write_recipients.as_deref(),
        &args.file,
        &output_path,
        &identity_paths,
        args.passphrase.passphrase_file.as_deref(),
        args.recipients.recipient_file.as_deref(),
    )?;
    let new_recipients = resolve_recipients(&args.recipients)?;
    let new_strings = recipient_strings(&new_recipients);
    let recipient_refresh = prepare_recipient_refresh(recipient_refresh_target, &new_strings)?;

    match probe {
        WriteTargetProbe::Encrypted {
            source: DocumentSource::Inline,
            bytes,
        } => {
            let resolved = seclusor_codec::resolve_runtime_document(&bytes, &[])?;
            let mut secrets = resolved.secrets;
            let policy_notices = evaluate_rekey_recipient_policy(
                secrets.recipients.as_deref(),
                &new_strings,
                allow_recipient_mismatch,
            )?;
            emit_self_lockout_warning(&identities, &new_strings);
            // Optional equality: if metadata present and explicit matches, still rekey
            // (rekey *is* allowed to change the set — skip equality fail).
            // Stanza tripwire: only refuse if metadata claims N but fields disagree.
            if let Some(meta) = secrets.recipients.as_deref() {
                // When rekeying *to* a new set, stanza mismatch vs old metadata is expected
                // only if already heterogeneous — check fields against each other.
                let expected = meta.len();
                if let Err(e) = crate::handlers::encrypted_write::ensure_inline_stanza_count_matches(
                    &secrets, expected,
                ) {
                    // Heterogeneous document: still allow rekey (the migration path).
                    // Log on stderr; reencrypt_all_inline will rewrite everything.
                    let _ = e;
                    eprintln!(
                        "warning: document had recipient stanza divergence; rekey will \
                         normalize all encrypted fields"
                    );
                }
            }

            let result = reencrypt_all_inline(&secrets, &identities, &new_recipients)?;
            secrets = result.secrets;
            // Always establish/replace metadata with the new canonical set.
            secrets.establish_recipients(new_strings.clone())?;
            ensure_no_plaintext_credential_values(&secrets)?;
            validate_strict(&secrets)?;

            let mut out = serde_json::to_vec_pretty(&secrets)?;
            if !out.ends_with(b"\n") {
                out.push(b'\n');
            }
            if out.len() > MAX_SECRETS_DOC_BYTES {
                return Err(CliError::Core(SeclusorError::DocumentTooLarge {
                    actual: out.len(),
                    max: MAX_SECRETS_DOC_BYTES,
                }));
            }

            if in_place {
                eprintln!("warning: overwriting {} in place", args.file.display());
                atomic_write_ciphertext(
                    &input_path,
                    &out,
                    AtomicWriteOptions {
                        expected_prior_bytes: Some(bytes),
                        create_new: false,
                    },
                )?;
            } else {
                write_new_ciphertext_file(&output_path, &out)?;
            }

            commit_recipient_refresh(recipient_refresh.as_ref(), &output_path)?;
            let count = seclusor_codec::encrypted_value_keys(&secrets).len();
            emit_rekey_policy_notices(&policy_notices);
            emit_establishment_notice(&new_strings);
            eprintln!("rekeyed {count} inline credential value(s)");
            emit_recipient_refresh_notice(recipient_refresh.as_ref());
            println!("{}", output_path.display());
            Ok(())
        }
        WriteTargetProbe::Encrypted {
            source: DocumentSource::Bundle,
            bytes,
        } => {
            // Scrypt already refused before identity resolve; mutate_bundle
            // re-checks as defense in depth.
            let mut policy_notices = None;
            let result = mutate_bundle(&bytes, &identities, &new_recipients, |secrets| {
                let notices = evaluate_rekey_recipient_policy(
                    secrets.recipients.as_deref(),
                    &new_strings,
                    allow_recipient_mismatch,
                )
                .map_err(|error| {
                    seclusor_codec::CodecError::Core(SeclusorError::Validation(error.to_string()))
                })?;
                emit_self_lockout_warning(&identities, &new_strings);
                policy_notices = Some(notices);
                secrets
                    .establish_recipients(new_strings.clone())
                    .map_err(seclusor_codec::CodecError::from)?;
                Ok(())
            })?;

            if in_place {
                eprintln!("warning: overwriting {} in place", args.file.display());
                atomic_write_ciphertext(
                    &input_path,
                    &result.ciphertext,
                    AtomicWriteOptions {
                        expected_prior_bytes: Some(bytes),
                        create_new: false,
                    },
                )?;
            } else {
                write_new_ciphertext_file(&output_path, &result.ciphertext)?;
            }

            commit_recipient_refresh(recipient_refresh.as_ref(), &output_path)?;
            let policy_notices = policy_notices.ok_or_else(|| {
                CliError::Message("internal error: recipient policy was not evaluated".to_string())
            })?;
            emit_rekey_policy_notices(&policy_notices);
            emit_establishment_notice(&new_strings);
            eprintln!("rekeyed bundle document");
            emit_recipient_refresh_notice(recipient_refresh.as_ref());
            println!("{}", output_path.display());
            Ok(())
        }
        WriteTargetProbe::Plaintext { mut secrets, bytes } => {
            // Plaintext → encrypt all direct values and establish recipients.
            // CAS is anchored to the exact load-time probe bytes (not a re-read).
            let policy_notices = evaluate_rekey_recipient_policy(
                secrets.recipients.as_deref(),
                &new_strings,
                allow_recipient_mismatch,
            )?;
            emit_self_lockout_warning(&identities, &new_strings);
            let result = reencrypt_all_inline(&secrets, &identities, &new_recipients)?;
            secrets = result.secrets;
            apply_establishment(&mut secrets, &new_strings)?;
            ensure_no_plaintext_credential_values(&secrets)?;
            let mut out = serde_json::to_vec_pretty(&secrets)?;
            if !out.ends_with(b"\n") {
                out.push(b'\n');
            }
            if in_place {
                eprintln!("warning: overwriting {} in place", args.file.display());
                atomic_write_ciphertext(
                    &input_path,
                    &out,
                    AtomicWriteOptions {
                        expected_prior_bytes: Some(bytes),
                        create_new: false,
                    },
                )?;
            } else {
                write_new_ciphertext_file(&output_path, &out)?;
            }
            commit_recipient_refresh(recipient_refresh.as_ref(), &output_path)?;
            let count = seclusor_codec::encrypted_value_keys(&secrets).len();
            emit_rekey_policy_notices(&policy_notices);
            emit_establishment_notice(&new_strings);
            eprintln!("rekeyed {count} credential value(s) from plaintext document");
            emit_recipient_refresh_notice(recipient_refresh.as_ref());
            println!("{}", output_path.display());
            Ok(())
        }
        WriteTargetProbe::NotEncrypted(bytes) => {
            let mut secrets = crate::io::secrets_from_bytes(&bytes)?;
            let policy_notices = evaluate_rekey_recipient_policy(
                secrets.recipients.as_deref(),
                &new_strings,
                allow_recipient_mismatch,
            )?;
            emit_self_lockout_warning(&identities, &new_strings);
            let result = reencrypt_all_inline(&secrets, &identities, &new_recipients)?;
            secrets = result.secrets;
            apply_establishment(&mut secrets, &new_strings)?;
            ensure_no_plaintext_credential_values(&secrets)?;
            let mut out = serde_json::to_vec_pretty(&secrets)?;
            if !out.ends_with(b"\n") {
                out.push(b'\n');
            }
            if in_place {
                eprintln!("warning: overwriting {} in place", args.file.display());
                atomic_write_ciphertext(
                    &input_path,
                    &out,
                    AtomicWriteOptions {
                        expected_prior_bytes: Some(bytes),
                        create_new: false,
                    },
                )?;
            } else {
                write_new_ciphertext_file(&output_path, &out)?;
            }
            commit_recipient_refresh(recipient_refresh.as_ref(), &output_path)?;
            let count = seclusor_codec::encrypted_value_keys(&secrets).len();
            emit_rekey_policy_notices(&policy_notices);
            emit_establishment_notice(&new_strings);
            eprintln!("rekeyed {count} credential value(s)");
            emit_recipient_refresh_notice(recipient_refresh.as_ref());
            println!("{}", output_path.display());
            Ok(())
        }
        WriteTargetProbe::Encrypted {
            source: DocumentSource::Plaintext,
            ..
        } => Err(CliError::Message(
            "internal classification error: encrypted+plaintext".to_string(),
        )),
    }
}

#[derive(Debug)]
struct RekeyPolicyNotices {
    relation: RecipientSetRelation,
}

fn evaluate_rekey_recipient_policy(
    document_recipients: Option<&[String]>,
    target_recipients: &[String],
    allow_mismatch: bool,
) -> CliResult<RekeyPolicyNotices> {
    let relation = compare_recipient_sets(document_recipients, target_recipients);
    if let RecipientSetRelation::Delta { added, removed } = &relation {
        if !allow_mismatch {
            return Err(CliError::Message(format!(
                "target recipient set differs from document metadata; refusing rekey \
                 without --allow-recipient-mismatch:{}",
                render_recipient_delta(added, removed)
            )));
        }
    }

    Ok(RekeyPolicyNotices { relation })
}

fn emit_rekey_policy_notices(notices: &RekeyPolicyNotices) {
    match &notices.relation {
        RecipientSetRelation::Match => {}
        RecipientSetRelation::Delta { added, removed } => eprintln!(
            "recipient set change accepted:{}",
            render_recipient_delta(added, removed)
        ),
        RecipientSetRelation::Indeterminate => {
            emit_recipient_comparison_indeterminate_notice();
        }
    }
}

fn write_new_ciphertext_file(path: &Path, content: &[u8]) -> CliResult<()> {
    atomic_write_ciphertext(
        path,
        content,
        AtomicWriteOptions {
            expected_prior_bytes: None,
            create_new: true,
        },
    )
}

const MAX_PRIOR_RECIPIENT_FILE_BYTES: u64 = 1024 * 1024;

#[derive(Debug)]
struct RecipientRefreshPlan {
    path: PathBuf,
    content: Vec<u8>,
    prior_bytes: Option<Vec<u8>>,
}

#[derive(Debug)]
struct RecipientRefreshTarget {
    path: PathBuf,
    prior_bytes: Option<Vec<u8>>,
}

fn prepare_recipient_refresh_target(
    path: Option<&Path>,
    input_path: &Path,
    output_path: &Path,
    identity_paths: &[PathBuf],
    passphrase_path: Option<&Path>,
    recipient_input_path: Option<&Path>,
) -> CliResult<Option<RecipientRefreshTarget>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let path = resolve_recipient_refresh_target(path)?;

    reject_recipient_refresh_alias(&path, input_path, "--file")?;
    reject_recipient_refresh_alias(&path, output_path, "--output")?;
    for identity_path in identity_paths {
        reject_recipient_refresh_alias(&path, identity_path, "identity source")?;
    }
    if let Some(passphrase_path) = passphrase_path {
        reject_recipient_refresh_alias(&path, passphrase_path, "--passphrase-file")?;
    }
    if let Some(recipient_input_path) = recipient_input_path {
        let exact_input_target = resolve_recipient_refresh_target(recipient_input_path)?;
        let same_resolved_path = normalize_path_for_comparison(&path)?
            == normalize_path_for_comparison(&exact_input_target)?;
        if !same_resolved_path && paths_alias(&path, &exact_input_target)? {
            return Err(CliError::Message(format!(
                "--write-recipients path {} aliases --recipient-file path {}; \
                 use the same explicitly named path to refresh that source",
                path.display(),
                recipient_input_path.display()
            )));
        }
    }

    let prior_bytes = read_optional_recipient_file(&path)?;
    Ok(Some(RecipientRefreshTarget { path, prior_bytes }))
}

fn prepare_recipient_refresh(
    target: Option<RecipientRefreshTarget>,
    recipients: &[String],
) -> CliResult<Option<RecipientRefreshPlan>> {
    let Some(target) = target else {
        return Ok(None);
    };

    let mut content = recipients.join("\n").into_bytes();
    content.push(b'\n');

    Ok(Some(RecipientRefreshPlan {
        path: target.path,
        content,
        prior_bytes: target.prior_bytes,
    }))
}

fn resolve_recipient_refresh_target(path: &Path) -> CliResult<PathBuf> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            let target = fs::canonicalize(path).map_err(CliError::Io)?;
            let target_metadata = fs::metadata(&target).map_err(CliError::Io)?;
            if !target_metadata.is_file() {
                return Err(CliError::Message(format!(
                    "--write-recipients target {} must resolve to a regular file",
                    path.display()
                )));
            }
            Ok(target)
        }
        Ok(metadata) if metadata.is_file() => Ok(path.to_path_buf()),
        Ok(_) => Err(CliError::Message(format!(
            "--write-recipients target {} must be a regular file path",
            path.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(path.to_path_buf()),
        Err(error) => Err(CliError::Io(error)),
    }
}

fn reject_recipient_refresh_alias(
    recipient_path: &Path,
    protected_path: &Path,
    protected_flag: &str,
) -> CliResult<()> {
    if paths_alias(recipient_path, protected_path)? {
        return Err(CliError::Message(format!(
            "--write-recipients path {} aliases {protected_flag} path {}; \
             choose a separate recipient-list path",
            recipient_path.display(),
            protected_path.display()
        )));
    }
    Ok(())
}

fn read_optional_recipient_file(path: &Path) -> CliResult<Option<Vec<u8>>> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(CliError::Io(error)),
    };
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_PRIOR_RECIPIENT_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_PRIOR_RECIPIENT_FILE_BYTES {
        return Err(CliError::Message(format!(
            "existing --write-recipients target {} exceeds the 1 MiB safety limit",
            path.display()
        )));
    }
    Ok(Some(bytes))
}

fn commit_recipient_refresh(
    plan: Option<&RecipientRefreshPlan>,
    output_path: &Path,
) -> CliResult<()> {
    let Some(plan) = plan else {
        return Ok(());
    };

    #[cfg(test)]
    inject_recipient_refresh_fault();

    let result = atomic_write_public_data(
        &plan.path,
        &plan.content,
        AtomicWriteOptions {
            expected_prior_bytes: plan.prior_bytes.clone(),
            create_new: plan.prior_bytes.is_none(),
        },
    );
    #[cfg(test)]
    crate::atomic_write::inject_fault(None);

    result.map_err(|source| CliError::RecipientRefreshFailed {
        output_path: output_path.display().to_string(),
        recipient_path: plan.path.display().to_string(),
        source: Box::new(source),
    })
}

fn emit_recipient_refresh_notice(plan: Option<&RecipientRefreshPlan>) {
    if let Some(plan) = plan {
        eprintln!("wrote recipient set to {}", plan.path.display());
    }
}

fn classify_rekey_output(input: &Path, explicit_output: Option<&Path>) -> CliResult<bool> {
    let Some(output) = explicit_output else {
        return Ok(true);
    };
    if normalize_absolute_lexically(input)? == normalize_absolute_lexically(output)? {
        return Ok(true);
    }
    if paths_alias(input, output)? {
        return Err(CliError::Message(format!(
            "--output path {} aliases --file path {}; use the same path spelling for an \
             in-place rekey or choose a separate output",
            output.display(),
            input.display()
        )));
    }
    Ok(false)
}

fn paths_alias(a: &Path, b: &Path) -> CliResult<bool> {
    if a == b {
        return Ok(true);
    }
    match same_file::is_same_file(a, b) {
        Ok(is_same) => return Ok(is_same),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(CliError::Io(error)),
    }

    Ok(normalize_path_for_comparison(a)? == normalize_path_for_comparison(b)?)
}

fn normalize_absolute_lexically(path: &Path) -> CliResult<PathBuf> {
    Ok(normalize_lexically(
        &std::path::absolute(path).map_err(CliError::Io)?,
    ))
}

fn normalize_path_for_comparison(path: &Path) -> CliResult<PathBuf> {
    let absolute = std::path::absolute(path).map_err(CliError::Io)?;
    let mut ancestor = absolute.as_path();
    let mut suffix = Vec::<OsString>::new();

    loop {
        match fs::canonicalize(ancestor) {
            Ok(base) => {
                let mut combined = base;
                for component in suffix.iter().rev() {
                    combined.push(component);
                }
                return Ok(normalize_lexically(&combined));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let name = ancestor.file_name().ok_or(CliError::Io(error))?;
                suffix.push(name.to_os_string());
                ancestor = ancestor.parent().ok_or_else(|| {
                    CliError::Message(format!(
                        "could not resolve path {} for alias validation",
                        path.display()
                    ))
                })?;
            }
            Err(error) => return Err(CliError::Io(error)),
        }
    }
}

fn normalize_lexically(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                let _ = normalized.pop();
            }
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
        }
    }
    normalized
}

#[cfg(test)]
thread_local! {
    static RECIPIENT_REFRESH_FAULT: std::cell::Cell<Option<crate::atomic_write::AtomicFault>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn set_recipient_refresh_fault(fault: Option<crate::atomic_write::AtomicFault>) {
    RECIPIENT_REFRESH_FAULT.with(|slot| slot.set(fault));
}

#[cfg(test)]
fn inject_recipient_refresh_fault() {
    RECIPIENT_REFRESH_FAULT.with(|slot| crate::atomic_write::inject_fault(slot.take()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    use crate::cli::{IdentityArgs, PassphraseArgs, RecipientArgs};
    use crate::io::write_secrets_file;
    use crate::test_support::*;

    #[test]
    fn rekey_inline_establishes_recipients_and_normalizes() {
        let dir = tempfile::tempdir().expect("temp");
        let (inline, identity_file) = write_inline_encrypted_file(dir.path());
        // Multi-field document; rekey normalizes/establishes the recipient set.
        let before = fs::read(&inline).expect("before");
        let _ = before;

        handle_rekey(RekeyArgs {
            file: inline.clone(),
            output: None,
            write_recipients: None,
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
        .expect("rekey");

        let after: seclusor_core::SecretsFile =
            serde_json::from_slice(&fs::read(&inline).expect("after")).expect("parse");
        assert_eq!(after.schema_version, "v1.1.0");
        assert_eq!(
            after.recipients.as_deref(),
            Some(std::slice::from_ref(&fixture_recipient_string()))
        );
        // All values still encrypted and decryptable.
        for (key, cred) in &after.projects[0].credentials {
            if let Some(v) = &cred.value {
                assert!(v.starts_with("sec:age:v1:"), "{key}");
                seclusor_crypto::decrypt_inline_value(v, &[fixture_identity()]).expect("dec");
            }
        }
    }

    #[test]
    fn rekey_inline_delta_fails_closed_then_override_rewrites_all_values() {
        let dir = tempfile::tempdir().expect("temp");
        let (inline, old_identity_file) = write_inline_encrypted_file(dir.path());
        let new_identity_file = dir.path().join("new-id.txt");
        let generated =
            seclusor_keyring::generate_identity_file(&new_identity_file).expect("new identity");
        let before = fs::read(&inline).expect("before");

        let err = handle_rekey(RekeyArgs {
            file: inline.clone(),
            output: None,
            write_recipients: None,
            recipients: RecipientArgs {
                recipients: vec![generated.recipient.clone()],
                recipient_file: None,
                recipient_env_var: None,
            },
            identities: IdentityArgs {
                identity_files: vec![old_identity_file.clone()],
                identity_public_key: None,
            },
            passphrase: PassphraseArgs::default(),
        })
        .expect_err("delta must require consent");
        let message = err.to_string();
        assert!(message.contains("--allow-recipient-mismatch"));
        assert!(message.contains(&format!("  +{}", generated.recipient)));
        assert!(message.contains(&format!("  -{}", fixture_recipient_string())));
        assert_eq!(fs::read(&inline).expect("after refusal"), before);

        handle_rekey_with_policy(
            RekeyArgs {
                file: inline.clone(),
                output: None,
                write_recipients: None,
                recipients: RecipientArgs {
                    recipients: vec![generated.recipient.clone()],
                    recipient_file: None,
                    recipient_env_var: None,
                },
                identities: IdentityArgs {
                    identity_files: vec![old_identity_file],
                    identity_public_key: None,
                },
                passphrase: PassphraseArgs::default(),
            },
            true,
        )
        .expect("allowed rotation");

        let rotated: seclusor_core::SecretsFile =
            serde_json::from_slice(&fs::read(&inline).expect("rotated")).expect("parse rotated");
        assert_eq!(
            rotated.recipients.as_deref(),
            Some(std::slice::from_ref(&generated.recipient))
        );
        let new_identity = generated
            .identity
            .parse::<Identity>()
            .expect("parse identity");
        seclusor_codec::decrypt_inline(&rotated, &[new_identity]).expect("new identity decrypts");
        seclusor_codec::decrypt_inline(&rotated, &[fixture_identity()])
            .expect_err("retired identity must not decrypt");
    }

    #[test]
    fn rekey_inline_explicitly_refreshes_recipient_file_canonically() {
        let dir = tempfile::tempdir().expect("temp");
        let (inline, old_identity_file) = write_inline_encrypted_file(dir.path());
        let new_id_a = dir.path().join("new-a.txt");
        let new_id_b = dir.path().join("new-b.txt");
        let generated_a =
            seclusor_keyring::generate_identity_file(&new_id_a).expect("new identity a");
        let generated_b =
            seclusor_keyring::generate_identity_file(&new_id_b).expect("new identity b");
        let recipient_file = dir.path().join("recipients.txt");
        fs::write(
            &recipient_file,
            format!(
                "{}\n{}\n{}\n",
                generated_b.recipient, generated_a.recipient, generated_b.recipient
            ),
        )
        .expect("seed recipients");

        handle_rekey_with_policy(
            RekeyArgs {
                file: inline.clone(),
                output: None,
                write_recipients: Some(recipient_file.clone()),
                recipients: RecipientArgs {
                    recipients: vec![],
                    recipient_file: Some(recipient_file.clone()),
                    recipient_env_var: None,
                },
                identities: IdentityArgs {
                    identity_files: vec![old_identity_file],
                    identity_public_key: None,
                },
                passphrase: PassphraseArgs::default(),
            },
            true,
        )
        .expect("rekey and refresh");

        let mut expected = vec![generated_a.recipient.clone(), generated_b.recipient.clone()];
        expected.sort();
        assert_eq!(
            fs::read_to_string(&recipient_file).expect("recipient file"),
            format!("{}\n", expected.join("\n"))
        );

        let rotated: seclusor_core::SecretsFile =
            serde_json::from_slice(&fs::read(&inline).expect("rotated")).expect("parse rotated");
        assert_eq!(rotated.recipients.as_deref(), Some(expected.as_slice()));
        let new_identity = generated_a
            .identity
            .parse::<Identity>()
            .expect("parse new identity");
        seclusor_codec::decrypt_inline(&rotated, &[new_identity]).expect("new identity decrypts");
        seclusor_codec::decrypt_inline(&rotated, &[fixture_identity()])
            .expect_err("retired identity must not decrypt");
    }

    #[test]
    fn recipient_refresh_failure_reports_partial_success_and_preserves_old_list() {
        use crate::atomic_write::AtomicFault;

        let dir = tempfile::tempdir().expect("temp");
        let (inline, old_identity_file) = write_inline_encrypted_file(dir.path());
        let new_identity_file = dir.path().join("new-id.txt");
        let generated =
            seclusor_keyring::generate_identity_file(&new_identity_file).expect("new identity");
        let recipient_file = dir.path().join("recipients.txt");
        let old_list = format!("{}\n", fixture_recipient_string());
        fs::write(&recipient_file, &old_list).expect("seed recipients");
        let names_before: Vec<_> = fs::read_dir(dir.path())
            .expect("read before")
            .map(|entry| entry.expect("entry").file_name())
            .collect();

        set_recipient_refresh_fault(Some(AtomicFault::AfterSyncBeforeReplace));
        let error = handle_rekey_with_policy(
            RekeyArgs {
                file: inline.clone(),
                output: None,
                write_recipients: Some(recipient_file.clone()),
                recipients: RecipientArgs {
                    recipients: vec![generated.recipient.clone()],
                    recipient_file: None,
                    recipient_env_var: None,
                },
                identities: IdentityArgs {
                    identity_files: vec![old_identity_file],
                    identity_public_key: None,
                },
                passphrase: PassphraseArgs::default(),
            },
            true,
        )
        .expect_err("recipient refresh fault");

        assert!(matches!(&error, CliError::RecipientRefreshFailed { .. }));
        let message = error.to_string();
        assert!(message.contains("rekey output was committed"));
        assert!(message.contains("may remain stale"));
        assert_eq!(
            fs::read_to_string(&recipient_file).expect("old list"),
            old_list
        );
        let names_after: Vec<_> = fs::read_dir(dir.path())
            .expect("read after")
            .map(|entry| entry.expect("entry").file_name())
            .collect();
        assert_eq!(names_after, names_before, "no temp residue");

        let rotated: seclusor_core::SecretsFile =
            serde_json::from_slice(&fs::read(&inline).expect("rotated")).expect("parse rotated");
        let new_identity = generated
            .identity
            .parse::<Identity>()
            .expect("parse identity");
        seclusor_codec::decrypt_inline(&rotated, &[new_identity])
            .expect("ciphertext commit must have succeeded");
        seclusor_codec::decrypt_inline(&rotated, &[fixture_identity()])
            .expect_err("old identity must have been retired");
    }

    #[test]
    fn recipient_refresh_aliases_refuse_before_rekey_write() {
        let dir = tempfile::tempdir().expect("temp");
        let (inline, identity_file) = write_inline_encrypted_file(dir.path());
        let before = fs::read(&inline).expect("before");

        for alias in [&inline, &identity_file] {
            let error = handle_rekey(RekeyArgs {
                file: inline.clone(),
                output: None,
                write_recipients: Some(alias.clone()),
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
            .expect_err("alias must refuse");
            assert!(error.to_string().contains("aliases"));
            assert_eq!(fs::read(&inline).expect("unchanged"), before);
        }

        let output = dir.path().join("output.age");
        let error = handle_rekey(RekeyArgs {
            file: inline.clone(),
            output: Some(output.clone()),
            write_recipients: Some(output),
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
        .expect_err("output alias must refuse");
        assert!(error.to_string().contains("--output"));
        assert_eq!(fs::read(&inline).expect("unchanged"), before);

        let passphrase_file = dir.path().join("passphrase.txt");
        fs::write(&passphrase_file, b"not-used\n").expect("passphrase fixture");
        let error = handle_rekey(RekeyArgs {
            file: inline.clone(),
            output: None,
            write_recipients: Some(passphrase_file.clone()),
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
            identities: IdentityArgs {
                identity_files: vec![identity_file],
                identity_public_key: None,
            },
            passphrase: PassphraseArgs {
                passphrase_file: Some(passphrase_file),
                ..PassphraseArgs::default()
            },
        })
        .expect_err("passphrase alias must refuse");
        assert!(error.to_string().contains("--passphrase-file"));
        assert_eq!(fs::read(&inline).expect("unchanged"), before);
    }

    #[cfg(unix)]
    #[test]
    fn recipient_refresh_hardlink_alias_refuses() {
        let dir = tempfile::tempdir().expect("temp");
        let (inline, identity_file) = write_inline_encrypted_file(dir.path());
        let alias = dir.path().join("recipient-alias.txt");
        fs::hard_link(&inline, &alias).expect("hard link");
        let before = fs::read(&inline).expect("before");

        let error = handle_rekey(RekeyArgs {
            file: inline.clone(),
            output: None,
            write_recipients: Some(alias),
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
        .expect_err("hardlink alias must refuse");
        assert!(error.to_string().contains("aliases"));
        assert_eq!(fs::read(&inline).expect("unchanged"), before);
    }

    #[cfg(unix)]
    #[test]
    fn rekey_preserves_input_symlink_and_refuses_distinct_hardlink_output() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().expect("temp");
        let (inline, identity_file) = write_inline_encrypted_file(dir.path());
        let link = dir.path().join("secrets-link.json");
        symlink(&inline, &link).expect("input symlink");

        handle_rekey(RekeyArgs {
            file: link.clone(),
            output: None,
            write_recipients: None,
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
        .expect("in-place rekey through symlink");

        assert!(
            fs::symlink_metadata(&link)
                .expect("link metadata")
                .file_type()
                .is_symlink(),
            "in-place rekey must preserve the input symlink"
        );
        let rotated: seclusor_core::SecretsFile =
            serde_json::from_slice(&fs::read(&inline).expect("rotated target"))
                .expect("parse rotated target");
        seclusor_codec::decrypt_inline(&rotated, &[fixture_identity()])
            .expect("rotated target decrypts");

        let hardlink_output = dir.path().join("hardlink-output.json");
        fs::hard_link(&inline, &hardlink_output).expect("hardlink output");
        let before = fs::read(&inline).expect("before refusal");
        let error = handle_rekey(RekeyArgs {
            file: inline.clone(),
            output: Some(hardlink_output),
            write_recipients: None,
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
        .expect_err("distinct hardlink output must refuse");
        assert!(error.to_string().contains("aliases --file"));
        assert_eq!(fs::read(&inline).expect("unchanged input"), before);
    }

    #[cfg(unix)]
    #[test]
    fn distinct_hardlink_alias_of_recipient_input_refuses() {
        let dir = tempfile::tempdir().expect("temp");
        let recipient_input = dir.path().join("recipients.txt");
        fs::write(
            &recipient_input,
            format!("{}\n", fixture_recipient_string()),
        )
        .expect("recipient input");
        let hardlink = dir.path().join("recipients-alias.txt");
        fs::hard_link(&recipient_input, &hardlink).expect("hardlink");

        let error = prepare_recipient_refresh_target(
            Some(&hardlink),
            &dir.path().join("secrets.json"),
            &dir.path().join("output.json"),
            &[],
            None,
            Some(&recipient_input),
        )
        .expect_err("distinct hardlink alias must refuse");
        assert!(error.to_string().contains("--recipient-file"));
    }

    #[cfg(unix)]
    #[test]
    fn exact_symlink_recipient_source_refreshes_underlying_file() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().expect("temp");
        let (inline, old_identity_file) = write_inline_encrypted_file(dir.path());
        let new_identity_file = dir.path().join("new-id.txt");
        let generated =
            seclusor_keyring::generate_identity_file(&new_identity_file).expect("new identity");
        let recipient_target = dir.path().join("recipients-target.txt");
        fs::write(
            &recipient_target,
            format!(
                "# current rotation target\n{}\r\n{}\n",
                generated.recipient, generated.recipient
            ),
        )
        .expect("seed recipient target");
        let recipient_link = dir.path().join("recipients.txt");
        symlink(&recipient_target, &recipient_link).expect("recipient symlink");

        handle_rekey_with_policy(
            RekeyArgs {
                file: inline,
                output: None,
                write_recipients: Some(recipient_link.clone()),
                recipients: RecipientArgs {
                    recipients: vec![],
                    recipient_file: Some(recipient_link.clone()),
                    recipient_env_var: None,
                },
                identities: IdentityArgs {
                    identity_files: vec![old_identity_file],
                    identity_public_key: None,
                },
                passphrase: PassphraseArgs::default(),
            },
            true,
        )
        .expect("refresh through explicit symlink source");

        assert!(
            fs::symlink_metadata(&recipient_link)
                .expect("link metadata")
                .file_type()
                .is_symlink(),
            "refresh must retain the durable symlink"
        );
        assert_eq!(
            fs::read_to_string(&recipient_target).expect("recipient target"),
            format!("{}\n", generated.recipient)
        );
    }

    #[cfg(unix)]
    #[test]
    fn dangling_symlink_and_fifo_recipient_targets_refuse_without_opening() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().expect("temp");
        let dangling = dir.path().join("dangling-recipients.txt");
        symlink(dir.path().join("missing-target.txt"), &dangling).expect("dangling symlink");
        assert!(
            resolve_recipient_refresh_target(&dangling).is_err(),
            "dangling symlink must fail before rekey"
        );

        let fifo = dir.path().join("recipients.fifo");
        let fifo_c = CString::new(fifo.as_os_str().as_bytes()).expect("fifo path");
        // SAFETY: the C string is NUL-terminated and points to a path in the
        // test-owned temporary directory.
        let result = unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) };
        assert_eq!(
            result,
            0,
            "mkfifo failed: {}",
            std::io::Error::last_os_error()
        );
        let error = resolve_recipient_refresh_target(&fifo).expect_err("FIFO must refuse");
        assert!(error.to_string().contains("regular file"));
    }

    #[test]
    fn rekey_bundle_persists_recipients_metadata() {
        let dir = tempfile::tempdir().expect("temp");
        let input = dir.path().join("plain.json");
        let bundle = dir.path().join("secrets.age");
        let identity_file = dir.path().join("id.txt");
        write_identity_file(&identity_file, TEST_IDENTITY);
        write_secrets_file(&input, &fixture_secrets(), true).expect("write");
        crate::handlers::bundle::handle_bundle_encrypt(crate::cli::BundleEncryptArgs {
            input,
            output: bundle.clone(),
            recipients: RecipientArgs {
                recipients: vec![fixture_recipient_string()],
                recipient_file: None,
                recipient_env_var: None,
            },
        })
        .expect("encrypt");

        handle_rekey(RekeyArgs {
            file: bundle.clone(),
            output: None,
            write_recipients: None,
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
        .expect("rekey bundle");

        let secrets = seclusor_codec::decrypt_bundle(
            &fs::read(&bundle).expect("read"),
            &[fixture_identity()],
        )
        .expect("decrypt");
        assert_eq!(secrets.schema_version, "v1.1.0");
        assert!(secrets.recipients.is_some());
    }

    #[test]
    fn rekey_plaintext_cas_failure_leaves_file_and_skips_notice_commit() {
        use crate::atomic_write::{inject_fault, AtomicFault};
        use crate::error::CliError;
        use crate::handlers::encrypted_write::take_establishment_notice_count;

        let dir = tempfile::tempdir().expect("temp");
        let path = dir.path().join("plain.json");
        let identity_file = dir.path().join("id.txt");
        write_identity_file(&identity_file, TEST_IDENTITY);
        write_secrets_file(&path, &fixture_secrets(), true).expect("write");
        let before = fs::read(&path).expect("before");

        let _ = take_establishment_notice_count(); // reset
        inject_fault(Some(AtomicFault::ForceCasMismatch));
        let err = handle_rekey(RekeyArgs {
            file: path.clone(),
            output: None,
            write_recipients: None,
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
        .expect_err("CAS must fail");
        inject_fault(None);

        assert!(
            matches!(err, CliError::ConcurrentModification { .. }),
            "got {err:?}"
        );
        assert_eq!(
            take_establishment_notice_count(),
            0,
            "establishment notice must not fire when commit fails"
        );
        assert_eq!(fs::read(&path).expect("after"), before);
        // Still plaintext JSON (no silent rekey); no residual siblings.
        let names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names.len(), 2, "only plain.json + identity: {names:?}");
        let still: seclusor_core::SecretsFile =
            serde_json::from_slice(&before).expect("still json");
        assert!(still.recipients.is_none());
        assert_eq!(
            still.projects[0].credentials["API_KEY"].value.as_deref(),
            Some("sk-123")
        );

        // Control: successful rekey does emit exactly one establishment notice.
        let _ = take_establishment_notice_count();
        handle_rekey(RekeyArgs {
            file: path.clone(),
            output: None,
            write_recipients: None,
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
        .expect("rekey success after clear fault");
        assert_eq!(take_establishment_notice_count(), 1);
    }
}
