//! `secrets rekey` — full-document recipient rewrite.
//!
//! Normalizes all encrypted fields to one canonical recipient set, persists
//! schema v1.1.0 `recipients` metadata, and commits via the atomic ciphertext
//! writer with CAS when rewriting in place.

use std::path::Path;

use seclusor_codec::{
    ensure_no_plaintext_credential_values, mutate_bundle, reencrypt_all_inline, DocumentSource,
};
use seclusor_core::constants::MAX_SECRETS_DOC_BYTES;
use seclusor_core::validate::{compare_recipient_sets, validate_strict, RecipientSetRelation};
use seclusor_core::SeclusorError;
use seclusor_crypto::Identity;

use crate::atomic_write::{atomic_write_ciphertext, AtomicWriteOptions};
use crate::cli::RekeyArgs;
use crate::error::{CliError, CliResult};
use crate::handlers::encrypted_write::{
    apply_establishment, emit_establishment_notice, emit_recipient_comparison_indeterminate_notice,
    recipient_strings, refuse_scrypt_bundle_write, render_recipient_delta,
};
use crate::io::{probe_write_target, WriteTargetProbe};
use crate::resolve::{resolve_identities, resolve_recipients};

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
    let new_recipients = resolve_recipients(&args.recipients)?;
    let new_strings = recipient_strings(&new_recipients);

    // Classify target before identity resolution so scrypt data-bundles refuse
    // naming SC-011 even when identity channels are missing/protected.
    let probe = probe_write_target(&args.file)?;
    if let WriteTargetProbe::Encrypted {
        source: DocumentSource::Bundle,
        bytes,
    } = &probe
    {
        refuse_scrypt_bundle_write(bytes)?;
    }

    let identities = resolve_identities(&args.identities, &args.passphrase, true)?;
    let output_path = args.output.as_ref().unwrap_or(&args.file);
    let in_place = paths_equal(output_path, &args.file);

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
                &identities,
                allow_recipient_mismatch,
            )?;
            emit_rekey_self_lockout_warning(&policy_notices);
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
                    &args.file,
                    &out,
                    AtomicWriteOptions {
                        expected_prior_bytes: Some(bytes),
                        create_new: false,
                    },
                )?;
            } else {
                write_new_ciphertext_file(output_path, &out)?;
            }

            let count = seclusor_codec::encrypted_value_keys(&secrets).len();
            emit_rekey_policy_notices(&policy_notices);
            emit_establishment_notice(&new_strings);
            eprintln!("rekeyed {count} inline credential value(s)");
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
                    &identities,
                    allow_recipient_mismatch,
                )
                .map_err(|error| {
                    seclusor_codec::CodecError::Core(SeclusorError::Validation(error.to_string()))
                })?;
                emit_rekey_self_lockout_warning(&notices);
                policy_notices = Some(notices);
                secrets
                    .establish_recipients(new_strings.clone())
                    .map_err(seclusor_codec::CodecError::from)?;
                Ok(())
            })?;

            if in_place {
                eprintln!("warning: overwriting {} in place", args.file.display());
                atomic_write_ciphertext(
                    &args.file,
                    &result.ciphertext,
                    AtomicWriteOptions {
                        expected_prior_bytes: Some(bytes),
                        create_new: false,
                    },
                )?;
            } else {
                write_new_ciphertext_file(output_path, &result.ciphertext)?;
            }

            let policy_notices = policy_notices.ok_or_else(|| {
                CliError::Message("internal error: recipient policy was not evaluated".to_string())
            })?;
            emit_rekey_policy_notices(&policy_notices);
            emit_establishment_notice(&new_strings);
            eprintln!("rekeyed bundle document");
            println!("{}", output_path.display());
            Ok(())
        }
        WriteTargetProbe::Plaintext { mut secrets, bytes } => {
            // Plaintext → encrypt all direct values and establish recipients.
            // CAS is anchored to the exact load-time probe bytes (not a re-read).
            let policy_notices = evaluate_rekey_recipient_policy(
                secrets.recipients.as_deref(),
                &new_strings,
                &identities,
                allow_recipient_mismatch,
            )?;
            emit_rekey_self_lockout_warning(&policy_notices);
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
                    &args.file,
                    &out,
                    AtomicWriteOptions {
                        expected_prior_bytes: Some(bytes),
                        create_new: false,
                    },
                )?;
            } else {
                write_new_ciphertext_file(output_path, &out)?;
            }
            let count = seclusor_codec::encrypted_value_keys(&secrets).len();
            emit_rekey_policy_notices(&policy_notices);
            emit_establishment_notice(&new_strings);
            eprintln!("rekeyed {count} credential value(s) from plaintext document");
            println!("{}", output_path.display());
            Ok(())
        }
        WriteTargetProbe::NotEncrypted(bytes) => {
            let mut secrets = crate::io::secrets_from_bytes(&bytes)?;
            let policy_notices = evaluate_rekey_recipient_policy(
                secrets.recipients.as_deref(),
                &new_strings,
                &identities,
                allow_recipient_mismatch,
            )?;
            emit_rekey_self_lockout_warning(&policy_notices);
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
                    &args.file,
                    &out,
                    AtomicWriteOptions {
                        expected_prior_bytes: Some(bytes),
                        create_new: false,
                    },
                )?;
            } else {
                write_new_ciphertext_file(output_path, &out)?;
            }
            let count = seclusor_codec::encrypted_value_keys(&secrets).len();
            emit_rekey_policy_notices(&policy_notices);
            emit_establishment_notice(&new_strings);
            eprintln!("rekeyed {count} credential value(s)");
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
    self_lockout: bool,
}

fn evaluate_rekey_recipient_policy(
    document_recipients: Option<&[String]>,
    target_recipients: &[String],
    identities: &[Identity],
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

    let self_lockout = !identities.iter().any(|identity| {
        let public = identity.to_public().to_string();
        target_recipients
            .iter()
            .any(|recipient| recipient == &public)
    });

    Ok(RekeyPolicyNotices {
        relation,
        self_lockout,
    })
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

fn emit_rekey_self_lockout_warning(notices: &RekeyPolicyNotices) {
    if notices.self_lockout {
        eprintln!(
            "warning: none of the loaded identities corresponds to the target recipient set; \
             this write may produce a document that is not decryptable with the supplied identities"
        );
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

fn paths_equal(a: &Path, b: &Path) -> bool {
    // Best-effort path equality for --output same as --file.
    a == b
        || a.canonicalize().ok().as_ref() == b.canonicalize().ok().as_ref()
            && a.canonicalize().is_ok()
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
