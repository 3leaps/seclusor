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
use seclusor_core::validate::validate_strict;
use seclusor_core::SeclusorError;

use crate::atomic_write::{atomic_write_ciphertext, AtomicWriteOptions};
use crate::cli::RekeyArgs;
use crate::error::{CliError, CliResult};
use crate::handlers::encrypted_write::{
    apply_establishment, emit_establishment_notice, recipient_strings,
};
use crate::io::{probe_write_target, WriteTargetProbe};
use crate::resolve::{resolve_identities, resolve_recipients};

pub(crate) fn handle_rekey(args: RekeyArgs) -> CliResult<()> {
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
    let identities = resolve_identities(&args.identities, &args.passphrase, true)?;

    let probe = probe_write_target(&args.file)?;
    let output_path = args.output.as_ref().unwrap_or(&args.file);
    let in_place = paths_equal(output_path, &args.file);

    match probe {
        WriteTargetProbe::Encrypted {
            source: DocumentSource::Inline,
            bytes,
        } => {
            let resolved = seclusor_codec::resolve_runtime_document(&bytes, &[])?;
            let mut secrets = resolved.secrets;
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
            emit_establishment_notice(&new_strings);
            eprintln!("rekeyed {count} inline credential value(s)");
            println!("{}", output_path.display());
            Ok(())
        }
        WriteTargetProbe::Encrypted {
            source: DocumentSource::Bundle,
            bytes,
        } => {
            if seclusor_crypto::is_scrypt_ciphertext(&bytes)? {
                return Err(CliError::Message(
                    "passphrase-encrypted (scrypt) bundle rekey is not supported; \
                     SC-011 owns data-passphrase UX"
                        .to_string(),
                ));
            }

            let result = mutate_bundle(&bytes, &identities, &new_recipients, |secrets| {
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

            emit_establishment_notice(&new_strings);
            eprintln!("rekeyed bundle document");
            println!("{}", output_path.display());
            Ok(())
        }
        WriteTargetProbe::Plaintext { mut secrets, bytes } => {
            // Plaintext → encrypt all direct values and establish recipients.
            // CAS is anchored to the exact load-time probe bytes (not a re-read).
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
            emit_establishment_notice(&new_strings);
            eprintln!("rekeyed {count} credential value(s) from plaintext document");
            println!("{}", output_path.display());
            Ok(())
        }
        WriteTargetProbe::NotEncrypted(bytes) => {
            let mut secrets = crate::io::secrets_from_bytes(&bytes)?;
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
        // Multi-field, no metadata — rekey is the migration path.
        let before = fs::read(&inline).expect("before");
        assert!(
            serde_json::from_slice::<seclusor_core::SecretsFile>(&before)
                .unwrap()
                .recipients
                .is_none()
        );

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
