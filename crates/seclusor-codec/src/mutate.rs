//! Targeted mutation primitives for encrypted secrets documents.
//!
//! # Design
//!
//! - **Mechanics only.** Callers supply an already-resolved, normalized recipient
//!   set. These functions do **not** validate document-level recipient canonicality
//!   or the establishment coverage policy — that is CLI policy.
//! - **Inline determinism.** Untouched `sec:age:v1:` credential values are
//!   preserved byte-identical; only changed values are encrypted.
//! - **Plaintext lifecycle.** Bundle decrypt buffers are wrapped in
//!   [`zeroize::Zeroizing`] at earliest allocation inside the primitive. Inline
//!   value set encrypts only the target field (no decrypt of untouched fields).
//!   Decrypted working documents are never serialized to disk here — callers
//!   own the atomic ciphertext writer.
//! - **Rekey-forward.** [`reencrypt_all_inline`] and [`mutate_bundle`] are the
//!   pieces a full-document rekey command can compose without a second surface.

use seclusor_core::constants::{INLINE_CIPHERTEXT_PREFIX, MAX_BUNDLE_CIPHERTEXT_BYTES};
use seclusor_core::validate::validate_strict;
use seclusor_core::{Credential, SecretsFile};
use seclusor_crypto::{Identity, Recipient};
use zeroize::Zeroizing;

use crate::{deserialize_json, serialize_canonical_json, CodecError, Result};

/// Result of an inline-document mutation that yields ciphertext-stable JSON.
#[derive(Debug, Clone, PartialEq)]
pub struct InlineMutateResult {
    /// Mutated secrets document (may still contain inline ciphertext).
    pub secrets: SecretsFile,
}

/// Result of a bundle mutation: whole-document ciphertext only.
#[derive(Debug, Clone, PartialEq)]
pub struct BundleMutateResult {
    /// Bundle ciphertext for the mutated document.
    pub ciphertext: Vec<u8>,
}

/// List `(project_slug, credential_key)` pairs whose values are inline ciphertext.
///
/// Used by CLI establishment-coverage and stanza cross-check policy without
/// reimplementing `sec:age:v1:` walks outside the codec.
pub fn encrypted_value_keys(secrets: &SecretsFile) -> Vec<(String, String)> {
    let mut keys = Vec::new();
    for project in &secrets.projects {
        for (key, credential) in &project.credentials {
            if credential.is_inline_encrypted() {
                keys.push((project.project_slug.clone(), key.clone()));
            }
        }
    }
    keys
}

/// Fail closed if any credential still carries a **direct plaintext value**.
///
/// Required before committing through the ciphertext-only atomic writer: mixed
/// documents (some `sec:age:v1:` values plus untouched plaintext values) must
/// not place plaintext into an orphanable temp.
///
/// - **Allowed:** inline-encrypted values (`sec:age:v1:…`), reference-only
///   credentials, empty projects.
/// - **Refused:** any `value` that is present and does not use the inline
///   ciphertext prefix.
///
/// Error text names project/key only — never the value body.
pub fn ensure_no_plaintext_credential_values(secrets: &SecretsFile) -> Result<()> {
    for project in &secrets.projects {
        for (key, credential) in &project.credentials {
            let Some(value) = credential.value.as_ref() else {
                continue;
            };
            if !value.starts_with(INLINE_CIPHERTEXT_PREFIX) {
                return Err(CodecError::PlaintextCredentialValuePresent {
                    project: project.project_slug.clone(),
                    key: key.clone(),
                });
            }
        }
    }
    Ok(())
}

/// How [`set_inline_value`] should treat the credential description.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DescriptionAction<'a> {
    /// Leave any existing description unchanged (new credentials stay `None`).
    Preserve,
    /// Replace description (`None` / empty after normalize clears).
    Replace(Option<&'a str>),
}

/// Options for [`set_inline_value`].
#[derive(Debug, Clone, Copy)]
pub struct SetInlineValueOptions<'a> {
    /// When true, insert the credential if missing.
    pub create_if_missing: bool,
    /// Credential type label (`secret` by default at the CLI).
    pub credential_type: &'a str,
    /// Description update policy.
    pub description: DescriptionAction<'a>,
}

impl Default for SetInlineValueOptions<'_> {
    fn default() -> Self {
        Self {
            create_if_missing: false,
            credential_type: "secret",
            description: DescriptionAction::Preserve,
        }
    }
}

/// Set (or replace) one credential **value** in an inline secrets document.
///
/// Encrypts **only** the target value with `recipients`. All other credential
/// values — including existing `sec:age:v1:` strings — are left byte-identical.
///
/// # Preconditions
///
/// - `recipients` is the document's canonical recipient set (caller-validated).
/// - This function does **not** validate recipient canonicality against the
///   document metadata or age headers.
/// - Does **not** decrypt untouched fields.
///
/// # Errors
///
/// - [`CodecError::EmptyRecipientSet`] if `recipients` is empty.
/// - [`CodecError::ProjectNotFound`] / [`CodecError::CredentialNotFound`] when
///   the target does not exist (use create helpers for minting — this primitive
///   is for mutation of an existing credential or insertion via
///   `create_if_missing`).
pub fn set_inline_value(
    secrets: &SecretsFile,
    project_slug: &str,
    key: &str,
    plaintext_value: &str,
    recipients: &[Recipient],
    options: SetInlineValueOptions<'_>,
) -> Result<InlineMutateResult> {
    ensure_recipients(recipients)?;
    validate_strict(secrets)?;

    let mut out = secrets.clone();
    let project = out
        .projects
        .iter_mut()
        .find(|p| p.project_slug == project_slug)
        .ok_or_else(|| CodecError::ProjectNotFound(project_slug.to_string()))?;

    let encrypted = seclusor_crypto::encrypt_inline_value(plaintext_value.as_bytes(), recipients)?;
    let credential_type = if options.credential_type.is_empty() {
        "secret"
    } else {
        options.credential_type
    };

    match project.credentials.get_mut(key) {
        Some(credential) => {
            // Domain parity with `set_credential`: ref→value replacement is allowed.
            // Clear ref and write the new encrypted value.
            credential.reference = None;
            credential.credential_type = credential_type.to_string();
            credential.value = Some(encrypted);
            match options.description {
                DescriptionAction::Preserve => {}
                DescriptionAction::Replace(desc) => {
                    credential.description = seclusor_core::validate::normalize_description(desc);
                }
            }
        }
        None if options.create_if_missing => {
            // `encrypted` is already a `sec:age:v1:` string.
            let mut cred = Credential::with_value(credential_type, &encrypted);
            match options.description {
                DescriptionAction::Preserve => {}
                DescriptionAction::Replace(desc) => {
                    cred.description = seclusor_core::validate::normalize_description(desc);
                }
            }
            project.credentials.insert(key.to_string(), cred);
        }
        None => {
            return Err(CodecError::CredentialNotFound {
                project: project_slug.to_string(),
                key: key.to_string(),
            });
        }
    }

    validate_strict(&out)?;
    assert_untouched_ciphertext_preserved(secrets, &out, project_slug, key)?;
    Ok(InlineMutateResult { secrets: out })
}

/// Remove one credential from an inline document without decrypting any values.
///
/// Untouched ciphertext strings remain byte-identical.
pub fn unset_inline_value(
    secrets: &SecretsFile,
    project_slug: &str,
    key: &str,
) -> Result<InlineMutateResult> {
    validate_strict(secrets)?;
    let mut out = secrets.clone();
    let project = out
        .projects
        .iter_mut()
        .find(|p| p.project_slug == project_slug)
        .ok_or_else(|| CodecError::ProjectNotFound(project_slug.to_string()))?;

    if project.credentials.remove(key).is_none() {
        return Err(CodecError::CredentialNotFound {
            project: project_slug.to_string(),
            key: key.to_string(),
        });
    }

    validate_strict(&out)?;
    assert_untouched_ciphertext_preserved(secrets, &out, project_slug, key)?;
    Ok(InlineMutateResult { secrets: out })
}

/// Update only the description of an existing credential (no crypto).
///
/// Value ciphertext is preserved byte-identical. Missing project/key fails —
/// description-only edits never mint credentials.
pub fn set_inline_description(
    secrets: &SecretsFile,
    project_slug: &str,
    key: &str,
    description: Option<&str>,
) -> Result<InlineMutateResult> {
    validate_strict(secrets)?;
    let mut out = secrets.clone();
    let project = out
        .projects
        .iter_mut()
        .find(|p| p.project_slug == project_slug)
        .ok_or_else(|| CodecError::ProjectNotFound(project_slug.to_string()))?;

    let credential =
        project
            .credentials
            .get_mut(key)
            .ok_or_else(|| CodecError::CredentialNotFound {
                project: project_slug.to_string(),
                key: key.to_string(),
            })?;

    credential.description = seclusor_core::validate::normalize_description(description);
    validate_strict(&out)?;
    assert_untouched_ciphertext_preserved(secrets, &out, "", "")?;
    Ok(InlineMutateResult { secrets: out })
}

/// Decrypt every inline ciphertext value and re-encrypt to `recipients`.
///
/// Rekey-forward primitive for full-document recipient rewrite. Value-write
/// commands must **not** use this for single-field edits (that would churn
/// untouched ciphertext).
pub fn reencrypt_all_inline(
    secrets: &SecretsFile,
    identities: &[Identity],
    recipients: &[Recipient],
) -> Result<InlineMutateResult> {
    ensure_recipients(recipients)?;
    validate_strict(secrets)?;

    let mut out = secrets.clone();
    for project in &mut out.projects {
        for (key, credential) in &mut project.credentials {
            match (&credential.value, &credential.reference) {
                (Some(value), None) if value.starts_with(INLINE_CIPHERTEXT_PREFIX) => {
                    let plaintext =
                        Zeroizing::new(seclusor_crypto::decrypt_inline_value(value, identities)?);
                    let encrypted =
                        seclusor_crypto::encrypt_inline_value(plaintext.as_slice(), recipients)?;
                    credential.value = Some(encrypted);
                }
                (Some(value), None) if !value.starts_with(INLINE_CIPHERTEXT_PREFIX) => {
                    // Plaintext value: encrypt in place for uniform document.
                    let encrypted =
                        seclusor_crypto::encrypt_inline_value(value.as_bytes(), recipients)?;
                    credential.value = Some(encrypted);
                }
                (None, Some(_)) => {}
                (Some(_), Some(_)) | (None, None) => {
                    return Err(CodecError::InvalidCredentialShape {
                        project: project.project_slug.clone(),
                        key: key.clone(),
                    });
                }
                _ => {}
            }
        }
    }

    validate_strict(&out)?;
    Ok(InlineMutateResult { secrets: out })
}

/// Decrypt a bundle, apply `mutate`, re-encrypt to `recipients`.
///
/// Plaintext buffers are [`Zeroizing`] and born/dropped inside this frame.
/// The decrypted [`SecretsFile`] (string residual) is dropped before return;
/// only ciphertext leaves the function.
///
/// # Preconditions
///
/// Caller supplies the canonical recipient set. This function does not
/// validate canonicality.
pub fn mutate_bundle<F>(
    ciphertext: &[u8],
    identities: &[Identity],
    recipients: &[Recipient],
    mutate: F,
) -> Result<BundleMutateResult>
where
    F: FnOnce(&mut SecretsFile) -> Result<()>,
{
    ensure_recipients(recipients)?;
    if identities.is_empty() {
        return Err(CodecError::BundleIdentityRequired);
    }

    if ciphertext.len() > MAX_BUNDLE_CIPHERTEXT_BYTES {
        return Err(CodecError::BundleCiphertextTooLarge {
            actual: ciphertext.len() as u64,
            max: MAX_BUNDLE_CIPHERTEXT_BYTES as u64,
        });
    }

    // Fail closed on passphrase (scrypt) data bundles — X25519 recipient docs only.
    // Uses the age header decoder (binary and armored), not a raw byte scan.
    if seclusor_crypto::is_scrypt_ciphertext(ciphertext)? {
        return Err(CodecError::ScryptBundleUnsupported);
    }

    let plaintext = Zeroizing::new(seclusor_crypto::decrypt(ciphertext, identities)?);
    let mut secrets = deserialize_json(plaintext.as_slice())?;
    // plaintext buffer drops at end of scope; secrets holds residual Strings.
    drop(plaintext);

    mutate(&mut secrets)?;
    validate_strict(&secrets)?;

    let out_plain = Zeroizing::new(serialize_canonical_json(&secrets)?);
    // Drop secrets before encrypt so the residual lives as briefly as possible
    // relative to ciphertext production.
    drop(secrets);

    let out_ct = seclusor_crypto::encrypt(out_plain.as_slice(), recipients)?;
    Ok(BundleMutateResult { ciphertext: out_ct })
}

fn ensure_recipients(recipients: &[Recipient]) -> Result<()> {
    if recipients.is_empty() {
        return Err(CodecError::EmptyRecipientSet);
    }
    Ok(())
}

/// Assert every inline ciphertext string except the optionally mutated key is
/// byte-identical between `before` and `after`.
///
/// Missing projects/keys that still held ciphertext before the mutation fail
/// closed (except the explicitly mutated key on unset).
fn assert_untouched_ciphertext_preserved(
    before: &SecretsFile,
    after: &SecretsFile,
    mutated_project: &str,
    mutated_key: &str,
) -> Result<()> {
    for project in &before.projects {
        for (key, credential) in &project.credentials {
            let Some(before_value) = credential.value.as_ref() else {
                continue;
            };
            if !before_value.starts_with(INLINE_CIPHERTEXT_PREFIX) {
                continue;
            }
            if project.project_slug == mutated_project && key == mutated_key {
                continue;
            }
            let after_project = after
                .projects
                .iter()
                .find(|p| p.project_slug == project.project_slug)
                .ok_or_else(|| {
                    CodecError::Core(seclusor_core::SeclusorError::Validation(format!(
                        "untouched project {:?} disappeared during mutation",
                        project.project_slug
                    )))
                })?;
            let after_cred = after_project.credentials.get(key).ok_or_else(|| {
                CodecError::Core(seclusor_core::SeclusorError::Validation(format!(
                    "untouched credential {key:?} in project {:?} disappeared during mutation",
                    project.project_slug
                )))
            })?;
            let Some(after_value) = after_cred.value.as_ref() else {
                return Err(CodecError::InvalidCredentialShape {
                    project: project.project_slug.clone(),
                    key: key.clone(),
                });
            };
            if after_value != before_value {
                // Internal invariant: surface as a generic validation failure
                // without echoing ciphertext.
                return Err(CodecError::Core(seclusor_core::SeclusorError::Validation(
                    format!(
                        "untouched inline ciphertext changed for credential {key:?} in project {:?}",
                        project.project_slug
                    ),
                )));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use seclusor_core::constants::{SCHEMA_VERSION, SCHEMA_VERSION_V1_1_0};
    use seclusor_core::{Credential, Project, SecretsFile};
    use std::collections::BTreeMap;

    const TEST_IDENTITY: &str =
        "AGE-SECRET-KEY-1GQ9778VQXMMJVE8SK7J6VT8UJ4HDQAJUVSFCWCM02D8GEWQ72PVQ2Y5J33";
    const SENTINEL: &str = "SECLUSOR_PLAINTEXT_SENTINEL_7f3a";

    fn fixture_identity() -> Identity {
        TEST_IDENTITY.parse().expect("test identity")
    }

    fn fixture_recipient() -> Recipient {
        fixture_identity().to_public()
    }

    fn plain_secrets() -> SecretsFile {
        let mut credentials = BTreeMap::new();
        credentials.insert(
            "A_KEY".to_string(),
            Credential::with_value("secret", "a-value"),
        );
        credentials.insert(
            "B_KEY".to_string(),
            Credential::with_value("secret", "b-value"),
        );
        SecretsFile {
            schema_version: SCHEMA_VERSION.to_string(),
            env_prefix: None,
            description: None,
            recipients: None,
            projects: vec![Project {
                project_slug: "demo".to_string(),
                description: None,
                credentials,
            }],
        }
    }

    #[test]
    fn ensure_no_plaintext_credential_values_allows_encrypted_and_refs() {
        let recipient = fixture_recipient();
        let mut secrets = crate::encrypt_inline(&plain_secrets(), std::slice::from_ref(&recipient))
            .expect("encrypt");
        secrets.projects[0].credentials.insert(
            "REF_KEY".to_string(),
            Credential::with_ref("ref", "vault://demo"),
        );
        ensure_no_plaintext_credential_values(&secrets).expect("encrypted+ref ok");
    }

    #[test]
    fn ensure_no_plaintext_credential_values_refuses_plaintext_sentinel() {
        let recipient = fixture_recipient();
        let mut secrets = crate::encrypt_inline(&plain_secrets(), std::slice::from_ref(&recipient))
            .expect("encrypt");
        secrets.projects[0].credentials.insert(
            "PLAIN".to_string(),
            Credential::with_value("secret", SENTINEL),
        );
        let err = ensure_no_plaintext_credential_values(&secrets).expect_err("mixed");
        let rendered = err.to_string();
        assert!(matches!(
            err,
            CodecError::PlaintextCredentialValuePresent { .. }
        ));
        assert!(rendered.contains("PLAIN"));
        assert!(!rendered.contains(SENTINEL));
    }

    #[test]
    fn set_inline_value_preserves_untouched_ciphertext() {
        let recipient = fixture_recipient();
        let identity = fixture_identity();
        let encrypted = crate::encrypt_inline(&plain_secrets(), std::slice::from_ref(&recipient))
            .expect("encrypt fixture");

        let before_a = encrypted.projects[0].credentials["A_KEY"]
            .value
            .clone()
            .unwrap();
        let before_b = encrypted.projects[0].credentials["B_KEY"]
            .value
            .clone()
            .unwrap();

        let result = set_inline_value(
            &encrypted,
            "demo",
            "A_KEY",
            SENTINEL,
            std::slice::from_ref(&recipient),
            SetInlineValueOptions {
                create_if_missing: false,
                ..Default::default()
            },
        )
        .expect("set A_KEY");

        let after_a = result.secrets.projects[0].credentials["A_KEY"]
            .value
            .as_ref()
            .unwrap();
        let after_b = result.secrets.projects[0].credentials["B_KEY"]
            .value
            .as_ref()
            .unwrap();

        assert_ne!(after_a, &before_a, "mutated field must re-encrypt");
        assert_eq!(after_b, &before_b, "untouched ciphertext must be identical");
        assert!(after_a.starts_with(INLINE_CIPHERTEXT_PREFIX));

        // Decrypt mutated field only via full decrypt_inline for assertion.
        let decrypted = crate::decrypt_inline(&result.secrets, &[identity]).expect("decrypt");
        assert_eq!(
            decrypted.projects[0].credentials["A_KEY"].value.as_deref(),
            Some(SENTINEL)
        );
        assert_eq!(
            decrypted.projects[0].credentials["B_KEY"].value.as_deref(),
            Some("b-value")
        );
    }

    #[test]
    fn unset_inline_value_preserves_remaining_ciphertext() {
        let recipient = fixture_recipient();
        let encrypted =
            crate::encrypt_inline(&plain_secrets(), &[recipient]).expect("encrypt fixture");
        let before_b = encrypted.projects[0].credentials["B_KEY"]
            .value
            .clone()
            .unwrap();

        let result = unset_inline_value(&encrypted, "demo", "A_KEY").expect("unset");
        assert!(!result.secrets.projects[0].credentials.contains_key("A_KEY"));
        assert_eq!(
            result.secrets.projects[0].credentials["B_KEY"]
                .value
                .as_ref()
                .unwrap(),
            &before_b
        );
    }

    #[test]
    fn set_inline_description_preserves_all_ciphertext() {
        let recipient = fixture_recipient();
        let encrypted =
            crate::encrypt_inline(&plain_secrets(), &[recipient]).expect("encrypt fixture");
        let before_a = encrypted.projects[0].credentials["A_KEY"]
            .value
            .clone()
            .unwrap();
        let before_b = encrypted.projects[0].credentials["B_KEY"]
            .value
            .clone()
            .unwrap();

        let result =
            set_inline_description(&encrypted, "demo", "A_KEY", Some("note")).expect("desc");
        assert_eq!(
            result.secrets.projects[0].credentials["A_KEY"]
                .description
                .as_deref(),
            Some("note")
        );
        assert_eq!(
            result.secrets.projects[0].credentials["A_KEY"]
                .value
                .as_ref()
                .unwrap(),
            &before_a
        );
        assert_eq!(
            result.secrets.projects[0].credentials["B_KEY"]
                .value
                .as_ref()
                .unwrap(),
            &before_b
        );
    }

    #[test]
    fn mutate_bundle_set_value_roundtrip() {
        let recipient = fixture_recipient();
        let identity = fixture_identity();
        let ct = crate::encrypt_bundle(&plain_secrets(), std::slice::from_ref(&recipient))
            .expect("encrypt");

        let result = mutate_bundle(
            &ct,
            std::slice::from_ref(&identity),
            std::slice::from_ref(&recipient),
            |sf| {
                let cred = sf.projects[0].credentials.get_mut("A_KEY").expect("A_KEY");
                cred.value = Some(SENTINEL.to_string());
                Ok(())
            },
        )
        .expect("mutate");

        // Ciphertext must not contain the plaintext sentinel.
        assert!(!result
            .ciphertext
            .windows(SENTINEL.len())
            .any(|w| w == SENTINEL.as_bytes()));

        let decrypted = crate::decrypt_bundle(&result.ciphertext, &[identity]).expect("decrypt");
        assert_eq!(
            decrypted.projects[0].credentials["A_KEY"].value.as_deref(),
            Some(SENTINEL)
        );
        assert_eq!(
            decrypted.projects[0].credentials["B_KEY"].value.as_deref(),
            Some("b-value")
        );
    }

    #[test]
    fn mutate_bundle_refuses_binary_scrypt() {
        let secrets = plain_secrets();
        let ct = crate::encrypt_bundle_with_passphrase(&secrets, "test-passphrase-not-a-secret")
            .expect("scrypt encrypt");
        assert!(ct.starts_with(b"age-encryption.org/"));
        let err = mutate_bundle(&ct, &[fixture_identity()], &[fixture_recipient()], |_| {
            Ok(())
        })
        .expect_err("must refuse scrypt");
        assert!(matches!(err, CodecError::ScryptBundleUnsupported));
        let msg = err.to_string();
        assert!(msg.contains("passphrase") || msg.contains("scrypt"));
        assert!(msg.contains("recipient"));
        assert!(!msg.contains("a-value"));
        assert!(!format!("{err:?}").contains("a-value"));
    }

    #[test]
    fn mutate_bundle_refuses_ascii_armored_scrypt() {
        use age::secrecy::SecretString;
        use std::io::Write;

        let secrets = plain_secrets();
        let plaintext = serialize_canonical_json(&secrets).expect("serialize");
        let encryptor = age::Encryptor::with_user_passphrase(SecretString::from(
            "test-passphrase-not-a-secret".to_owned(),
        ));
        let mut armored = Vec::new();
        {
            let armor_writer = age::armor::ArmoredWriter::wrap_output(
                &mut armored,
                age::armor::Format::AsciiArmor,
            )
            .expect("armor");
            let mut writer = encryptor.wrap_output(armor_writer).expect("wrap");
            writer.write_all(&plaintext).expect("write");
            writer.finish().and_then(|a| a.finish()).expect("finish");
        }
        assert!(std::str::from_utf8(&armored)
            .unwrap()
            .contains("BEGIN AGE ENCRYPTED FILE"));

        let err = mutate_bundle(
            &armored,
            &[fixture_identity()],
            &[fixture_recipient()],
            |_| Ok(()),
        )
        .expect_err("armored scrypt must refuse with deliberate variant");
        assert!(
            matches!(err, CodecError::ScryptBundleUnsupported),
            "expected ScryptBundleUnsupported, got {err:?}"
        );
        assert!(!err.to_string().contains("a-value"));
    }

    #[test]
    fn mutate_bundle_refuses_oversized_ciphertext() {
        let oversized = vec![0u8; MAX_BUNDLE_CIPHERTEXT_BYTES + 1];
        let err = mutate_bundle(
            &oversized,
            &[fixture_identity()],
            &[fixture_recipient()],
            |_| Ok(()),
        )
        .expect_err("oversized");
        assert!(matches!(err, CodecError::BundleCiphertextTooLarge { .. }));
    }

    #[test]
    fn empty_recipients_refused() {
        let secrets = plain_secrets();
        let err = set_inline_value(
            &secrets,
            "demo",
            "A_KEY",
            "x",
            &[],
            SetInlineValueOptions::default(),
        )
        .expect_err("empty recipients");
        assert!(matches!(err, CodecError::EmptyRecipientSet));
    }

    #[test]
    fn encrypted_value_keys_lists_inline_only() {
        let recipient = fixture_recipient();
        let encrypted =
            crate::encrypt_inline(&plain_secrets(), &[recipient]).expect("encrypt fixture");
        let keys = encrypted_value_keys(&encrypted);
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&("demo".to_string(), "A_KEY".to_string())));
        assert!(keys.contains(&("demo".to_string(), "B_KEY".to_string())));
    }

    #[test]
    fn establish_recipients_rewrites_schema() {
        let mut secrets = plain_secrets();
        let recipient = fixture_recipient().to_string();
        secrets
            .establish_recipients(vec![recipient.clone()])
            .expect("establish");
        assert_eq!(secrets.schema_version, SCHEMA_VERSION_V1_1_0);
        assert_eq!(
            secrets.recipients.as_deref(),
            Some(std::slice::from_ref(&recipient))
        );
        seclusor_core::validate::validate_strict(&secrets).expect("v1.1.0 with recipients");
    }

    #[test]
    fn establish_recipients_normalizes_and_rejects_invalid() {
        let mut secrets = plain_secrets();
        let r1 = fixture_recipient().to_string();
        // Unsorted + duplicate + whitespace should normalize.
        secrets
            .establish_recipients(vec![format!("  {r1}  "), r1.clone(), r1.clone()])
            .expect("normalize");
        assert_eq!(secrets.recipients.as_ref().map(|v| v.len()), Some(1));

        let err = secrets
            .establish_recipients(vec!["not-a-key".into()])
            .expect_err("bad key");
        assert!(err.to_string().contains("not a valid age recipient"));

        let err = secrets.establish_recipients(vec![]).expect_err("empty");
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn v1_1_0_document_accepted_by_deserialize() {
        let recipient = fixture_recipient().to_string();
        let mut secrets = plain_secrets();
        secrets
            .establish_recipients(vec![recipient])
            .expect("establish");
        let json = serde_json::to_vec(&secrets).expect("serialize");
        let loaded = deserialize_json(&json).expect("v1.1.0 must load");
        assert_eq!(loaded.schema_version, SCHEMA_VERSION_V1_1_0);
        assert!(loaded.recipients.is_some());
    }

    #[test]
    fn set_inline_value_ref_to_value_replacement() {
        let recipient = fixture_recipient();
        let mut secrets = plain_secrets();
        secrets.projects[0].credentials.insert(
            "REF_KEY".to_string(),
            Credential::with_ref("ref", "vault://path"),
        );
        // Mixed document: encrypt A/B, leave REF as ref — encrypt_inline skips refs.
        let encrypted =
            crate::encrypt_inline(&secrets, std::slice::from_ref(&recipient)).expect("encrypt");
        // After encrypt_inline, REF_KEY still a ref.
        assert!(encrypted.projects[0].credentials["REF_KEY"].is_ref());
        let before_a = encrypted.projects[0].credentials["A_KEY"]
            .value
            .clone()
            .unwrap();

        let result = set_inline_value(
            &encrypted,
            "demo",
            "REF_KEY",
            SENTINEL,
            std::slice::from_ref(&recipient),
            SetInlineValueOptions {
                create_if_missing: false,
                ..Default::default()
            },
        )
        .expect("ref→value");
        assert!(result.secrets.projects[0].credentials["REF_KEY"]
            .value
            .as_ref()
            .unwrap()
            .starts_with(INLINE_CIPHERTEXT_PREFIX));
        assert!(result.secrets.projects[0].credentials["REF_KEY"]
            .reference
            .is_none());
        assert_eq!(
            result.secrets.projects[0].credentials["A_KEY"]
                .value
                .as_ref()
                .unwrap(),
            &before_a
        );
    }

    #[test]
    fn set_inline_value_multi_project_preserves_other_project_ciphertext() {
        let recipient = fixture_recipient();
        let mut secrets = plain_secrets();
        let mut other_creds = BTreeMap::new();
        other_creds.insert(
            "C_KEY".to_string(),
            Credential::with_value("secret", "c-value"),
        );
        secrets.projects.push(Project {
            project_slug: "other".to_string(),
            description: None,
            credentials: other_creds,
        });
        let encrypted =
            crate::encrypt_inline(&secrets, std::slice::from_ref(&recipient)).expect("encrypt");
        let before_c = encrypted.projects[1].credentials["C_KEY"]
            .value
            .clone()
            .unwrap();
        let before_b = encrypted.projects[0].credentials["B_KEY"]
            .value
            .clone()
            .unwrap();

        let result = set_inline_value(
            &encrypted,
            "demo",
            "A_KEY",
            SENTINEL,
            std::slice::from_ref(&recipient),
            SetInlineValueOptions {
                create_if_missing: false,
                ..Default::default()
            },
        )
        .expect("set");
        assert_eq!(
            result.secrets.projects[1].credentials["C_KEY"]
                .value
                .as_ref()
                .unwrap(),
            &before_c
        );
        assert_eq!(
            result.secrets.projects[0].credentials["B_KEY"]
                .value
                .as_ref()
                .unwrap(),
            &before_b
        );
    }

    #[test]
    fn set_inline_value_create_if_missing_preserves_existing_ciphertext() {
        let recipient = fixture_recipient();
        let encrypted = crate::encrypt_inline(&plain_secrets(), std::slice::from_ref(&recipient))
            .expect("encrypt");
        let before_a = encrypted.projects[0].credentials["A_KEY"]
            .value
            .clone()
            .unwrap();
        let result = set_inline_value(
            &encrypted,
            "demo",
            "NEW_KEY",
            SENTINEL,
            std::slice::from_ref(&recipient),
            SetInlineValueOptions {
                create_if_missing: true,
                ..Default::default()
            },
        )
        .expect("create");
        assert!(result.secrets.projects[0]
            .credentials
            .contains_key("NEW_KEY"));
        assert_eq!(
            result.secrets.projects[0].credentials["A_KEY"]
                .value
                .as_ref()
                .unwrap(),
            &before_a
        );
    }

    #[test]
    fn reencrypt_all_inline_changes_every_ciphertext() {
        let recipient = fixture_recipient();
        let identity = fixture_identity();
        let encrypted = crate::encrypt_inline(&plain_secrets(), std::slice::from_ref(&recipient))
            .expect("encrypt");
        let before_a = encrypted.projects[0].credentials["A_KEY"]
            .value
            .clone()
            .unwrap();
        let before_b = encrypted.projects[0].credentials["B_KEY"]
            .value
            .clone()
            .unwrap();

        let result = reencrypt_all_inline(
            &encrypted,
            std::slice::from_ref(&identity),
            std::slice::from_ref(&recipient),
        )
        .expect("rekey");
        assert_ne!(
            result.secrets.projects[0].credentials["A_KEY"]
                .value
                .as_ref()
                .unwrap(),
            &before_a
        );
        assert_ne!(
            result.secrets.projects[0].credentials["B_KEY"]
                .value
                .as_ref()
                .unwrap(),
            &before_b
        );
        let decrypted = crate::decrypt_inline(&result.secrets, &[identity]).expect("decrypt");
        assert_eq!(
            decrypted.projects[0].credentials["A_KEY"].value.as_deref(),
            Some("a-value")
        );
    }
}
