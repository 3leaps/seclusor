//! Encrypting write policy for secrets documents.
//!
//! Recipient resolution, establishment coverage, stanza-count tripwire, and
//! atomic ciphertext commit helpers shared by `set`, `import-env`, bundle
//! `unset`/description-only, and `rekey`.

use std::collections::HashSet;
use std::path::Path;

use seclusor_codec::{
    encrypted_value_keys, ensure_no_plaintext_credential_values, mutate_bundle, DocumentSource,
};
use seclusor_core::constants::MAX_SECRETS_DOC_BYTES;
use seclusor_core::validate::{compare_recipient_sets, validate_strict, RecipientSetRelation};
use seclusor_core::{SeclusorError, SecretsFile};
use seclusor_crypto::{Identity, Recipient};
use zeroize::Zeroizing;

use crate::atomic_write::{atomic_write_ciphertext, AtomicWriteOptions};
use crate::cli::RecipientArgs;
use crate::error::{CliError, CliResult};
use crate::io::refuse_encrypted_write;
use crate::resolve::resolve_recipients;

/// Canonical recipient set for an encrypting write.
#[derive(Debug, Clone)]
pub(crate) struct ResolvedWriteRecipients {
    /// Parsed age recipients (normalized unique set).
    pub recipients: Vec<Recipient>,
    /// Sorted public-key strings (document metadata form).
    pub as_strings: Vec<String>,
    /// True when this write must establish or replace document `recipients` metadata.
    pub established: bool,
    /// Relationship between prior metadata and the write target.
    pub relation: RecipientSetRelation,
}

/// Whether any of the three explicit recipient channels is present on the CLI.
pub(crate) fn recipient_channels_present(args: &RecipientArgs) -> bool {
    !args.recipients.is_empty() || args.recipient_file.is_some() || args.recipient_env_var.is_some()
}

/// Resolve the canonical recipient set for an encrypting write.
///
/// | Document metadata | Explicit channels | Behavior |
/// |-------------------|-------------------|----------|
/// | Absent            | Given             | Establish when coverage permits |
/// | Present           | Given             | Equality check (fail loud) |
/// | Present           | Absent            | Metadata is the set |
/// | Absent            | Absent            | Fail closed |
///
/// `coverage_ok` is true when establishment is permitted for this write
/// (bundle always; inline when no untouched encrypted fields remain).
pub(crate) fn resolve_write_recipients(
    document_recipients: Option<&[String]>,
    args: &RecipientArgs,
    coverage_ok: bool,
    allow_mismatch: bool,
) -> CliResult<ResolvedWriteRecipients> {
    let explicit = if recipient_channels_present(args) {
        Some(resolve_recipients(args)?)
    } else {
        None
    };

    match (document_recipients, explicit) {
        (None, None) => Err(CliError::Message(
            "no recipients resolved for encrypting write; provide --recipient, \
             --recipient-file, or --recipient-env-var, or rekey the document to \
             establish recipients metadata first"
                .to_string(),
        )),
        (None, Some(recipients)) => {
            if !coverage_ok {
                return Err(CliError::Message(
                    "cannot establish recipients metadata while untouched encrypted \
                     fields remain; run `seclusor secrets rekey` to normalize the \
                     document to a single recipient set first"
                        .to_string(),
                ));
            }
            let as_strings = recipient_strings(&recipients);
            Ok(ResolvedWriteRecipients {
                recipients,
                as_strings,
                established: true,
                relation: RecipientSetRelation::Indeterminate,
            })
        }
        (Some(meta), None) => {
            let recipients = parse_metadata_recipients(meta)?;
            let as_strings = recipient_strings(&recipients);
            Ok(ResolvedWriteRecipients {
                recipients,
                as_strings,
                established: false,
                relation: RecipientSetRelation::Match,
            })
        }
        (Some(meta), Some(explicit_recipients)) => {
            let meta_recipients = parse_metadata_recipients(meta)?;
            let explicit_strings = recipient_strings(&explicit_recipients);
            let relation = compare_recipient_sets(Some(meta), &explicit_strings);
            if let RecipientSetRelation::Delta { added, removed } = &relation {
                if !allow_mismatch {
                    return Err(CliError::Message(format!(
                        "explicit recipient set does not match document metadata; refusing write \
                         without --allow-recipient-mismatch; use `seclusor secrets rekey` for a \
                         full-document recipient rotation:{}",
                        render_recipient_delta(added, removed)
                    )));
                }
                if !coverage_ok {
                    return Err(CliError::Message(format!(
                        "recipient-set change cannot be applied safely while untouched inline \
                         ciphertext remains; use `seclusor secrets rekey` to rewrite the full \
                         document:{}",
                        render_recipient_delta(added, removed)
                    )));
                }
                return Ok(ResolvedWriteRecipients {
                    recipients: explicit_recipients,
                    as_strings: explicit_strings,
                    established: true,
                    relation,
                });
            }
            // Prefer metadata order (already normalized).
            let as_strings = recipient_strings(&meta_recipients);
            Ok(ResolvedWriteRecipients {
                recipients: meta_recipients,
                as_strings,
                established: false,
                relation,
            })
        }
    }
}

fn parse_metadata_recipients(meta: &[String]) -> CliResult<Vec<Recipient>> {
    let mut out = Vec::with_capacity(meta.len());
    for (index, key) in meta.iter().enumerate() {
        let recipient = key.parse::<Recipient>().map_err(|_| {
            CliError::Message(format!(
                "document recipients[{index}] is not a valid age recipient public key"
            ))
        })?;
        out.push(recipient);
    }
    if out.is_empty() {
        return Err(CliError::Message(
            "document recipients metadata is empty; omit the field or rekey".to_string(),
        ));
    }
    Ok(out)
}

pub(crate) fn recipient_strings(recipients: &[Recipient]) -> Vec<String> {
    let mut keys: Vec<String> = recipients.iter().map(|r| r.to_string()).collect();
    keys.sort();
    keys.dedup();
    keys
}

/// Render a deterministic public-key-only delta for CLI diagnostics.
pub(crate) fn render_recipient_delta(added: &[String], removed: &[String]) -> String {
    let mut rendered = String::new();
    for recipient in added {
        rendered.push_str("\n  +");
        rendered.push_str(recipient);
    }
    for recipient in removed {
        rendered.push_str("\n  -");
        rendered.push_str(recipient);
    }
    rendered
}

/// Establishment coverage for an **inline** write: after the mutation, every
/// encrypted field must be one the write encrypted (no untouched leftovers).
///
/// Call with the set of `(project, key)` pairs the write will encrypt.
pub(crate) fn inline_establishment_coverage_ok(
    before: &SecretsFile,
    keys_this_write_encrypts: &[(String, String)],
) -> bool {
    let before_encrypted: HashSet<(String, String)> =
        encrypted_value_keys(before).into_iter().collect();
    let writing: HashSet<(String, String)> = keys_this_write_encrypts.iter().cloned().collect();
    // Untouched encrypted fields = present before and not rewritten by this write.
    before_encrypted.is_subset(&writing)
}

/// Fail closed when any **prior** encrypted field's X25519 stanza count diverges
/// from `expected_recipients` (cardinality tripwire).
///
/// Used when document `recipients` metadata is present and on **establishment**
/// (value writes must not resize the prior set — only `rekey` may).
/// Green-field docs with no `sec:age:v1:` values make this loop vacuous → first
/// encrypt may establish freely.
///
/// Residual: same-count key swap is not detectable from X25519 headers.
pub(crate) fn ensure_inline_stanza_count_matches(
    secrets: &SecretsFile,
    expected_recipients: usize,
) -> CliResult<()> {
    for (project, key) in encrypted_value_keys(secrets) {
        let value = secrets
            .projects
            .iter()
            .find(|p| p.project_slug == project)
            .and_then(|p| p.credentials.get(&key))
            .and_then(|c| c.value.as_ref())
            .ok_or_else(|| {
                CliError::Message(format!(
                    "internal error: missing encrypted value for {project}/{key}"
                ))
            })?;
        let count =
            seclusor_crypto::count_inline_x25519_recipient_stanzas(value).map_err(|_| {
                CliError::Message(format!(
                    "credential {key:?} in project {project:?} has unreadable age header; \
                 refusing encrypting write (run rekey after repair)"
                ))
            })?;
        if count != expected_recipients {
            return Err(CliError::Message(format!(
                "recipient stanza count mismatch for credential {key:?} in project \
                 {project:?} (header stanzas: {count}, resolved recipients: \
                 {expected_recipients}); refuse write — value writes cannot resize \
                 the recipient set; run `seclusor secrets rekey` to change recipients"
            )));
        }
    }
    Ok(())
}

/// Refuse scrypt (passphrase) data-bundle inputs on encrypting write/rekey paths.
///
/// Call **before** identity decrypt so CLI failures name SC-011 instead of a
/// generic decryption error.
pub(crate) fn refuse_scrypt_bundle_write(ciphertext: &[u8]) -> CliResult<()> {
    if seclusor_crypto::is_scrypt_ciphertext(ciphertext)? {
        return Err(CliError::Message(
            "passphrase-encrypted (scrypt) bundle writes are not supported; \
             SC-011 owns data-passphrase encrypt/decrypt UX — convert to X25519 \
             recipient mode first"
                .to_string(),
        ));
    }
    Ok(())
}

/// Fail closed when a **bundle** ciphertext stanza count diverges from the set.
///
/// On establishment this is explicit cardinality must match the prior
/// header. Resize → rekey only. Residual: same-count key swap not detectable.
pub(crate) fn ensure_bundle_stanza_count_matches(
    ciphertext: &[u8],
    expected_recipients: usize,
) -> CliResult<()> {
    refuse_scrypt_bundle_write(ciphertext)?;
    let count = seclusor_crypto::count_x25519_recipient_stanzas(ciphertext)?;
    if count != expected_recipients {
        return Err(CliError::Message(format!(
            "recipient stanza count mismatch for bundle (header stanzas: {count}, \
             resolved recipients: {expected_recipients}); refuse write — value \
             writes cannot resize the recipient set; run `seclusor secrets rekey` \
             to change recipients"
        )));
    }
    Ok(())
}

/// Commit an inline encrypting mutation: serialize pretty JSON (ciphertext values
/// only), residual-plaintext gate, atomic write + CAS on `prior_bytes`.
pub(crate) fn commit_inline_ciphertext_document(
    path: &Path,
    prior_bytes: &[u8],
    secrets: &SecretsFile,
) -> CliResult<()> {
    validate_strict(secrets)?;
    ensure_no_plaintext_credential_values(secrets)?;

    let mut out = serde_json::to_vec_pretty(secrets)?;
    if !out.ends_with(b"\n") {
        out.push(b'\n');
    }
    if out.len() > MAX_SECRETS_DOC_BYTES {
        return Err(CliError::Core(SeclusorError::DocumentTooLarge {
            actual: out.len(),
            max: MAX_SECRETS_DOC_BYTES,
        }));
    }

    atomic_write_ciphertext(
        path,
        &out,
        AtomicWriteOptions {
            expected_prior_bytes: Some(prior_bytes.to_vec()),
            create_new: false,
        },
    )?;
    Ok(())
}

/// Decrypt→mutate→re-encrypt a bundle and commit with CAS on the original bytes.
///
/// `expected_recipient_count` describes the prior document set: metadata count
/// when present, or the establishing explicit set when metadata is absent.
/// The prior header stanza count must match it (establishment count-guard;
/// heterogeneity tripwire when metadata already present). Bundles always have
/// prior ciphertext (≥1 stanza); there is no green-field bundle via `set`.
pub(crate) fn commit_bundle_mutation<F>(
    path: &Path,
    prior_ciphertext: &[u8],
    identities: &[Identity],
    recipients: &[Recipient],
    expected_recipient_count: usize,
    mutate: F,
) -> CliResult<()>
where
    F: FnOnce(&mut SecretsFile) -> CliResult<()>,
{
    if seclusor_crypto::is_scrypt_ciphertext(prior_ciphertext)? {
        return Err(CliError::Message(
            "passphrase-encrypted (scrypt) bundle writes are not supported; \
             SC-011 owns data-passphrase encrypt/decrypt UX — convert to X25519 \
             recipient mode first"
                .to_string(),
        ));
    }

    ensure_bundle_stanza_count_matches(prior_ciphertext, expected_recipient_count)?;

    let result = mutate_bundle(prior_ciphertext, identities, recipients, |secrets| {
        mutate(secrets).map_err(|e| {
            // Map CLI errors into codec so mutate_bundle can surface them;
            // we re-wrap non-codec paths as Core validation.
            match e {
                CliError::Codec(c) => c,
                CliError::Core(c) => seclusor_codec::CodecError::Core(c),
                other => {
                    seclusor_codec::CodecError::Core(SeclusorError::Validation(other.to_string()))
                }
            }
        })
    })?;

    atomic_write_ciphertext(
        path,
        &result.ciphertext,
        AtomicWriteOptions {
            expected_prior_bytes: Some(prior_ciphertext.to_vec()),
            create_new: false,
        },
    )?;
    Ok(())
}

/// Persist establishment into a working document (**no** stderr — emit only after commit).
pub(crate) fn apply_establishment(
    secrets: &mut SecretsFile,
    as_strings: &[String],
) -> CliResult<()> {
    secrets.establish_recipients(as_strings.to_vec())?;
    Ok(())
}

/// Loud stderr after a successful establishing commit.
pub(crate) fn emit_establishment_notice(as_strings: &[String]) {
    #[cfg(test)]
    ESTABLISHMENT_NOTICE_COUNT.with(|c| c.set(c.get().saturating_add(1)));
    eprintln!("recipient metadata established: {}", as_strings.join(", "));
}

/// Loud degradation notice when no prior recipient metadata was available.
pub(crate) fn emit_recipient_comparison_indeterminate_notice() {
    eprintln!(
        "warning: recipient-set comparison was indeterminate because the input document \
         had no recipients metadata; the age header cannot identify X25519 recipients"
    );
}

/// Emit recipient-policy diagnostics only after a successful write.
pub(crate) fn emit_write_recipient_policy_notices(resolved: &ResolvedWriteRecipients) {
    match &resolved.relation {
        RecipientSetRelation::Match => {}
        RecipientSetRelation::Delta { added, removed } => eprintln!(
            "recipient set change accepted:{}",
            render_recipient_delta(added, removed)
        ),
        RecipientSetRelation::Indeterminate => {
            emit_recipient_comparison_indeterminate_notice();
            emit_establishment_notice(&resolved.as_strings);
        }
    }
}

/// Warn when none of the identities already loaded for a write belongs to the
/// target recipient set.
///
/// This notice is advisory only. Callers must not resolve identities solely to
/// emit it, and recipient-policy failures must be handled before it is called.
pub(crate) fn emit_self_lockout_warning(identities: &[Identity], target_recipients: &[String]) {
    let identity_matches = identities.iter().any(|identity| {
        let public = identity.to_public().to_string();
        target_recipients
            .iter()
            .any(|recipient| recipient == &public)
    });
    if !identity_matches {
        eprintln!(
            "warning: none of the loaded identities corresponds to the target recipient set; \
             this write may produce a document that is not decryptable with the supplied identities"
        );
    }
}

// Test-only: count of establishment notices emitted (for post-commit-only proofs).
#[cfg(test)]
thread_local! {
    static ESTABLISHMENT_NOTICE_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Reset and return the establishment-notice counter (test-only).
#[cfg(test)]
pub(crate) fn take_establishment_notice_count() -> usize {
    ESTABLISHMENT_NOTICE_COUNT.with(|c| c.replace(0))
}

/// Load inline document structure without decrypting values (structural-only path).
pub(crate) fn load_inline_structural(prior_bytes: &[u8]) -> CliResult<SecretsFile> {
    let resolved = seclusor_codec::resolve_runtime_document(prior_bytes, &[])?;
    if resolved.source != DocumentSource::Inline {
        return Err(refuse_encrypted_write(
            Path::new("<inline>"),
            resolved.source,
        ));
    }
    Ok(resolved.secrets)
}

/// Full-load an inline encrypted document: require identities and successfully
/// decrypt/validate every inline ciphertext, then return the **encrypted**
/// working copy (from the same prior bytes) for targeted mutation.
///
/// Wrong/missing identities or undecryptable fields fail closed before mutate.
pub(crate) fn load_inline_full_for_write(
    prior_bytes: &[u8],
    identities: &[Identity],
) -> CliResult<SecretsFile> {
    if identities.is_empty() {
        return Err(CliError::Message(
            "inline encrypting write requires an identity (--identity-file or \
             --identity-public-key) for full validation of encrypted values"
                .to_string(),
        ));
    }
    let full = seclusor_codec::resolve_runtime_document(prior_bytes, identities)?;
    if full.source != DocumentSource::Inline {
        return Err(refuse_encrypted_write(Path::new("<inline>"), full.source));
    }
    if full.mode != seclusor_codec::LoadMode::Full {
        return Err(CliError::Message(
            "inline encrypting write requires a full cryptographic load".to_string(),
        ));
    }
    // Drop decrypted material; retain original encrypted representation for mutate.
    drop(full);
    load_inline_structural(prior_bytes)
}

/// Safe value channels for encrypting `set` (mutually exclusive with each other
/// and with legacy `--value` / `--ref`).
///
/// `value` is moved (not cloned) from CLI args so legacy argv material is owned
/// once inside a zeroizing buffer.
///
/// Deliberately **not** `Debug` — may hold legacy argv plaintext.
#[derive(Default)]
pub(crate) struct ValueChannelArgs {
    pub value: Option<String>,
    pub value_stdin: bool,
    pub value_file: Option<std::path::PathBuf>,
    pub value_env: Option<String>,
    pub reference: Option<String>,
}

/// Resolved material for a set operation (zeroizing when value-bearing).
///
/// Value bodies are UTF-8-validated bytes in a zeroizing buffer from earliest
/// ownership — never cloned into a non-zeroizing `String` intermediate.
///
/// `Debug` is intentionally redacted — never prints value bodies.
pub(crate) enum SetMaterial {
    Value(Zeroizing<Vec<u8>>),
    Reference(String),
}

impl std::fmt::Debug for SetMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SetMaterial::Value(bytes) => f
                .debug_struct("Value")
                .field("len", &bytes.len())
                .field("body", &"<redacted>")
                .finish(),
            SetMaterial::Reference(r) => f.debug_tuple("Reference").field(r).finish(),
        }
    }
}

impl SetMaterial {
    /// Borrow the value as `&str` (UTF-8 was validated at construction).
    pub(crate) fn value_str(&self) -> Option<&str> {
        match self {
            SetMaterial::Value(bytes) => std::str::from_utf8(bytes.as_slice()).ok(),
            SetMaterial::Reference(_) => None,
        }
    }
}

/// Max plaintext value size for set channels (matches inline crypto limit).
pub(crate) const MAX_SET_VALUE_BYTES: usize = seclusor_core::constants::MAX_INLINE_PLAINTEXT_BYTES;

/// Read set material from mutually exclusive channels.
///
/// Legacy `--value` is accepted with a stderr warning. Value bodies never appear
/// in returned errors. Stdin/file reads are bounded before allocation; buffers
/// are zeroizing from earliest ownership with no plaintext `to_vec` clone.
pub(crate) fn resolve_set_material(mut channels: ValueChannelArgs) -> CliResult<SetMaterial> {
    let value_sources = [
        channels.value.is_some(),
        channels.value_stdin,
        channels.value_file.is_some(),
        channels.value_env.is_some(),
    ]
    .iter()
    .filter(|&&v| v)
    .count();
    let has_ref = channels.reference.is_some();

    if value_sources > 1 {
        return Err(CliError::Message(
            "set accepts at most one value channel among --value, --value-stdin, \
             --value-file, and --value-env"
                .to_string(),
        ));
    }
    if value_sources > 0 && has_ref {
        return Err(CliError::Message(
            "set requires exactly one of a value channel or --ref \
             (or --description alone for a description-only edit)"
                .to_string(),
        ));
    }
    if value_sources == 0 && !has_ref {
        return Err(CliError::Message(
            "set requires exactly one of a value channel or --ref \
             (or --description alone for a description-only edit)"
                .to_string(),
        ));
    }

    if let Some(reference) = channels.reference.take() {
        return Ok(SetMaterial::Reference(reference));
    }

    if let Some(v) = channels.value.take() {
        eprintln!(
            "warning: --value places secret material in process argv; prefer \
             --value-stdin, --value-file, or --value-env"
        );
        return Ok(SetMaterial::Value(guard_owned_value_string(v)?));
    }

    if channels.value_stdin {
        return Ok(SetMaterial::Value(read_value_stdin_bounded()?));
    }

    if let Some(path) = channels.value_file.take() {
        return Ok(SetMaterial::Value(read_value_file_bounded(&path)?));
    }

    if let Some(var) = channels.value_env.take() {
        let text = std::env::var(&var).map_err(|_| {
            CliError::Message(format!("value environment variable {var} is not set"))
        })?;
        // Empty allowed for parity with stdin/file/argv.
        return Ok(SetMaterial::Value(guard_owned_value_string(text)?));
    }

    Err(CliError::Message(
        "set requires exactly one of a value channel or --ref".to_string(),
    ))
}

/// Move an owned `String` into zeroizing storage **before** the size check so
/// oversize error paths never drop an ordinary plaintext `String`.
fn guard_owned_value_string(v: String) -> CliResult<Zeroizing<Vec<u8>>> {
    let guarded = Zeroizing::new(v.into_bytes());
    if guarded.len() > MAX_SET_VALUE_BYTES {
        return Err(CliError::Message(format!(
            "value exceeds maximum size of {MAX_SET_VALUE_BYTES} bytes"
        )));
    }
    Ok(guarded)
}

/// Validate UTF-8 while bytes stay in the zeroizing buffer (no plaintext clone).
fn ensure_utf8_zeroizing(bytes: &Zeroizing<Vec<u8>>) -> CliResult<()> {
    std::str::from_utf8(bytes.as_slice())
        .map_err(|_| CliError::Message("value is not valid UTF-8".to_string()))?;
    Ok(())
}

fn read_value_stdin_bounded() -> CliResult<Zeroizing<Vec<u8>>> {
    use std::io::Read;
    let mut limited = std::io::stdin().take((MAX_SET_VALUE_BYTES as u64) + 1);
    let mut bytes = Zeroizing::new(Vec::new());
    limited
        .read_to_end(&mut bytes)
        .map_err(|_| CliError::Message("failed to read value from stdin".to_string()))?;
    if bytes.len() > MAX_SET_VALUE_BYTES {
        return Err(CliError::Message(format!(
            "value exceeds maximum size of {MAX_SET_VALUE_BYTES} bytes"
        )));
    }
    if bytes.ends_with(b"\n") {
        bytes.pop();
        if bytes.ends_with(b"\r") {
            bytes.pop();
        }
    }
    ensure_utf8_zeroizing(&bytes)?;
    Ok(bytes)
}

fn read_value_file_bounded(path: &Path) -> CliResult<Zeroizing<Vec<u8>>> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|_| {
        CliError::Message(format!("failed to read --value-file {}", path.display()))
    })?;
    let mut limited = file.take((MAX_SET_VALUE_BYTES as u64) + 1);
    let mut bytes = Zeroizing::new(Vec::new());
    limited.read_to_end(&mut bytes).map_err(|_| {
        CliError::Message(format!("failed to read --value-file {}", path.display()))
    })?;
    if bytes.len() > MAX_SET_VALUE_BYTES {
        return Err(CliError::Message(format!(
            "value exceeds maximum size of {MAX_SET_VALUE_BYTES} bytes"
        )));
    }
    ensure_utf8_zeroizing(&bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use seclusor_core::{Credential, SecretsFile};

    const TEST_IDENTITY: &str =
        "AGE-SECRET-KEY-1GQ9778VQXMMJVE8SK7J6VT8UJ4HDQAJUVSFCWCM02D8GEWQ72PVQ2Y5J33";

    fn fixture_recipient() -> Recipient {
        TEST_IDENTITY.parse::<Identity>().expect("id").to_public()
    }

    #[test]
    fn coverage_ok_when_rewriting_only_encrypted_field() {
        let r = fixture_recipient();
        let mut secrets = SecretsFile::new("demo");
        let ct = seclusor_crypto::encrypt_inline_value(b"a", std::slice::from_ref(&r)).unwrap();
        secrets.projects[0]
            .credentials
            .insert("A".into(), Credential::with_value("secret", &ct));
        assert!(inline_establishment_coverage_ok(
            &secrets,
            &[("demo".into(), "A".into())]
        ));
    }

    #[test]
    fn coverage_refuses_when_untouched_encrypted_field_remains() {
        let r = fixture_recipient();
        let mut secrets = SecretsFile::new("demo");
        let ct_a = seclusor_crypto::encrypt_inline_value(b"a", std::slice::from_ref(&r)).unwrap();
        let ct_b = seclusor_crypto::encrypt_inline_value(b"b", std::slice::from_ref(&r)).unwrap();
        secrets.projects[0]
            .credentials
            .insert("A".into(), Credential::with_value("secret", &ct_a));
        secrets.projects[0]
            .credentials
            .insert("B".into(), Credential::with_value("secret", &ct_b));
        assert!(!inline_establishment_coverage_ok(
            &secrets,
            &[("demo".into(), "A".into())]
        ));
    }

    #[test]
    fn resolve_equality_fails_on_mismatch() {
        let r = fixture_recipient();
        let meta = vec![r.to_string()];
        // Distinct well-formed age1 key (not the fixture).
        let other = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p".to_string();
        let args = RecipientArgs {
            recipients: vec![other],
            recipient_file: None,
            recipient_env_var: None,
        };
        let err = resolve_write_recipients(Some(&meta), &args, true, false).expect_err("mismatch");
        let message = err.to_string();
        assert!(message.contains("does not match document metadata"));
        assert!(message.contains(&format!("  +{}", args.recipients[0])));
        assert!(message.contains(&format!("  -{}", meta[0])));
        assert!(!message.contains("AGE-SECRET"));
    }

    #[test]
    fn resolve_metadata_only() {
        let r = fixture_recipient();
        let meta = vec![r.to_string()];
        let args = RecipientArgs::default();
        let resolved = resolve_write_recipients(Some(&meta), &args, false, false).expect("meta");
        assert!(!resolved.established);
        assert_eq!(resolved.as_strings, meta);
    }

    #[test]
    fn override_returns_delta_only_when_full_rewrite_coverage_is_safe() {
        let meta = vec![fixture_recipient().to_string()];
        let other = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p";
        let args = RecipientArgs {
            recipients: vec![other.to_string()],
            recipient_file: None,
            recipient_env_var: None,
        };

        let blocked =
            resolve_write_recipients(Some(&meta), &args, false, true).expect_err("partial");
        assert!(blocked.to_string().contains("untouched inline ciphertext"));

        let resolved =
            resolve_write_recipients(Some(&meta), &args, true, true).expect("full rewrite");
        assert!(resolved.established);
        assert_eq!(resolved.as_strings, vec![other.to_string()]);
        assert!(matches!(
            resolved.relation,
            RecipientSetRelation::Delta { .. }
        ));
    }

    #[test]
    fn value_file_exact_limit_and_over_limit() {
        let dir = tempfile::tempdir().expect("temp");
        let exact = dir.path().join("exact.bin");
        let over = dir.path().join("over.bin");
        std::fs::write(&exact, vec![b'a'; MAX_SET_VALUE_BYTES]).expect("write exact");
        std::fs::write(&over, vec![b'a'; MAX_SET_VALUE_BYTES + 1]).expect("write over");

        let ok = read_value_file_bounded(&exact).expect("exact limit ok");
        assert_eq!(ok.len(), MAX_SET_VALUE_BYTES);

        let err = read_value_file_bounded(&over).expect_err("over limit");
        let msg = err.to_string();
        assert!(msg.contains("maximum size"));
        assert!(!msg.contains(&"a".repeat(32)));
    }

    #[test]
    fn value_file_invalid_utf8_redacted() {
        let dir = tempfile::tempdir().expect("temp");
        let path = dir.path().join("bad.bin");
        // Invalid UTF-8 sequence; must not appear in error text.
        std::fs::write(
            &path,
            [0xff, 0xfe, 0xfd, b's', b'e', b'c', b'r', b'e', b't'],
        )
        .expect("write");
        let err = read_value_file_bounded(&path).expect_err("utf8");
        let msg = err.to_string();
        assert!(msg.contains("UTF-8"));
        assert!(!msg.contains("secret"));
        assert!(!format!("{err:?}").contains("secret"));
    }

    #[test]
    fn value_env_empty_allowed() {
        // Empty env is allowed (parity with stdin/file). Keep tiny to avoid
        // ARG_MAX pollution for parallel child-spawn tests.
        std::env::set_var("SECLUSOR_TEST_EMPTY_VAL", "");
        let mat = resolve_set_material(ValueChannelArgs {
            value_env: Some("SECLUSOR_TEST_EMPTY_VAL".into()),
            ..Default::default()
        })
        .expect("empty env");
        std::env::remove_var("SECLUSOR_TEST_EMPTY_VAL");
        assert!(matches!(mat, SetMaterial::Value(v) if v.is_empty()));
    }

    #[test]
    fn guard_owned_value_string_oversize_no_body_in_error() {
        // Shared path for legacy --value and --value-env: size-check after
        // zeroizing, without planting megabyte env vars (ARG_MAX races).
        let big = "x".repeat(MAX_SET_VALUE_BYTES + 1);
        let err = guard_owned_value_string(big).expect_err("oversize");
        let msg = err.to_string();
        assert!(msg.contains("maximum size"));
        assert!(!msg.contains(&"x".repeat(40)));
    }

    #[test]
    fn value_legacy_argv_oversize_guarded_before_refuse() {
        let big = "y".repeat(MAX_SET_VALUE_BYTES + 1);
        let err = resolve_set_material(ValueChannelArgs {
            value: Some(big),
            ..Default::default()
        })
        .expect_err("oversize argv");
        let msg = err.to_string();
        assert!(msg.contains("maximum size"));
        assert!(!msg.contains(&"y".repeat(40)));
    }

    #[test]
    fn value_channel_conflict_refuses() {
        let err = resolve_set_material(ValueChannelArgs {
            value: Some("a".into()),
            value_stdin: true,
            ..Default::default()
        })
        .expect_err("conflict");
        assert!(err.to_string().contains("at most one value channel"));
        assert!(!err.to_string().contains("a\n") || !err.to_string().ends_with('a'));
    }
}
