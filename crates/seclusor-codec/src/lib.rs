//! seclusor-codec
//!
//! Storage codecs (bundle + inline) and format conversion.

mod mutate;

use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use seclusor_core::constants::{
    INLINE_CIPHERTEXT_PREFIX, MAX_BUNDLE_CIPHERTEXT_BYTES, MAX_SECRETS_DOC_BYTES,
};
use seclusor_core::error::sanitize_serde_json_error_message;
use seclusor_core::validate::{validate_strict, validate_structure_strict};
use seclusor_core::{SeclusorError, SecretsFile};
use seclusor_crypto::{CryptoError, Identity, Recipient};
use thiserror::Error;

pub use mutate::{
    encrypted_value_keys, ensure_no_plaintext_credential_values, mutate_bundle,
    reencrypt_all_inline, set_inline_description, set_inline_value, unset_inline_value,
    BundleMutateResult, DescriptionAction, InlineMutateResult, SetInlineValueOptions,
};

/// Supported storage codecs (conversion surface: bundle ↔ JSON form).
///
/// Note: both plaintext secrets JSON and inline-encrypted JSON map to
/// [`StorageCodec::Inline`] for convert. For read-side classification that
/// distinguishes plaintext vs inline ciphertext, use [`DocumentSource`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageCodec {
    /// Whole-document age ciphertext.
    Bundle,
    /// Structured JSON (plaintext values and/or per-value inline ciphertext).
    Inline,
}

/// How secrets document bytes were classified before optional decryption.
///
/// Used by read-side operations so callers can distinguish full validation
/// from structural-only inspection of encrypted inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocumentSource {
    /// Whole-file age ciphertext (binary or armored header).
    Bundle,
    /// Valid secrets JSON with no `sec:age:v1:` credential values.
    Plaintext,
    /// Valid secrets JSON containing at least one inline-encrypted value.
    Inline,
}

impl DocumentSource {
    /// Machine-readable classification token (`bundle`, `plaintext`, or `inline`).
    pub fn token(self) -> &'static str {
        match self {
            DocumentSource::Bundle => "bundle",
            DocumentSource::Plaintext => "plaintext",
            DocumentSource::Inline => "inline",
        }
    }
}

/// Whether encrypted material was opened for this load.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadMode {
    /// All applicable ciphertext opened (or none present).
    Full,
    /// Structure only; encrypted values left opaque (not decrypted).
    StructuralOnly,
}

impl LoadMode {
    /// Machine-readable mode token (`full` or `structural-only`).
    ///
    /// Single vocabulary source for CLI status lines (validate, structural-only writes).
    pub fn token(self) -> &'static str {
        match self {
            LoadMode::Full => "full",
            LoadMode::StructuralOnly => "structural-only",
        }
    }
}

/// Classified load of a secrets document for read-side operations.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedDocument {
    /// Document contents (may still contain inline ciphertext when mode is
    /// [`LoadMode::StructuralOnly`]).
    pub secrets: SecretsFile,
    /// Input classification.
    pub source: DocumentSource,
    /// Whether ciphertext was opened.
    pub mode: LoadMode,
}

impl ResolvedDocument {
    /// Machine-readable token for validate/list tooling (`full` or `structural-only`).
    pub fn mode_token(&self) -> &'static str {
        self.mode.token()
    }

    /// Machine-readable source classification (`bundle`, `plaintext`, or `inline`).
    pub fn source_token(&self) -> &'static str {
        self.source.token()
    }
}

/// Error type for codec operations.
///
/// Marked `non_exhaustive` so write-side variants can land without breaking
/// downstream exhaustive matches (semver note in CHANGELOG when public).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CodecError {
    /// Unsupported document format for autodetection/parsing.
    #[error("unsupported secrets document format")]
    UnsupportedFormat,

    /// A credential had an invalid shape at runtime.
    #[error("credential {key:?} in project {project:?} must set exactly one of value or ref")]
    InvalidCredentialShape { project: String, key: String },

    /// Decrypted inline payload was not valid UTF-8.
    #[error("credential {key:?} in project {project:?} decrypted to non-utf8 data")]
    NonUtf8InlineValue { project: String, key: String },

    /// Inline encryption refused to skip values that already look encrypted.
    #[error(
        "credential {key:?} in project {project:?} already has inline ciphertext prefix; refusing implicit skip"
    )]
    InlineCiphertextPrefixConflict { project: String, key: String },

    /// Bundle ciphertext file exceeded allowed size before read.
    #[error("bundle ciphertext exceeds maximum size of {max} bytes (actual: {actual})")]
    BundleCiphertextTooLarge { actual: u64, max: u64 },

    /// Runtime bundle source requires an identity for decryption.
    #[error("bundle input requires an identity (--identity-file or --identity-public-key)")]
    BundleIdentityRequired,

    /// Prefixed inline value failed marker/base64/size structural checks.
    ///
    /// Error text intentionally omits the credential value / ciphertext body.
    #[error(
        "credential {key:?} in project {project:?} has invalid inline ciphertext encoding (marker, base64, or size)"
    )]
    InvalidInlineCiphertextShape { project: String, key: String },

    /// Bundle decrypt produced a document that still contains inline ciphertext.
    ///
    /// Nested codecs are not supported: a bundle payload must decrypt to
    /// plaintext secrets JSON so [`LoadMode::Full`] remains truthful.
    #[error(
        "bundle plaintext must not contain nested inline ciphertext (found credential {key:?} in project {project:?}); nested codecs are not supported"
    )]
    NestedInlineInBundle { project: String, key: String },

    /// Targeted mutation could not locate the requested project.
    #[error("project not found: {0}")]
    ProjectNotFound(String),

    /// Targeted mutation could not locate the requested credential.
    #[error("credential {key:?} not found in project {project:?}")]
    CredentialNotFound { project: String, key: String },

    /// Mutation called with an empty recipient set.
    #[error("recipient set is empty; supply at least one age recipient")]
    EmptyRecipientSet,

    /// Passphrase-encrypted (scrypt) data bundles are not supported on this write surface.
    ///
    /// Write paths here are X25519 recipient documents only. Convert to recipient
    /// mode or use passphrase-specific tooling outside this path.
    #[error(
        "passphrase-encrypted (scrypt) bundle writes are not supported; \
         convert to X25519 recipient mode first"
    )]
    ScryptBundleUnsupported,

    /// Document still contains a direct plaintext credential value after mutation.
    ///
    /// Structural ciphertext commits must not place plaintext values into
    /// orphanable temps. Reference credentials are allowed. Names project/key
    /// only — never the value body.
    #[error(
        "refusing ciphertext commit: credential {key:?} in project {project:?} \
         still has a plaintext value; encrypt remaining values or use a \
         fully encrypted document"
    )]
    PlaintextCredentialValuePresent { project: String, key: String },

    /// Core-domain validation or model error.
    #[error(transparent)]
    Core(#[from] SeclusorError),

    /// Crypto-layer error.
    #[error(transparent)]
    Crypto(#[from] CryptoError),

    /// JSON parse/serialize error.
    #[error("json error: {0}")]
    Json(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type alias for codec operations.
pub type Result<T> = std::result::Result<T, CodecError>;

impl From<serde_json::Error> for CodecError {
    fn from(value: serde_json::Error) -> Self {
        CodecError::Json(sanitize_serde_json_error_message(&value.to_string()))
    }
}

/// Serialize a secrets file into canonical JSON bytes for bundle payloads.
///
/// Uses **structure-only** validation: decrypted bundle working copies hold
/// plaintext credential values with optional `recipients` metadata — the
/// JSON-at-rest recipients⇒ciphertext policy does not apply inside age.
pub fn serialize_canonical_json(secrets: &SecretsFile) -> Result<Vec<u8>> {
    validate_structure_strict(secrets)?;
    let mut writer = BoundedJsonWriter::new(MAX_SECRETS_DOC_BYTES);
    match serde_json::to_writer(&mut writer, secrets) {
        Ok(()) => Ok(writer.into_inner()),
        Err(_) if writer.exceeded() => Err(SeclusorError::DocumentTooLarge {
            actual: writer.attempted_size(),
            max: MAX_SECRETS_DOC_BYTES,
        }
        .into()),
        Err(err) => Err(err.into()),
    }
}

/// Deserialize a secrets file from JSON bytes and validate it.
pub fn deserialize_json(input: &[u8]) -> Result<SecretsFile> {
    ensure_document_size(input.len())?;
    let secrets: SecretsFile = serde_json::from_slice(input)?;
    validate_strict(&secrets)?;
    Ok(secrets)
}

/// Autodetect whether input is bundle ciphertext or inline JSON.
pub fn detect_format(input: &[u8]) -> Result<StorageCodec> {
    if is_bundle_ciphertext(input) {
        return Ok(StorageCodec::Bundle);
    }

    ensure_document_size(input.len())?;

    if serde_json::from_slice::<SecretsFile>(input).is_ok() {
        return Ok(StorageCodec::Inline);
    }

    Err(CodecError::UnsupportedFormat)
}

/// Encrypt an entire secrets document as bundle ciphertext.
pub fn encrypt_bundle(secrets: &SecretsFile, recipients: &[Recipient]) -> Result<Vec<u8>> {
    let plaintext = serialize_canonical_json(secrets)?;
    Ok(seclusor_crypto::encrypt(&plaintext, recipients)?)
}

/// Decrypt bundle ciphertext into a secrets document.
///
/// Interior JSON is validated structurally only (values are plaintext by design
/// inside the outer age envelope).
pub fn decrypt_bundle(ciphertext: &[u8], identities: &[Identity]) -> Result<SecretsFile> {
    let plaintext = seclusor_crypto::decrypt(ciphertext, identities)?;
    deserialize_bundle_interior(&plaintext)
}

/// Decrypt passphrase-mode / X25519 bundle interior (structure-only validation).
pub(crate) fn deserialize_bundle_interior(input: &[u8]) -> Result<SecretsFile> {
    ensure_document_size(input.len())?;
    let secrets: SecretsFile = serde_json::from_slice(input)?;
    validate_structure_strict(&secrets)?;
    Ok(secrets)
}

/// Encrypt an entire secrets document with passphrase mode.
pub fn encrypt_bundle_with_passphrase(secrets: &SecretsFile, passphrase: &str) -> Result<Vec<u8>> {
    let plaintext = serialize_canonical_json(secrets)?;
    Ok(seclusor_crypto::encrypt_with_passphrase(
        &plaintext, passphrase,
    )?)
}

/// Decrypt passphrase-encrypted bundle ciphertext into a secrets document.
pub fn decrypt_bundle_with_passphrase(ciphertext: &[u8], passphrase: &str) -> Result<SecretsFile> {
    let plaintext = seclusor_crypto::decrypt_with_passphrase(ciphertext, passphrase)?;
    deserialize_bundle_interior(&plaintext)
}

/// Encrypt plaintext values into inline `sec:age:v1:` values.
///
/// Input may be a structure-validated **working copy** (for example a decrypted
/// bundle with plaintext credential values and optional `recipients` metadata).
/// The encrypted output is validated with the JSON-at-rest policy, and document
/// `recipients` metadata is rewritten to match the encryption target set so
/// metadata stays truthful to the ciphertext recipients.
pub fn encrypt_inline(secrets: &SecretsFile, recipients: &[Recipient]) -> Result<SecretsFile> {
    ensure_nonempty_recipients(recipients)?;
    // Accept decrypted-bundle / plaintext working copies (structure only).
    validate_structure_strict(secrets)?;

    let mut out = secrets.clone();
    for project in &mut out.projects {
        for (key, credential) in &mut project.credentials {
            match (&credential.value, &credential.reference) {
                (Some(value), None) => {
                    if value.starts_with(INLINE_CIPHERTEXT_PREFIX) {
                        return Err(CodecError::InlineCiphertextPrefixConflict {
                            project: project.project_slug.clone(),
                            key: key.clone(),
                        });
                    }

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
            }
        }
    }

    // Metadata must match the set actually used to encrypt values.
    apply_target_recipients_metadata(&mut out, recipients)?;
    // JSON-at-rest: recipients present ⇒ ciphertext values only.
    validate_strict(&out)?;
    Ok(out)
}

fn ensure_nonempty_recipients(recipients: &[Recipient]) -> Result<()> {
    if recipients.is_empty() {
        return Err(CodecError::EmptyRecipientSet);
    }
    Ok(())
}

/// Rewrite document `recipients` (+ schema v1.1.0) to the target encryption set.
fn apply_target_recipients_metadata(
    secrets: &mut SecretsFile,
    recipients: &[Recipient],
) -> Result<()> {
    let as_strings: Vec<String> = recipients.iter().map(|r| r.to_string()).collect();
    secrets
        .establish_recipients(as_strings)
        .map_err(CodecError::from)?;
    Ok(())
}

/// Decrypt inline `sec:age:v1:` values.
pub fn decrypt_inline(secrets: &SecretsFile, identities: &[Identity]) -> Result<SecretsFile> {
    validate_strict(secrets)?;

    let mut out = secrets.clone();
    for project in &mut out.projects {
        for (key, credential) in &mut project.credentials {
            match (&credential.value, &credential.reference) {
                (Some(value), None) => {
                    if !value.starts_with(INLINE_CIPHERTEXT_PREFIX) {
                        continue;
                    }

                    let plaintext = seclusor_crypto::decrypt_inline_value(value, identities)?;
                    let plaintext = String::from_utf8(plaintext).map_err(|_| {
                        CodecError::NonUtf8InlineValue {
                            project: project.project_slug.clone(),
                            key: key.clone(),
                        }
                    })?;
                    credential.value = Some(plaintext);
                }
                (None, Some(_)) => {}
                (Some(_), Some(_)) | (None, None) => {
                    return Err(CodecError::InvalidCredentialShape {
                        project: project.project_slug.clone(),
                        key: key.clone(),
                    });
                }
            }
        }
    }

    // Preserve recipients metadata on the in-memory working copy (structure-only).
    // JSON-at-rest projection (strip recipients) belongs at persistence/export
    // boundaries via [`project_plaintext_at_rest`].
    validate_structure_strict(&out)?;
    Ok(out)
}

/// Decrypt inline values with passphrase mode.
pub fn decrypt_inline_with_passphrase(
    secrets: &SecretsFile,
    passphrase: &str,
) -> Result<SecretsFile> {
    validate_strict(secrets)?;

    let mut out = secrets.clone();
    for project in &mut out.projects {
        for (key, credential) in &mut project.credentials {
            match (&credential.value, &credential.reference) {
                (Some(value), None) => {
                    if !value.starts_with(INLINE_CIPHERTEXT_PREFIX) {
                        continue;
                    }

                    let plaintext =
                        seclusor_crypto::decrypt_inline_value_with_passphrase(value, passphrase)?;
                    let plaintext = String::from_utf8(plaintext).map_err(|_| {
                        CodecError::NonUtf8InlineValue {
                            project: project.project_slug.clone(),
                            key: key.clone(),
                        }
                    })?;
                    credential.value = Some(plaintext);
                }
                (None, Some(_)) => {}
                (Some(_), Some(_)) | (None, None) => {
                    return Err(CodecError::InvalidCredentialShape {
                        project: project.project_slug.clone(),
                        key: key.clone(),
                    });
                }
            }
        }
    }

    validate_structure_strict(&out)?;
    Ok(out)
}

/// Project a decrypted **working copy** to JSON-at-rest plaintext form.
///
/// Clears `recipients` so plaintext credential values remain valid under the
/// recipients⇒ciphertext policy, then runs [`validate_strict`]. Use this at
/// persistence/export boundaries (CLI decrypt writers, FFI/TS file export) —
/// not on public decrypt APIs that return in-memory working copies.
pub fn project_plaintext_at_rest(secrets: &SecretsFile) -> Result<SecretsFile> {
    let mut out = secrets.clone();
    out.recipients = None;
    validate_strict(&out)?;
    Ok(out)
}

/// Serialize a decrypted working copy as pretty JSON-at-rest plaintext bytes.
pub fn serialize_plaintext_at_rest(secrets: &SecretsFile) -> Result<Vec<u8>> {
    let projected = project_plaintext_at_rest(secrets)?;
    let mut data = serde_json::to_vec_pretty(&projected)?;
    if !data.ends_with(b"\n") {
        data.push(b'\n');
    }
    if data.len() > MAX_SECRETS_DOC_BYTES {
        return Err(SeclusorError::DocumentTooLarge {
            actual: data.len(),
            max: MAX_SECRETS_DOC_BYTES,
        }
        .into());
    }
    Ok(data)
}

/// Convert bundle ciphertext to inline-encrypted document.
pub fn convert_bundle_to_inline(
    bundle_ciphertext: &[u8],
    identities: &[Identity],
    recipients: &[Recipient],
) -> Result<SecretsFile> {
    let plaintext = decrypt_bundle(bundle_ciphertext, identities)?;
    encrypt_inline(&plaintext, recipients)
}

/// Convert bundle ciphertext (passphrase mode) to inline-encrypted document.
pub fn convert_bundle_to_inline_with_passphrase(
    bundle_ciphertext: &[u8],
    decrypt_passphrase: &str,
    recipients: &[Recipient],
) -> Result<SecretsFile> {
    let plaintext = decrypt_bundle_with_passphrase(bundle_ciphertext, decrypt_passphrase)?;
    encrypt_inline(&plaintext, recipients)
}

/// Convert inline document to bundle ciphertext.
///
/// After decrypt, document `recipients` is rewritten to the target encryption
/// set so bundle interior metadata matches the outer age recipients.
pub fn convert_inline_to_bundle(
    inline: &SecretsFile,
    identities: &[Identity],
    recipients: &[Recipient],
) -> Result<Vec<u8>> {
    ensure_nonempty_recipients(recipients)?;
    let mut plaintext = decrypt_inline(inline, identities)?;
    apply_target_recipients_metadata(&mut plaintext, recipients)?;
    encrypt_bundle(&plaintext, recipients)
}

/// Convert inline document to bundle ciphertext using passphrase decryption for inline.
pub fn convert_inline_to_bundle_with_passphrase(
    inline: &SecretsFile,
    decrypt_passphrase: &str,
    recipients: &[Recipient],
) -> Result<Vec<u8>> {
    ensure_nonempty_recipients(recipients)?;
    let mut plaintext = decrypt_inline_with_passphrase(inline, decrypt_passphrase)?;
    apply_target_recipients_metadata(&mut plaintext, recipients)?;
    encrypt_bundle(&plaintext, recipients)
}

/// Encrypt bundle and write ciphertext to file.
pub fn encrypt_bundle_to_file(
    secrets: &SecretsFile,
    recipients: &[Recipient],
    output_path: impl AsRef<Path>,
) -> Result<()> {
    let ciphertext = encrypt_bundle(secrets, recipients)?;
    fs::write(output_path, ciphertext)?;
    Ok(())
}

/// Decrypt bundle ciphertext from file.
pub fn decrypt_bundle_from_file(
    input_path: impl AsRef<Path>,
    identities: &[Identity],
) -> Result<SecretsFile> {
    let input_path = input_path.as_ref();
    let actual = fs::metadata(input_path)?.len();
    let max = MAX_BUNDLE_CIPHERTEXT_BYTES as u64;
    if actual > max {
        return Err(CodecError::BundleCiphertextTooLarge { actual, max });
    }

    let ciphertext = read_file_with_limit(input_path, max, ReadLimitKind::BundleCiphertext)?;
    decrypt_bundle(&ciphertext, identities)
}

/// Classify secrets document bytes without decrypting.
///
/// Bundle markers take precedence (fail-closed). Valid JSON is then classified
/// as [`DocumentSource::Inline`] if any credential value carries the inline
/// ciphertext prefix, otherwise [`DocumentSource::Plaintext`].
///
/// Classification is not validation: a document may classify as
/// [`DocumentSource::Inline`] even when inline encodings are malformed. Use
/// [`resolve_runtime_document`] for shape checks and load-mode reporting.
pub fn classify_document_bytes(input: &[u8]) -> Result<DocumentSource> {
    if is_bundle_ciphertext(input) {
        return Ok(DocumentSource::Bundle);
    }

    let secrets = deserialize_json(input)?;
    if secrets.has_inline_ciphertext() {
        Ok(DocumentSource::Inline)
    } else {
        Ok(DocumentSource::Plaintext)
    }
}

/// Resolve runtime source bytes as plaintext JSON, bundle ciphertext, or
/// inline-encrypted JSON, retaining classification metadata.
///
/// Classification is fail-closed: bundle marker detection takes precedence and
/// never falls back to plaintext JSON if bundle decryption fails.
///
/// Mode rules:
/// - Bundle with identities → decrypt outer bundle; reject nested inline
///   ciphertext ([`CodecError::NestedInlineInBundle`]); else [`LoadMode::Full`]
/// - Bundle without identities → [`CodecError::BundleIdentityRequired`]
/// - Plaintext JSON → [`LoadMode::Full`] (nothing to decrypt)
/// - Inline JSON with identities → decrypt inline values, [`LoadMode::Full`]
/// - Inline JSON without identities → validate marker/base64/size for every
///   prefixed value (no decrypt), preserve ciphertext, [`LoadMode::StructuralOnly`]
/// - Mixed plaintext + inline values: accepted; only prefixed values are shape-checked
///   or decrypted (existing runtime leniency)
pub fn resolve_runtime_document(input: &[u8], identities: &[Identity]) -> Result<ResolvedDocument> {
    if is_bundle_ciphertext(input) {
        if identities.is_empty() {
            return Err(CodecError::BundleIdentityRequired);
        }
        let secrets = decrypt_bundle(input, identities)?;
        reject_nested_inline_in_bundle(&secrets)?;
        return Ok(ResolvedDocument {
            secrets,
            source: DocumentSource::Bundle,
            mode: LoadMode::Full,
        });
    }

    let secrets = deserialize_json(input)?;

    if secrets.has_inline_ciphertext() {
        if identities.is_empty() {
            validate_structural_inline_shapes(&secrets)?;
            return Ok(ResolvedDocument {
                secrets,
                source: DocumentSource::Inline,
                mode: LoadMode::StructuralOnly,
            });
        }
        let secrets = decrypt_inline(&secrets, identities)?;
        return Ok(ResolvedDocument {
            secrets,
            source: DocumentSource::Inline,
            mode: LoadMode::Full,
        });
    }

    Ok(ResolvedDocument {
        secrets,
        source: DocumentSource::Plaintext,
        mode: LoadMode::Full,
    })
}

/// Validate every `sec:age:v1:` value for marker/base64/size without decrypting.
///
/// Used for structural-only loads so `validate` cannot report success over
/// malformed ciphertext. Error messages never include credential values.
fn validate_structural_inline_shapes(secrets: &SecretsFile) -> Result<()> {
    for project in &secrets.projects {
        for (key, credential) in &project.credentials {
            let Some(value) = credential.value.as_ref() else {
                continue;
            };
            if !value.starts_with(INLINE_CIPHERTEXT_PREFIX) {
                continue;
            }
            seclusor_crypto::validate_inline_ciphertext_encoding(value).map_err(|err| {
                // Map crypto encoding failures to a codec-level shape error that
                // names project/key but never echoes the ciphertext body.
                let _ = err;
                CodecError::InvalidInlineCiphertextShape {
                    project: project.project_slug.clone(),
                    key: key.clone(),
                }
            })?;
        }
    }
    Ok(())
}

/// Fail closed if a decrypted bundle still contains inline ciphertext markers.
///
/// Nested bundle→inline is unsupported so [`LoadMode::Full`] remains truthful.
fn reject_nested_inline_in_bundle(secrets: &SecretsFile) -> Result<()> {
    for project in &secrets.projects {
        for (key, credential) in &project.credentials {
            if credential.is_inline_encrypted() {
                return Err(CodecError::NestedInlineInBundle {
                    project: project.project_slug.clone(),
                    key: key.clone(),
                });
            }
        }
    }
    Ok(())
}

/// Resolve runtime source bytes as plaintext JSON, bundle ciphertext, or
/// inline-encrypted JSON.
///
/// Thin wrapper over [`resolve_runtime_document`] for callers that only need
/// the document. Prefer the classified API for validate/list mode reporting.
pub fn resolve_runtime_source(input: &[u8], identities: &[Identity]) -> Result<SecretsFile> {
    Ok(resolve_runtime_document(input, identities)?.secrets)
}

/// Resolve and classify a runtime source from file.
///
/// Uses bounded reads with codec-specific limits before allocation:
/// - bundle marker input: `MAX_BUNDLE_CIPHERTEXT_BYTES`
/// - non-bundle input: `MAX_SECRETS_DOC_BYTES`
pub fn resolve_runtime_document_from_file(
    input_path: impl AsRef<Path>,
    identities: &[Identity],
) -> Result<ResolvedDocument> {
    let input = read_runtime_input_bytes(input_path.as_ref())?;
    resolve_runtime_document(&input, identities)
}

/// Resolve runtime source from file as either plaintext JSON or bundle ciphertext.
///
/// Thin wrapper over [`resolve_runtime_document_from_file`].
pub fn resolve_runtime_source_from_file(
    input_path: impl AsRef<Path>,
    identities: &[Identity],
) -> Result<SecretsFile> {
    Ok(resolve_runtime_document_from_file(input_path, identities)?.secrets)
}

fn read_runtime_input_bytes(input_path: &Path) -> Result<Vec<u8>> {
    let is_bundle = detect_bundle_marker_from_file(input_path)?;
    let max = if is_bundle {
        MAX_BUNDLE_CIPHERTEXT_BYTES as u64
    } else {
        MAX_SECRETS_DOC_BYTES as u64
    };
    let kind = if is_bundle {
        ReadLimitKind::BundleCiphertext
    } else {
        ReadLimitKind::Document
    };

    let actual = fs::metadata(input_path)?.len();
    if actual > max {
        return match kind {
            ReadLimitKind::BundleCiphertext => {
                Err(CodecError::BundleCiphertextTooLarge { actual, max })
            }
            ReadLimitKind::Document => Err(SeclusorError::DocumentTooLarge {
                actual: actual as usize,
                max: MAX_SECRETS_DOC_BYTES,
            }
            .into()),
        };
    }

    read_file_with_limit(input_path, max, kind)
}

/// Return true when `input` begins with a binary or armored age bundle marker.
///
/// Bounded prefix probe suitable for classification without reading a full file.
/// Does not validate the remainder of the ciphertext.
pub fn is_bundle_ciphertext(input: &[u8]) -> bool {
    input.starts_with(b"age-encryption.org/")
        || input.starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----")
}

/// Probe only the first bytes of a file for a bundle marker (64-byte prefix).
///
/// Used by write guards so oversized bundles refuse as encrypted targets
/// rather than failing with a document-size error.
pub fn file_has_bundle_marker(path: impl AsRef<Path>) -> Result<bool> {
    detect_bundle_marker_from_file(path.as_ref())
}

fn ensure_document_size(actual: usize) -> Result<()> {
    if actual > MAX_SECRETS_DOC_BYTES {
        return Err(SeclusorError::DocumentTooLarge {
            actual,
            max: MAX_SECRETS_DOC_BYTES,
        }
        .into());
    }
    Ok(())
}

fn detect_bundle_marker_from_file(path: &Path) -> Result<bool> {
    let mut file = std::fs::File::open(path)?;
    let mut prefix = [0u8; 64];
    let read = file.read(&mut prefix)?;
    Ok(is_bundle_ciphertext(&prefix[..read]))
}

#[derive(Debug, Clone, Copy)]
enum ReadLimitKind {
    BundleCiphertext,
    Document,
}

struct BoundedJsonWriter {
    buf: Vec<u8>,
    max: usize,
    overflow_attempt: Option<usize>,
}

impl BoundedJsonWriter {
    fn new(max: usize) -> Self {
        Self {
            buf: Vec::new(),
            max,
            overflow_attempt: None,
        }
    }

    fn exceeded(&self) -> bool {
        self.overflow_attempt.is_some()
    }

    fn attempted_size(&self) -> usize {
        self.overflow_attempt.unwrap_or(self.buf.len())
    }

    fn into_inner(self) -> Vec<u8> {
        self.buf
    }
}

impl Write for BoundedJsonWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let attempted = self.buf.len().saturating_add(bytes.len());
        if attempted > self.max {
            if self.overflow_attempt.is_none() {
                self.overflow_attempt = Some(attempted);
            }
            return Err(std::io::Error::other("document exceeds max size"));
        }

        self.buf.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn read_file_with_limit(path: &Path, max: u64, kind: ReadLimitKind) -> Result<Vec<u8>> {
    let mut file = std::fs::File::open(path)?;
    let mut limited = std::io::Read::by_ref(&mut file).take(max + 1);
    let mut buf = Vec::new();
    limited.read_to_end(&mut buf)?;

    if buf.len() as u64 > max {
        return match kind {
            ReadLimitKind::BundleCiphertext => Err(CodecError::BundleCiphertextTooLarge {
                actual: buf.len() as u64,
                max,
            }),
            ReadLimitKind::Document => Err(SeclusorError::DocumentTooLarge {
                actual: buf.len(),
                max: MAX_SECRETS_DOC_BYTES,
            }
            .into()),
        };
    }

    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const TEST_IDENTITY: &str =
        "AGE-SECRET-KEY-1GQ9778VQXMMJVE8SK7J6VT8UJ4HDQAJUVSFCWCM02D8GEWQ72PVQ2Y5J33";

    fn fixture_identity() -> Identity {
        TEST_IDENTITY.parse().expect("test identity should parse")
    }

    fn fixture_recipient() -> Recipient {
        fixture_identity().to_public()
    }

    fn fixture_secrets() -> SecretsFile {
        let mut credentials = BTreeMap::new();
        credentials.insert(
            "B_KEY".to_string(),
            seclusor_core::Credential::with_value("secret", "b-value"),
        );
        credentials.insert(
            "A_KEY".to_string(),
            seclusor_core::Credential::with_value("secret", "a-value"),
        );
        credentials.insert(
            "REF_ONLY".to_string(),
            seclusor_core::Credential::with_ref("ref", "vault://secret/path"),
        );

        SecretsFile {
            schema_version: "v1.0.0".to_string(),
            env_prefix: Some("APP_".to_string()),
            description: Some("fixture".to_string()),
            recipients: None,
            projects: vec![seclusor_core::Project {
                project_slug: "demo".to_string(),
                description: None,
                credentials,
            }],
        }
    }

    #[test]
    fn canonical_json_is_stable() {
        let secrets = fixture_secrets();
        let a = serialize_canonical_json(&secrets).expect("first serialize should succeed");
        let b = serialize_canonical_json(&secrets).expect("second serialize should succeed");
        assert_eq!(a, b);

        let text = String::from_utf8(a).expect("json should be utf8");
        let idx_a = text.find("\"A_KEY\"").expect("A_KEY present");
        let idx_b = text.find("\"B_KEY\"").expect("B_KEY present");
        assert!(idx_a < idx_b);
    }

    #[test]
    fn deserialize_json_redacts_plaintext_strings_in_errors() {
        let json = br#"{"schema_version":"v1.0.0","projects":"cfat_secret_token"}"#;
        let err = deserialize_json(json).expect_err("must fail");
        let rendered = err.to_string();
        assert!(!rendered.contains("cfat_secret_token"));
        assert!(rendered.contains("string \"<redacted>\""));
    }

    #[test]
    fn bundle_roundtrip_recipient_mode() {
        let secrets = fixture_secrets();
        let recipient = fixture_recipient();
        let identity = fixture_identity();

        let ciphertext = encrypt_bundle(&secrets, &[recipient]).expect("encrypt should succeed");
        let decrypted = decrypt_bundle(&ciphertext, &[identity]).expect("decrypt should succeed");
        assert_eq!(decrypted, secrets);
    }

    #[test]
    fn bundle_roundtrip_passphrase_mode() {
        let secrets = fixture_secrets();
        let passphrase = "correct horse battery staple";

        let ciphertext =
            encrypt_bundle_with_passphrase(&secrets, passphrase).expect("encrypt should succeed");
        let decrypted = decrypt_bundle_with_passphrase(&ciphertext, passphrase)
            .expect("decrypt should succeed");
        assert_eq!(decrypted, secrets);
    }

    #[test]
    fn inline_roundtrip_recipient_mode() {
        let secrets = fixture_secrets();
        let recipient = fixture_recipient();
        let identity = fixture_identity();

        let recipient_str = recipient.to_string();
        let inline = encrypt_inline(&secrets, std::slice::from_ref(&recipient))
            .expect("encrypt should succeed");
        assert!(inline.has_inline_ciphertext());

        let decrypted = decrypt_inline(&inline, std::slice::from_ref(&identity))
            .expect("decrypt should succeed");
        // Working copy preserves recipients; values are plaintext.
        assert_eq!(decrypted.projects, secrets.projects);
        assert_eq!(decrypted.env_prefix, secrets.env_prefix);
        assert_eq!(
            decrypted.recipients.as_deref(),
            Some(std::slice::from_ref(&recipient_str))
        );
        let at_rest = project_plaintext_at_rest(&decrypted).expect("project at rest");
        assert!(at_rest.recipients.is_none());
        assert_eq!(at_rest.projects, secrets.projects);
    }

    #[test]
    fn decrypt_inline_preserves_recipients_on_working_copy() {
        let secrets = fixture_secrets();
        let recipient = fixture_recipient();
        let identity = fixture_identity();
        let inline = encrypt_inline(&secrets, std::slice::from_ref(&recipient)).expect("encrypt");
        assert!(inline.recipients.is_some());
        let working = decrypt_inline(&inline, std::slice::from_ref(&identity)).expect("decrypt");
        assert_eq!(
            working.recipients.as_deref(),
            Some(std::slice::from_ref(&recipient.to_string())),
            "public decrypt_inline must preserve source recipients metadata"
        );
        // Structure-only policy allows plaintext values + recipients in memory.
        seclusor_core::validate::validate_structure_strict(&working).expect("structure ok");
        // JSON-at-rest projection strips recipients for disk/export.
        let projected = project_plaintext_at_rest(&working).expect("project");
        assert!(projected.recipients.is_none());
        seclusor_core::validate::validate_strict(&projected).expect("at-rest ok");
    }

    #[test]
    fn encrypt_inline_rejects_prefixed_plaintext_values() {
        let mut secrets = fixture_secrets();
        secrets.projects[0].credentials.insert(
            "A_KEY".to_string(),
            seclusor_core::Credential::with_value("secret", "sec:age:v1:not-actually-encrypted"),
        );

        let err = encrypt_inline(&secrets, &[fixture_recipient()]).expect_err("must fail");
        assert!(matches!(
            err,
            CodecError::InlineCiphertextPrefixConflict { .. }
        ));
    }

    #[test]
    fn detect_bundle_format() {
        let secrets = fixture_secrets();
        let recipient = fixture_recipient();
        let ciphertext = encrypt_bundle(&secrets, &[recipient]).expect("encrypt should succeed");

        assert_eq!(detect_format(&ciphertext).unwrap(), StorageCodec::Bundle);
    }

    #[test]
    fn detect_inline_format() {
        let secrets = fixture_secrets();
        let json = serde_json::to_vec(&secrets).expect("serialize should succeed");

        assert_eq!(detect_format(&json).unwrap(), StorageCodec::Inline);
    }

    #[test]
    fn detect_unknown_format() {
        let err = detect_format(b"this is not bundle nor json").expect_err("must fail");
        assert!(matches!(err, CodecError::UnsupportedFormat));
    }

    #[test]
    fn resolve_runtime_source_inline_json() {
        let secrets = fixture_secrets();
        let json = serde_json::to_vec(&secrets).expect("serialize should succeed");
        let resolved = resolve_runtime_source(&json, &[]).expect("resolve should succeed");
        assert_eq!(resolved, secrets);
    }

    #[test]
    fn classify_document_bytes_plaintext_vs_inline_vs_bundle() {
        let secrets = fixture_secrets();
        let plain_json = serde_json::to_vec(&secrets).expect("serialize");
        assert_eq!(
            classify_document_bytes(&plain_json).expect("classify plain"),
            DocumentSource::Plaintext
        );

        let encrypted = encrypt_inline(&secrets, &[fixture_recipient()]).expect("inline encrypt");
        let inline_json = serde_json::to_vec(&encrypted).expect("serialize");
        assert_eq!(
            classify_document_bytes(&inline_json).expect("classify inline"),
            DocumentSource::Inline
        );

        let bundle = encrypt_bundle(&secrets, &[fixture_recipient()]).expect("bundle encrypt");
        assert_eq!(
            classify_document_bytes(&bundle).expect("classify bundle"),
            DocumentSource::Bundle
        );

        // detect_format still maps both plain and inline JSON to StorageCodec::Inline
        assert_eq!(detect_format(&plain_json).unwrap(), StorageCodec::Inline);
        assert_eq!(detect_format(&inline_json).unwrap(), StorageCodec::Inline);
    }

    #[test]
    fn classify_document_bytes_rejects_garbage() {
        let err = classify_document_bytes(b"not-a-document").expect_err("must fail");
        assert!(matches!(err, CodecError::Json(_) | CodecError::Core(_)));
    }

    #[test]
    fn resolve_runtime_document_plaintext_is_full() {
        let secrets = fixture_secrets();
        let json = serde_json::to_vec(&secrets).expect("serialize");
        let resolved = resolve_runtime_document(&json, &[]).expect("resolve");
        assert_eq!(resolved.source, DocumentSource::Plaintext);
        assert_eq!(resolved.mode, LoadMode::Full);
        assert_eq!(resolved.mode_token(), "full");
        assert_eq!(resolved.source_token(), "plaintext");
        assert_eq!(resolved.secrets, secrets);
    }

    #[test]
    fn resolve_runtime_document_accepts_v1_1_0_with_recipients() {
        // Read loaders must accept schema v1.1.0 documents with optional recipients.
        // Empty credentials: recipients + plaintext values fail closed (Slice 4).
        let mut secrets = fixture_secrets();
        secrets.projects[0].credentials.clear();
        let recipient = fixture_recipient().to_string();
        secrets
            .establish_recipients(vec![recipient])
            .expect("establish");
        let json = serde_json::to_vec(&secrets).expect("serialize");
        let resolved = resolve_runtime_document(&json, &[]).expect("v1.1.0 resolve");
        assert_eq!(resolved.source, DocumentSource::Plaintext);
        assert_eq!(resolved.mode, LoadMode::Full);
        assert_eq!(
            resolved.secrets.schema_version,
            seclusor_core::constants::SCHEMA_VERSION_V1_1_0
        );
        assert!(resolved.secrets.recipients.is_some());
    }

    #[test]
    fn document_source_token_matches_resolved_source_token() {
        assert_eq!(DocumentSource::Bundle.token(), "bundle");
        assert_eq!(DocumentSource::Plaintext.token(), "plaintext");
        assert_eq!(DocumentSource::Inline.token(), "inline");
    }

    #[test]
    fn resolve_runtime_source_inline_encrypted_with_identities_decrypts() {
        let secrets = fixture_secrets();
        let recipient = fixture_recipient();
        let identity = fixture_identity();
        let encrypted = encrypt_inline(&secrets, &[recipient]).expect("inline encrypt");
        let json = serde_json::to_vec(&encrypted).expect("serialize");

        let classified = resolve_runtime_document(&json, std::slice::from_ref(&identity))
            .expect("should decrypt");
        assert_eq!(classified.source, DocumentSource::Inline);
        assert_eq!(classified.mode, LoadMode::Full);
        assert_eq!(classified.mode_token(), "full");

        let resolved = &classified.secrets;
        // Values should be decrypted
        let project = &resolved.projects[0];
        assert_eq!(
            project.credentials["A_KEY"].value.as_deref(),
            Some("a-value")
        );
        assert_eq!(
            project.credentials["B_KEY"].value.as_deref(),
            Some("b-value")
        );
        // Ref credentials preserved
        assert_eq!(
            project.credentials["REF_ONLY"].reference.as_deref(),
            Some("vault://secret/path")
        );
    }

    #[test]
    fn resolve_runtime_source_inline_encrypted_without_identities_preserves_ciphertext() {
        let secrets = fixture_secrets();
        let recipient = fixture_recipient();
        let encrypted = encrypt_inline(&secrets, &[recipient]).expect("inline encrypt");
        let json = serde_json::to_vec(&encrypted).expect("serialize");

        let classified = resolve_runtime_document(&json, &[]).expect("should succeed");
        assert_eq!(classified.source, DocumentSource::Inline);
        assert_eq!(classified.mode, LoadMode::StructuralOnly);
        assert_eq!(classified.mode_token(), "structural-only");

        let resolved = &classified.secrets;
        // Values should still be inline-encrypted (no identities to decrypt with)
        let project = &resolved.projects[0];
        assert!(project.credentials["A_KEY"]
            .value
            .as_ref()
            .unwrap()
            .starts_with(INLINE_CIPHERTEXT_PREFIX));
    }

    #[test]
    fn resolve_runtime_source_mixed_plaintext_and_inline_with_identities() {
        let mut secrets = fixture_secrets();
        let recipient = fixture_recipient();
        let identity = fixture_identity();

        // Encrypt only B_KEY inline, leave A_KEY as plaintext
        let b_encrypted =
            seclusor_crypto::encrypt_inline_value(b"b-value", std::slice::from_ref(&recipient))
                .expect("inline encrypt value");
        secrets.projects[0]
            .credentials
            .get_mut("B_KEY")
            .unwrap()
            .value = Some(b_encrypted);

        let json = serde_json::to_vec(&secrets).expect("serialize");
        let classified = resolve_runtime_document(&json, std::slice::from_ref(&identity))
            .expect("should decrypt");
        assert_eq!(classified.source, DocumentSource::Inline);
        assert_eq!(classified.mode, LoadMode::Full);

        let project = &classified.secrets.projects[0];
        assert_eq!(
            project.credentials["A_KEY"].value.as_deref(),
            Some("a-value")
        );
        assert_eq!(
            project.credentials["B_KEY"].value.as_deref(),
            Some("b-value")
        );
    }

    #[test]
    fn resolve_runtime_document_mixed_without_identities_is_structural_only() {
        let mut secrets = fixture_secrets();
        let recipient = fixture_recipient();
        let b_encrypted =
            seclusor_crypto::encrypt_inline_value(b"b-value", std::slice::from_ref(&recipient))
                .expect("inline encrypt value");
        secrets.projects[0]
            .credentials
            .get_mut("B_KEY")
            .unwrap()
            .value = Some(b_encrypted);

        let json = serde_json::to_vec(&secrets).expect("serialize");
        let classified = resolve_runtime_document(&json, &[]).expect("mixed structural");
        assert_eq!(classified.source, DocumentSource::Inline);
        assert_eq!(classified.mode, LoadMode::StructuralOnly);
        assert_eq!(
            classified.secrets.projects[0].credentials["A_KEY"]
                .value
                .as_deref(),
            Some("a-value")
        );
        assert!(classified.secrets.projects[0].credentials["B_KEY"]
            .value
            .as_ref()
            .unwrap()
            .starts_with(INLINE_CIPHERTEXT_PREFIX));
    }

    #[test]
    fn resolve_runtime_source_bundle_requires_identity() {
        let secrets = fixture_secrets();
        let ciphertext =
            encrypt_bundle(&secrets, &[fixture_recipient()]).expect("encrypt should succeed");
        let err = resolve_runtime_source(&ciphertext, &[]).expect_err("must fail");
        assert!(matches!(err, CodecError::BundleIdentityRequired));
        let err = resolve_runtime_document(&ciphertext, &[]).expect_err("must fail");
        assert!(matches!(err, CodecError::BundleIdentityRequired));
    }

    #[test]
    fn resolve_runtime_document_bundle_full_with_identity() {
        let secrets = fixture_secrets();
        let ciphertext =
            encrypt_bundle(&secrets, &[fixture_recipient()]).expect("encrypt should succeed");
        let classified =
            resolve_runtime_document(&ciphertext, &[fixture_identity()]).expect("bundle decrypt");
        assert_eq!(classified.source, DocumentSource::Bundle);
        assert_eq!(classified.mode, LoadMode::Full);
        assert_eq!(classified.secrets, secrets);
    }

    #[test]
    fn resolve_runtime_source_bundle_decrypt_failure_is_fail_closed() {
        let err = resolve_runtime_source(
            b"age-encryption.org/v1\nthis is not valid age payload",
            &[fixture_identity()],
        )
        .expect_err("must fail");
        assert!(matches!(err, CodecError::Crypto(_)));

        // Bundle marker must not fall through to JSON parse.
        let err = resolve_runtime_document(
            b"age-encryption.org/v1\nthis is not valid age payload",
            &[fixture_identity()],
        )
        .expect_err("must fail closed");
        assert!(matches!(err, CodecError::Crypto(_)));
        assert!(!matches!(err, CodecError::Json(_)));
    }

    #[test]
    fn resolve_runtime_document_armored_bundle_marker_fail_closed() {
        let err = resolve_runtime_document(
            b"-----BEGIN AGE ENCRYPTED FILE-----\nnot-real\n-----END AGE ENCRYPTED FILE-----\n",
            &[fixture_identity()],
        )
        .expect_err("must fail");
        assert!(matches!(err, CodecError::Crypto(_)));
    }

    #[test]
    fn resolve_runtime_document_from_file_classifies_plaintext() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("secrets.json");
        let secrets = fixture_secrets();
        std::fs::write(&path, serde_json::to_vec(&secrets).expect("ser")).expect("write");

        let classified =
            resolve_runtime_document_from_file(&path, &[]).expect("from file plaintext");
        assert_eq!(classified.source, DocumentSource::Plaintext);
        assert_eq!(classified.mode, LoadMode::Full);
        assert_eq!(classified.secrets, secrets);
    }

    #[test]
    fn resolve_runtime_document_from_file_bundle_requires_identity() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("secrets.age");
        let secrets = fixture_secrets();
        encrypt_bundle_to_file(&secrets, &[fixture_recipient()], &path).expect("write bundle");

        let err = resolve_runtime_document_from_file(&path, &[]).expect_err("no identity");
        assert!(matches!(err, CodecError::BundleIdentityRequired));

        let classified = resolve_runtime_document_from_file(&path, &[fixture_identity()])
            .expect("with identity");
        assert_eq!(classified.source, DocumentSource::Bundle);
        assert_eq!(classified.mode, LoadMode::Full);
    }

    #[test]
    fn structural_only_rejects_malformed_inline_base64() {
        let mut secrets = fixture_secrets();
        secrets.projects[0].credentials.insert(
            "A_KEY".to_string(),
            seclusor_core::Credential::with_value("secret", "sec:age:v1:not base64!"),
        );
        let json = serde_json::to_vec(&secrets).expect("serialize");

        let err = resolve_runtime_document(&json, &[]).expect_err("malformed base64");
        assert!(matches!(
            err,
            CodecError::InvalidInlineCiphertextShape { ref key, .. } if key == "A_KEY"
        ));
        let rendered = err.to_string();
        assert!(!rendered.contains("not base64"));
        assert!(!rendered.contains("sec:age:v1:"));
    }

    #[test]
    fn structural_only_rejects_oversized_credential_value_without_leaking() {
        // Domain validate_strict enforces a per-value size cap at or below the
        // inline ciphertext bound, so encoded-length overflow is unreachable
        // through deserialize_json. Oversized values still fail closed before
        // any Full/structural-only success, without echoing the payload.
        let mut secrets = fixture_secrets();
        let oversized = "A".repeat(seclusor_core::constants::MAX_INLINE_CIPHERTEXT_BYTES + 1);
        let value = format!("{INLINE_CIPHERTEXT_PREFIX}{oversized}");
        secrets.projects[0].credentials.insert(
            "A_KEY".to_string(),
            seclusor_core::Credential::with_value("secret", &value),
        );
        let json = serde_json::to_vec(&secrets).expect("serialize");

        let err = resolve_runtime_document(&json, &[]).expect_err("oversized value");
        assert!(
            matches!(err, CodecError::Core(SeclusorError::Validation(_))),
            "unexpected error: {err:?} / {err}"
        );
        let rendered = err.to_string();
        assert!(!rendered.contains(&oversized[..32]));
        assert!(!rendered.contains(INLINE_CIPHERTEXT_PREFIX));
    }

    #[test]
    fn structural_only_malformed_inline_from_file_path() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("bad-inline.json");
        let mut secrets = fixture_secrets();
        secrets.projects[0].credentials.insert(
            "B_KEY".to_string(),
            seclusor_core::Credential::with_value("secret", "sec:age:v1:%%%"),
        );
        std::fs::write(&path, serde_json::to_vec(&secrets).expect("ser")).expect("write");

        let err = resolve_runtime_document_from_file(&path, &[]).expect_err("from file");
        assert!(matches!(
            err,
            CodecError::InvalidInlineCiphertextShape { ref key, .. } if key == "B_KEY"
        ));
        assert!(!err.to_string().contains("%%%"));
    }

    #[test]
    fn bundle_with_nested_inline_ciphertext_rejected() {
        // Build plaintext doc → encrypt_inline → encrypt that as bundle payload.
        let secrets = fixture_secrets();
        let inline =
            encrypt_inline(&secrets, &[fixture_recipient()]).expect("inline encrypt nested");
        assert!(inline.has_inline_ciphertext());
        let nested_bundle =
            encrypt_bundle(&inline, &[fixture_recipient()]).expect("bundle encrypt nested");

        let err = resolve_runtime_document(&nested_bundle, &[fixture_identity()])
            .expect_err("nested inline in bundle");
        assert!(matches!(err, CodecError::NestedInlineInBundle { .. }));
        let rendered = err.to_string();
        assert!(!rendered.contains(INLINE_CIPHERTEXT_PREFIX));
        // Source classification path must not report Full over unopened values.
        assert!(resolve_runtime_source(&nested_bundle, &[fixture_identity()]).is_err());
    }

    #[test]
    fn bundle_nested_inline_from_file_rejected() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("nested.age");
        let secrets = fixture_secrets();
        let inline =
            encrypt_inline(&secrets, &[fixture_recipient()]).expect("inline encrypt nested");
        encrypt_bundle_to_file(&inline, &[fixture_recipient()], &path).expect("write nested");

        let err = resolve_runtime_document_from_file(&path, &[fixture_identity()])
            .expect_err("nested from file");
        assert!(matches!(err, CodecError::NestedInlineInBundle { .. }));
    }

    #[test]
    fn detect_format_rejects_oversized_non_bundle_input() {
        let oversized = vec![b'{'; MAX_SECRETS_DOC_BYTES + 1];
        let err = detect_format(&oversized).expect_err("must fail");
        assert!(matches!(
            err,
            CodecError::Core(SeclusorError::DocumentTooLarge { .. })
        ));
    }

    #[test]
    fn resolve_runtime_source_from_file_rejects_oversized_document() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("oversized.json");
        let file = std::fs::File::create(&path).expect("create file");
        file.set_len((MAX_SECRETS_DOC_BYTES as u64) + 1)
            .expect("set file length");
        drop(file);

        let err = resolve_runtime_source_from_file(&path, &[]).expect_err("must fail");
        assert!(matches!(
            err,
            CodecError::Core(SeclusorError::DocumentTooLarge { .. })
        ));
    }

    #[test]
    fn deserialize_json_rejects_oversized_input() {
        let oversized = vec![b' '; MAX_SECRETS_DOC_BYTES + 1];
        let err = deserialize_json(&oversized).expect_err("must fail");
        assert!(matches!(
            err,
            CodecError::Core(SeclusorError::DocumentTooLarge { .. })
        ));
    }

    #[test]
    fn serialize_canonical_json_rejects_oversized_output() {
        let mut oversized = fixture_secrets();
        let value = "x".repeat(900_000);
        oversized.projects[0].credentials.insert(
            "BIG_A".to_string(),
            seclusor_core::Credential::with_value("secret", &value),
        );
        oversized.projects[0].credentials.insert(
            "BIG_B".to_string(),
            seclusor_core::Credential::with_value("secret", &value),
        );
        oversized.projects[0].credentials.insert(
            "BIG_C".to_string(),
            seclusor_core::Credential::with_value("secret", &value),
        );

        let err = serialize_canonical_json(&oversized).expect_err("must fail");
        assert!(matches!(
            err,
            CodecError::Core(SeclusorError::DocumentTooLarge { .. })
        ));
    }

    #[test]
    fn convert_bundle_to_inline_and_back() {
        let secrets = fixture_secrets();
        let recipient = fixture_recipient();
        let identity = fixture_identity();

        let bundle =
            encrypt_bundle(&secrets, std::slice::from_ref(&recipient)).expect("bundle encrypt");
        let inline = convert_bundle_to_inline(
            &bundle,
            std::slice::from_ref(&identity),
            std::slice::from_ref(&recipient),
        )
        .expect("bundle->inline");
        let bundle_again = convert_inline_to_bundle(
            &inline,
            std::slice::from_ref(&identity),
            std::slice::from_ref(&recipient),
        )
        .expect("inline->bundle");
        let final_plain =
            decrypt_bundle(&bundle_again, std::slice::from_ref(&identity)).expect("final decrypt");

        // Conversion establishes recipients to the target set (schema v1.1.0).
        assert_eq!(final_plain.projects, secrets.projects);
        assert_eq!(
            final_plain.recipients.as_deref(),
            Some(std::slice::from_ref(&recipient.to_string()))
        );
        assert_eq!(
            final_plain.schema_version,
            seclusor_core::constants::SCHEMA_VERSION_V1_1_0
        );
    }

    #[test]
    fn convert_recipients_bearing_bundle_to_inline_succeeds_and_rewrites_metadata() {
        // Regression: populated bundle with recipients decrypts to a structure-only
        // working copy and must still convert via encrypt_inline (JSON-at-rest policy
        // is enforced on output, not on decrypted input).
        let mut secrets = fixture_secrets();
        let identity = fixture_identity();
        let source_recipient = identity.to_public();
        let target_identity = Identity::generate();
        let target_recipient = target_identity.to_public();

        secrets
            .establish_recipients(vec![source_recipient.to_string()])
            .expect("establish source recipients");
        let bundle = encrypt_bundle(&secrets, std::slice::from_ref(&source_recipient))
            .expect("bundle encrypt");

        let inline = convert_bundle_to_inline(
            &bundle,
            std::slice::from_ref(&identity),
            std::slice::from_ref(&target_recipient),
        )
        .expect("recipients-bearing bundle->inline");

        assert!(inline.has_inline_ciphertext());
        assert_eq!(
            inline.recipients.as_deref(),
            Some(std::slice::from_ref(&target_recipient.to_string())),
            "inline recipients metadata must match conversion target set"
        );
        assert_eq!(
            inline.schema_version,
            seclusor_core::constants::SCHEMA_VERSION_V1_1_0
        );
        assert_ne!(
            inline.recipients.as_ref().unwrap().as_slice(),
            &[source_recipient.to_string()]
        );

        // Reciprocal: inline→bundle rewrites interior metadata to the (same) target set.
        let bundle_again = convert_inline_to_bundle(
            &inline,
            std::slice::from_ref(&target_identity),
            std::slice::from_ref(&target_recipient),
        )
        .expect("inline->bundle with target identity");
        let interior =
            decrypt_bundle(&bundle_again, std::slice::from_ref(&target_identity)).expect("decrypt");
        assert_eq!(
            interior.recipients.as_deref(),
            Some(std::slice::from_ref(&target_recipient.to_string())),
            "bundle interior recipients must match conversion target set"
        );
        assert_eq!(
            interior.projects[0].credentials.len(),
            secrets.projects[0].credentials.len()
        );
    }

    #[test]
    fn file_roundtrip_bundle() {
        let secrets = fixture_secrets();
        let recipient = fixture_recipient();
        let identity = fixture_identity();
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("secrets.age");

        encrypt_bundle_to_file(&secrets, &[recipient], &path).expect("write bundle");
        let decoded = decrypt_bundle_from_file(&path, &[identity]).expect("read bundle");
        assert_eq!(decoded, secrets);
    }

    #[test]
    fn decrypt_bundle_from_file_rejects_oversized_input_before_read() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("oversized.age");
        let file = std::fs::File::create(&path).expect("create file");
        file.set_len((MAX_BUNDLE_CIPHERTEXT_BYTES as u64) + 1)
            .expect("set file length");
        drop(file);

        let err = decrypt_bundle_from_file(&path, &[fixture_identity()]).expect_err("must fail");
        assert!(matches!(err, CodecError::BundleCiphertextTooLarge { .. }));
    }

    #[test]
    fn non_utf8_inline_payload_rejected() {
        let mut secrets = fixture_secrets();
        let recipient = fixture_recipient();
        let identity = fixture_identity();

        let non_utf8 = vec![0xff, 0xfe, 0xfd];
        let inline = seclusor_crypto::encrypt_inline_value(&non_utf8, &[recipient])
            .expect("inline encryption should succeed");
        secrets.projects[0].credentials.insert(
            "A_KEY".to_string(),
            seclusor_core::Credential::with_value("secret", &inline),
        );

        let err = decrypt_inline(&secrets, &[identity]).expect_err("must fail");
        assert!(matches!(err, CodecError::NonUtf8InlineValue { .. }));
    }
}
