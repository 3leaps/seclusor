//! seclusor-codec
//!
//! Storage codecs (bundle + inline) and format conversion.

use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use seclusor_core::constants::{
    INLINE_CIPHERTEXT_PREFIX, MAX_BUNDLE_CIPHERTEXT_BYTES, MAX_SECRETS_DOC_BYTES,
};
use seclusor_core::error::sanitize_serde_json_error_message;
use seclusor_core::validate::validate_strict;
use seclusor_core::{SeclusorError, SecretsFile};
use seclusor_crypto::{CryptoError, Identity, Recipient};
use thiserror::Error;

/// Supported storage codecs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageCodec {
    /// Whole-document age ciphertext.
    Bundle,
    /// Structured JSON with per-value inline ciphertext.
    Inline,
}

/// Error type for codec operations.
#[derive(Debug, Error)]
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

    /// Runtime bundle source requires identity files for decryption.
    #[error("bundle input requires at least one identity file (--identity-file)")]
    BundleIdentityRequired,

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
pub fn serialize_canonical_json(secrets: &SecretsFile) -> Result<Vec<u8>> {
    validate_strict(secrets)?;
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
pub fn decrypt_bundle(ciphertext: &[u8], identities: &[Identity]) -> Result<SecretsFile> {
    let plaintext = seclusor_crypto::decrypt(ciphertext, identities)?;
    deserialize_json(&plaintext)
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
    deserialize_json(&plaintext)
}

/// Encrypt plaintext values into inline `sec:age:v1:` values.
pub fn encrypt_inline(secrets: &SecretsFile, recipients: &[Recipient]) -> Result<SecretsFile> {
    validate_strict(secrets)?;

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

    validate_strict(&out)?;
    Ok(out)
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

    validate_strict(&out)?;
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

    validate_strict(&out)?;
    Ok(out)
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
pub fn convert_inline_to_bundle(
    inline: &SecretsFile,
    identities: &[Identity],
    recipients: &[Recipient],
) -> Result<Vec<u8>> {
    let plaintext = decrypt_inline(inline, identities)?;
    encrypt_bundle(&plaintext, recipients)
}

/// Convert inline document to bundle ciphertext using passphrase decryption for inline.
pub fn convert_inline_to_bundle_with_passphrase(
    inline: &SecretsFile,
    decrypt_passphrase: &str,
    recipients: &[Recipient],
) -> Result<Vec<u8>> {
    let plaintext = decrypt_inline_with_passphrase(inline, decrypt_passphrase)?;
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

/// Resolve runtime source bytes as either plaintext JSON or bundle ciphertext.
///
/// Classification is fail-closed: bundle marker detection takes precedence and
/// never falls back to plaintext JSON if bundle decryption fails.
pub fn resolve_runtime_source(input: &[u8], identities: &[Identity]) -> Result<SecretsFile> {
    if is_bundle_ciphertext(input) {
        if identities.is_empty() {
            return Err(CodecError::BundleIdentityRequired);
        }
        return decrypt_bundle(input, identities);
    }

    deserialize_json(input)
}

/// Resolve runtime source from file as either plaintext JSON or bundle ciphertext.
///
/// Uses bounded reads with codec-specific limits before allocation:
/// - bundle marker input: `MAX_BUNDLE_CIPHERTEXT_BYTES`
/// - non-bundle input: `MAX_SECRETS_DOC_BYTES`
pub fn resolve_runtime_source_from_file(
    input_path: impl AsRef<Path>,
    identities: &[Identity],
) -> Result<SecretsFile> {
    let input_path = input_path.as_ref();
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

    let input = read_file_with_limit(input_path, max, kind)?;
    resolve_runtime_source(&input, identities)
}

fn is_bundle_ciphertext(input: &[u8]) -> bool {
    input.starts_with(b"age-encryption.org/")
        || input.starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----")
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
        let json = br#"{"schema_version":"v1.0.0","projects":[{"project_slug":"demo","credentials":{"CLOUDFLARE_API_TOKEN":"cfat_secret_token"}}]}"#;
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

        let inline = encrypt_inline(&secrets, &[recipient]).expect("encrypt should succeed");
        assert!(inline.has_inline_ciphertext());

        let decrypted = decrypt_inline(&inline, &[identity]).expect("decrypt should succeed");
        assert_eq!(decrypted, secrets);
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
    fn resolve_runtime_source_bundle_requires_identity() {
        let secrets = fixture_secrets();
        let ciphertext =
            encrypt_bundle(&secrets, &[fixture_recipient()]).expect("encrypt should succeed");
        let err = resolve_runtime_source(&ciphertext, &[]).expect_err("must fail");
        assert!(matches!(err, CodecError::BundleIdentityRequired));
    }

    #[test]
    fn resolve_runtime_source_bundle_decrypt_failure_is_fail_closed() {
        let err = resolve_runtime_source(
            b"age-encryption.org/v1\nthis is not valid age payload",
            &[fixture_identity()],
        )
        .expect_err("must fail");
        assert!(matches!(err, CodecError::Crypto(_)));
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

        assert_eq!(final_plain, secrets);
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
