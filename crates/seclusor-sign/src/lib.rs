//! Asset signing envelope support for seclusor.
//!
//! This crate owns the `seclusor.signature.v1` detached envelope contract from
//! DDR-0004. Low-level Ed25519 primitives remain in `seclusor-crypto`.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use seclusor_crypto::{
    generate_signing_keypair, sign, signature_from_bytes, signature_to_bytes, signing_public_key,
    signing_public_key_from_bytes, signing_public_key_to_bytes, signing_secret_key_from_bytes,
    signing_secret_key_to_bytes, verify, CryptoError, Identity, Recipient, SigningSecretKey,
    SIGNATURE_LEN, SIGNING_PUBLIC_KEY_LEN,
};

const SIGNATURE_SCHEMA: &str = "seclusor.signature.v1";
const SIGNING_KEY_SCHEMA: &str = "seclusor.signing-key.v1";
const SIGNING_ALGORITHM: &str = "Ed25519";
const DIGEST_ALGORITHM: &str = "SHA-256";
const DOMAIN_SEPARATOR: &[u8] = b"seclusor.signature.v1\x00";
const MAX_SIGNING_KEY_FILE_BYTES: u64 = 64 * 1024;
const MAX_REPO_ROOT_SEARCH_DEPTH: usize = 32;

/// Result type for asset signing operations.
pub type Result<T> = std::result::Result<T, SignError>;

/// Error type for `seclusor.signature.v1` and signing-key-file operations.
#[derive(Debug, Error)]
pub enum SignError {
    /// Envelope JSON was rejected by the strict parser.
    #[error("signature envelope rejected by strict parser")]
    ParserRejected,

    /// A binary envelope field decoded but had the wrong fixed size.
    #[error("signature envelope binary field has invalid size")]
    BinarySizeRejected,

    /// The envelope public key is 32 bytes but not a valid Ed25519 public key.
    #[error("signature envelope public key is invalid")]
    PublicKeyInvalid,

    /// Asset bytes do not match the signed digest.
    #[error("asset digest does not match signature envelope")]
    AssetDigestMismatch,

    /// Embedded public key and key fingerprint do not match.
    #[error("signature envelope public key does not match key fingerprint")]
    FingerprintMismatch,

    /// Ed25519 signature verification failed.
    #[error("signature verification failed")]
    SignatureInvalid,

    /// Verification requires an expected public key or fingerprint by default.
    #[error("expected public key or fingerprint is required")]
    ExpectedKeyRequired,

    /// Expected key/fingerprint did not match the verified envelope.
    #[error("signature envelope does not match expected key")]
    ExpectedKeyMismatch,

    /// Signing-key file path is blocked by repository-root pathguard.
    #[error(
        "refusing to write signing-key file under repository root: {path} (repo root: {repo_root})"
    )]
    SigningKeyFilePathBlocked { path: PathBuf, repo_root: PathBuf },

    /// Signing-key file already exists.
    #[error("signing-key file already exists: {path}")]
    SigningKeyFileAlreadyExists { path: PathBuf },

    /// Signing-key file exceeded the defensive size limit.
    #[error("signing-key file exceeds maximum size of {max} bytes (actual: {actual})")]
    SigningKeyFileTooLarge { actual: u64, max: u64 },

    /// Signing-key file is not owned by the current user.
    #[error(
        "signing-key file must be owned by the current user (file uid: {file_uid}, current uid: {current_uid})"
    )]
    SigningKeyFileWrongOwner { file_uid: u32, current_uid: u32 },

    /// Signing-key file could not be decrypted or parsed.
    #[error("wrong identity or corrupted signing-key file")]
    SigningKeyFileInvalid,

    /// Crypto-layer error.
    #[error(transparent)]
    Crypto(#[from] CryptoError),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization error.
    #[error("json error")]
    Json,
}

/// Optional signed signer metadata.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SignerMetadata {
    pub label: Option<String>,
    pub claimed_at: Option<String>,
}

/// Parsed `seclusor.signature.v1` envelope with binary fields decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningEnvelope {
    pub digest_value: [u8; 32],
    pub signature: [u8; SIGNATURE_LEN],
    pub public_key: [u8; SIGNING_PUBLIC_KEY_LEN],
    pub key_fingerprint: [u8; 32],
    pub signer: SignerMetadata,
}

/// Options used when creating a detached signature envelope.
#[derive(Debug, Clone, Default)]
pub struct SignOptions {
    pub signer: SignerMetadata,
}

/// Trust inputs for verification.
#[derive(Debug, Clone, Default)]
pub struct VerifyOptions {
    pub expected_public_key: Option<[u8; SIGNING_PUBLIC_KEY_LEN]>,
    pub expected_fingerprint: Option<[u8; 32]>,
    pub trust_embedded_key: bool,
}

/// Successful verification metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verification {
    pub public_key: [u8; SIGNING_PUBLIC_KEY_LEN],
    pub key_fingerprint: [u8; 32],
    pub signer: SignerMetadata,
}

/// Generated signing-key metadata safe to print.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedSigningKey {
    pub public_key: [u8; SIGNING_PUBLIC_KEY_LEN],
    pub key_fingerprint: [u8; 32],
}

#[derive(Serialize)]
struct SigningKeyFile<'a> {
    schema: &'static str,
    algorithm: &'static str,
    secret_key: &'a str,
}

#[derive(Deserialize)]
struct SigningKeyFileOwned {
    schema: String,
    algorithm: String,
    secret_key: String,
}

/// Generate an Ed25519 signing key and write it as an age-encrypted file.
pub fn generate_signing_key_file(
    path: impl AsRef<Path>,
    recipients: &[Recipient],
) -> Result<GeneratedSigningKey> {
    let path = path.as_ref();
    enforce_signing_key_file_pathguard(path)?;

    let keypair = generate_signing_keypair()?;
    let mut secret_key_bytes = signing_secret_key_to_bytes(keypair.secret_key());
    let public_key = signing_public_key_to_bytes(keypair.public_key());
    let key_fingerprint = fingerprint_public_key(&public_key);
    let secret_key_encoded = Zeroizing::new(encode_base64url(&secret_key_bytes));
    secret_key_bytes.zeroize();

    let key_file = SigningKeyFile {
        schema: SIGNING_KEY_SCHEMA,
        algorithm: SIGNING_ALGORITHM,
        secret_key: secret_key_encoded.as_str(),
    };
    let plaintext = Zeroizing::new(serde_json::to_vec(&key_file).map_err(|_| SignError::Json)?);
    let ciphertext = seclusor_crypto::encrypt(&plaintext, recipients)?;

    let mut file = create_new_signing_key_file(path)?;
    file.write_all(&ciphertext)?;
    file.flush()?;

    Ok(GeneratedSigningKey {
        public_key,
        key_fingerprint,
    })
}

/// Load an age-encrypted Ed25519 signing key file.
pub fn load_signing_key_file(
    path: impl AsRef<Path>,
    identities: &[Identity],
) -> Result<SigningSecretKey> {
    let path = path.as_ref();
    seclusor_crypto::assert_secure_permissions(path)?;
    assert_signing_key_file_owner(path)?;
    let ciphertext = read_file_bounded(path, MAX_SIGNING_KEY_FILE_BYTES)?;
    let plaintext = Zeroizing::new(
        seclusor_crypto::decrypt(&ciphertext, identities)
            .map_err(|_| SignError::SigningKeyFileInvalid)?,
    );
    let mut key_file: SigningKeyFileOwned =
        serde_json::from_slice(&plaintext).map_err(|_| SignError::SigningKeyFileInvalid)?;
    if key_file.schema != SIGNING_KEY_SCHEMA || key_file.algorithm != SIGNING_ALGORITHM {
        key_file.secret_key.zeroize();
        return Err(SignError::SigningKeyFileInvalid);
    }
    let mut secret_key = match decode_base64url_strict(&key_file.secret_key) {
        Ok(secret_key) => secret_key,
        Err(_) => {
            key_file.secret_key.zeroize();
            return Err(SignError::SigningKeyFileInvalid);
        }
    };
    key_file.secret_key.zeroize();
    if secret_key.len() != 32 {
        secret_key.zeroize();
        return Err(SignError::SigningKeyFileInvalid);
    }
    let parsed =
        signing_secret_key_from_bytes(&secret_key).map_err(|_| SignError::SigningKeyFileInvalid)?;
    secret_key.zeroize();
    Ok(parsed)
}

/// Sign an asset stream and produce a detached signature envelope.
pub fn sign_asset<R: Read>(
    reader: R,
    secret_key: &SigningSecretKey,
    options: &SignOptions,
) -> Result<SigningEnvelope> {
    validate_signer_metadata(&options.signer)?;
    let digest_value = hash_reader(reader)?;
    let public_key = signing_public_key_to_bytes(&signing_public_key(secret_key));
    let key_fingerprint = fingerprint_public_key(&public_key);
    let mut envelope = SigningEnvelope {
        digest_value,
        signature: [0_u8; SIGNATURE_LEN],
        public_key,
        key_fingerprint,
        signer: options.signer.clone(),
    };
    let payload = canonical_payload_bytes(&envelope)?;
    let signature = sign(secret_key, &payload)?;
    envelope.signature = signature_to_bytes(&signature);
    Ok(envelope)
}

/// Verify an asset stream against a detached signature envelope.
pub fn verify_asset<R: Read>(
    reader: R,
    envelope_json: &[u8],
    options: &VerifyOptions,
) -> Result<Verification> {
    let envelope = parse_envelope(envelope_json)?;

    let public_key = signing_public_key_from_bytes(&envelope.public_key)
        .map_err(|_| SignError::PublicKeyInvalid)?;

    let asset_digest = hash_reader(reader)?;
    if asset_digest.ct_eq(&envelope.digest_value).unwrap_u8() != 1 {
        return Err(SignError::AssetDigestMismatch);
    }

    let derived_fingerprint = fingerprint_public_key(&envelope.public_key);
    if derived_fingerprint
        .ct_eq(&envelope.key_fingerprint)
        .unwrap_u8()
        != 1
    {
        return Err(SignError::FingerprintMismatch);
    }

    let payload = canonical_payload_bytes(&envelope)?;
    let signature =
        signature_from_bytes(&envelope.signature).map_err(|_| SignError::BinarySizeRejected)?;
    verify(&public_key, &payload, &signature).map_err(|_| SignError::SignatureInvalid)?;

    verify_expected_key(&envelope, options)?;

    Ok(Verification {
        public_key: envelope.public_key,
        key_fingerprint: envelope.key_fingerprint,
        signer: envelope.signer,
    })
}

/// Parse a detached signature envelope under DDR-0004 strict JSON rules.
pub fn parse_envelope(input: &[u8]) -> Result<SigningEnvelope> {
    let raw: RawEnvelope = serde_json::from_slice(input).map_err(|_| SignError::ParserRejected)?;
    raw.into_envelope()
}

/// Serialize a detached signature envelope as canonical emitted JSON.
pub fn envelope_to_json_pretty(envelope: &SigningEnvelope) -> Result<String> {
    serde_json::to_string_pretty(&EnvelopeJson::from(envelope)).map_err(|_| SignError::Json)
}

/// Build the DDR-0004 canonical payload bytes for an envelope.
pub fn canonical_payload_bytes(envelope: &SigningEnvelope) -> Result<Vec<u8>> {
    validate_signer_metadata(&envelope.signer)?;
    let mut payload = Vec::with_capacity(256);
    payload.extend_from_slice(DOMAIN_SEPARATOR);
    push_len_prefixed(&mut payload, SIGNATURE_SCHEMA.as_bytes())?;
    push_len_prefixed(&mut payload, SIGNING_ALGORITHM.as_bytes())?;
    push_len_prefixed(&mut payload, DIGEST_ALGORITHM.as_bytes())?;
    push_len_prefixed(&mut payload, &envelope.digest_value)?;
    push_len_prefixed(&mut payload, &envelope.public_key)?;
    push_len_prefixed(&mut payload, &envelope.key_fingerprint)?;
    push_optional_text(&mut payload, envelope.signer.label.as_deref())?;
    push_optional_text(&mut payload, envelope.signer.claimed_at.as_deref())?;
    Ok(payload)
}

/// Return the raw SHA-256 fingerprint for a 32-byte Ed25519 public key.
pub fn fingerprint_public_key(public_key: &[u8; SIGNING_PUBLIC_KEY_LEN]) -> [u8; 32] {
    Sha256::digest(public_key).into()
}

/// Encode bytes as unpadded URL-safe base64.
pub fn encode_base64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode an unpadded URL-safe base64 public key.
pub fn parse_public_key_text(input: &str) -> Result<[u8; SIGNING_PUBLIC_KEY_LEN]> {
    decode_fixed_base64url(input)
}

/// Decode an unpadded URL-safe base64 fingerprint.
pub fn parse_fingerprint_text(input: &str) -> Result<[u8; 32]> {
    decode_fixed_base64url(input)
}

fn verify_expected_key(envelope: &SigningEnvelope, options: &VerifyOptions) -> Result<()> {
    if options.expected_public_key.is_none()
        && options.expected_fingerprint.is_none()
        && !options.trust_embedded_key
    {
        return Err(SignError::ExpectedKeyRequired);
    }

    if let Some(expected_public_key) = &options.expected_public_key {
        if expected_public_key.ct_eq(&envelope.public_key).unwrap_u8() != 1 {
            return Err(SignError::ExpectedKeyMismatch);
        }
    }

    if let Some(expected_fingerprint) = &options.expected_fingerprint {
        if expected_fingerprint
            .ct_eq(&envelope.key_fingerprint)
            .unwrap_u8()
            != 1
        {
            return Err(SignError::ExpectedKeyMismatch);
        }
    }

    Ok(())
}

fn hash_reader<R: Read>(mut reader: R) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    let mut buf = [0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buf)?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(hasher.finalize().into())
}

fn push_len_prefixed(payload: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    let len = u32::try_from(value.len()).map_err(|_| SignError::ParserRejected)?;
    payload.extend_from_slice(&len.to_be_bytes());
    payload.extend_from_slice(value);
    Ok(())
}

fn push_optional_text(payload: &mut Vec<u8>, value: Option<&str>) -> Result<()> {
    match value {
        Some(value) => {
            payload.push(0x01);
            push_len_prefixed(payload, value.as_bytes())
        }
        None => {
            payload.push(0x00);
            Ok(())
        }
    }
}

fn validate_signer_metadata(signer: &SignerMetadata) -> Result<()> {
    if let Some(label) = &signer.label {
        if label
            .chars()
            .next()
            .map(char::is_whitespace)
            .unwrap_or(false)
            || label
                .chars()
                .last()
                .map(char::is_whitespace)
                .unwrap_or(false)
            || label.as_bytes().contains(&0)
        {
            return Err(SignError::ParserRejected);
        }
    }
    if let Some(claimed_at) = &signer.claimed_at {
        if !is_strict_claimed_at(claimed_at) {
            return Err(SignError::ParserRejected);
        }
    }
    Ok(())
}

fn is_strict_claimed_at(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
        || bytes
            .iter()
            .enumerate()
            .any(|(idx, b)| !matches!(idx, 4 | 7 | 10 | 13 | 16 | 19) && !b.is_ascii_digit())
    {
        return false;
    }

    let year = parse_ascii_digits(&bytes[0..4]);
    let month = parse_ascii_digits(&bytes[5..7]);
    let day = parse_ascii_digits(&bytes[8..10]);
    let hour = parse_ascii_digits(&bytes[11..13]);
    let minute = parse_ascii_digits(&bytes[14..16]);
    let second = parse_ascii_digits(&bytes[17..19]);

    (1..=12).contains(&month)
        && day >= 1
        && day <= days_in_month(year, month)
        && hour <= 23
        && minute <= 59
        && second <= 59
}

fn parse_ascii_digits(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0_u32, |acc, b| {
        acc.saturating_mul(10).saturating_add(u32::from(b - b'0'))
    })
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap_year(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

fn decode_fixed_base64url<const N: usize>(input: &str) -> Result<[u8; N]> {
    let decoded = decode_base64url_strict(input)?;
    decoded
        .try_into()
        .map_err(|_| SignError::BinarySizeRejected)
}

fn decode_base64url_strict(input: &str) -> Result<Vec<u8>> {
    if input.is_empty()
        || input
            .bytes()
            .any(|b| !(b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
    {
        return Err(SignError::ParserRejected);
    }
    URL_SAFE_NO_PAD
        .decode(input)
        .map_err(|_| SignError::ParserRejected)
}

fn read_file_bounded(path: &Path, max: u64) -> Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut limited = std::io::Read::by_ref(&mut file).take(max + 1);
    let mut buf = Vec::new();
    limited.read_to_end(&mut buf)?;
    if buf.len() as u64 > max {
        return Err(SignError::SigningKeyFileTooLarge {
            actual: buf.len() as u64,
            max,
        });
    }
    Ok(buf)
}

fn assert_signing_key_file_owner(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let file_uid = fs::metadata(path)?.uid();
        let current_uid = unsafe { libc::getuid() };
        validate_owner_uids(file_uid, current_uid)?;
    }

    #[cfg(not(unix))]
    {
        let _ = path;
    }

    Ok(())
}

#[cfg(unix)]
fn validate_owner_uids(file_uid: u32, current_uid: u32) -> Result<()> {
    if file_uid != current_uid {
        return Err(SignError::SigningKeyFileWrongOwner {
            file_uid,
            current_uid,
        });
    }
    Ok(())
}

fn enforce_signing_key_file_pathguard(path: &Path) -> Result<()> {
    let target = canonicalize_target_path(path)?;
    let target_anchor = target.parent().unwrap_or(target.as_path());
    if let Some(repo_root) = detect_repo_root(target_anchor)? {
        if target.starts_with(&repo_root) {
            return Err(SignError::SigningKeyFilePathBlocked {
                path: target,
                repo_root,
            });
        }
    }

    let cwd = fs::canonicalize(std::env::current_dir()?)?;
    if let Some(repo_root) = detect_repo_root(&cwd)? {
        if target.starts_with(&repo_root) {
            return Err(SignError::SigningKeyFilePathBlocked {
                path: target,
                repo_root,
            });
        }
    }

    Ok(())
}

fn canonicalize_target_path(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };

    let parent = absolute.parent().unwrap_or(Path::new("."));
    let canonical_parent = fs::canonicalize(parent)?;
    Ok(canonical_parent.join(
        absolute
            .file_name()
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?,
    ))
}

fn detect_repo_root(start: &Path) -> Result<Option<PathBuf>> {
    let mut current = fs::canonicalize(start)?;
    for _ in 0..MAX_REPO_ROOT_SEARCH_DEPTH {
        if is_repo_root_marker(&current)? {
            return Ok(Some(current));
        }
        if !current.pop() {
            break;
        }
    }
    Ok(None)
}

fn is_repo_root_marker(dir: &Path) -> Result<bool> {
    Ok(dir.join(".git").exists() || dir.join("Cargo.toml").exists() && dir.join("crates").is_dir())
}

fn create_new_signing_key_file(path: &Path) -> Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|err| {
                if err.kind() == std::io::ErrorKind::AlreadyExists {
                    SignError::SigningKeyFileAlreadyExists {
                        path: path.to_path_buf(),
                    }
                } else {
                    SignError::Io(err)
                }
            })
    }

    #[cfg(not(unix))]
    {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|err| {
                if err.kind() == std::io::ErrorKind::AlreadyExists {
                    SignError::SigningKeyFileAlreadyExists {
                        path: path.to_path_buf(),
                    }
                } else {
                    SignError::Io(err)
                }
            })
    }
}

#[derive(Debug)]
struct RawEnvelope {
    schema: String,
    algorithm: String,
    digest: RawDigest,
    signature: String,
    public_key: String,
    key_fingerprint: String,
    signer: SignerMetadata,
}

impl RawEnvelope {
    fn into_envelope(self) -> Result<SigningEnvelope> {
        if self.schema != SIGNATURE_SCHEMA
            || self.algorithm != SIGNING_ALGORITHM
            || self.digest.algorithm != DIGEST_ALGORITHM
        {
            return Err(SignError::ParserRejected);
        }
        validate_signer_metadata(&self.signer)?;
        Ok(SigningEnvelope {
            digest_value: decode_fixed_base64url(&self.digest.value)?,
            signature: decode_fixed_base64url(&self.signature)?,
            public_key: decode_fixed_base64url(&self.public_key)?,
            key_fingerprint: decode_fixed_base64url(&self.key_fingerprint)?,
            signer: self.signer,
        })
    }
}

#[derive(Debug)]
struct RawDigest {
    algorithm: String,
    value: String,
}

impl<'de> Deserialize<'de> for RawEnvelope {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(RawEnvelopeVisitor)
    }
}

struct RawEnvelopeVisitor;

impl<'de> Visitor<'de> for RawEnvelopeVisitor {
    type Value = RawEnvelope;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a seclusor signature envelope object")
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut seen = HashSet::new();
        let mut schema = None;
        let mut algorithm = None;
        let mut digest = None;
        let mut signature = None;
        let mut public_key = None;
        let mut key_fingerprint = None;
        let mut signer = None;

        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(de::Error::custom("duplicate field"));
            }
            match key.as_str() {
                "schema" => schema = Some(map.next_value()?),
                "algorithm" => algorithm = Some(map.next_value()?),
                "digest" => digest = Some(map.next_value()?),
                "signature" => signature = Some(map.next_value()?),
                "public_key" => public_key = Some(map.next_value()?),
                "key_fingerprint" => key_fingerprint = Some(map.next_value()?),
                "signer" => signer = Some(map.next_value::<RawSigner>()?.0),
                _ => return Err(de::Error::unknown_field(&key, ENVELOPE_FIELDS)),
            }
        }

        Ok(RawEnvelope {
            schema: required(schema, "schema")?,
            algorithm: required(algorithm, "algorithm")?,
            digest: required(digest, "digest")?,
            signature: required(signature, "signature")?,
            public_key: required(public_key, "public_key")?,
            key_fingerprint: required(key_fingerprint, "key_fingerprint")?,
            signer: signer.unwrap_or_default(),
        })
    }
}

impl<'de> Deserialize<'de> for RawDigest {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(RawDigestVisitor)
    }
}

struct RawDigestVisitor;

impl<'de> Visitor<'de> for RawDigestVisitor {
    type Value = RawDigest;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a digest object")
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut seen = HashSet::new();
        let mut algorithm = None;
        let mut value = None;
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(de::Error::custom("duplicate field"));
            }
            match key.as_str() {
                "algorithm" => algorithm = Some(map.next_value()?),
                "value" => value = Some(map.next_value()?),
                _ => return Err(de::Error::unknown_field(&key, DIGEST_FIELDS)),
            }
        }
        Ok(RawDigest {
            algorithm: required(algorithm, "algorithm")?,
            value: required(value, "value")?,
        })
    }
}

struct RawSigner(SignerMetadata);

impl<'de> Deserialize<'de> for RawSigner {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(RawSignerVisitor)
    }
}

struct RawSignerVisitor;

impl<'de> Visitor<'de> for RawSignerVisitor {
    type Value = RawSigner;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a signer object")
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut seen = HashSet::new();
        let mut label = None;
        let mut claimed_at = None;
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(de::Error::custom("duplicate field"));
            }
            match key.as_str() {
                "label" => label = Some(map.next_value()?),
                "claimed_at" => claimed_at = Some(map.next_value()?),
                _ => return Err(de::Error::unknown_field(&key, SIGNER_FIELDS)),
            }
        }
        Ok(RawSigner(SignerMetadata { label, claimed_at }))
    }
}

fn required<T, E: de::Error>(value: Option<T>, field: &'static str) -> std::result::Result<T, E> {
    value.ok_or_else(|| de::Error::missing_field(field))
}

const ENVELOPE_FIELDS: &[&str] = &[
    "schema",
    "algorithm",
    "digest",
    "signature",
    "public_key",
    "key_fingerprint",
    "signer",
];
const DIGEST_FIELDS: &[&str] = &["algorithm", "value"];
const SIGNER_FIELDS: &[&str] = &["label", "claimed_at"];

#[derive(Serialize)]
struct EnvelopeJson<'a> {
    schema: &'static str,
    algorithm: &'static str,
    digest: DigestJson<'a>,
    signature: String,
    public_key: String,
    key_fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    signer: Option<SignerJson<'a>>,
}

#[derive(Serialize)]
struct DigestJson<'a> {
    algorithm: &'static str,
    value: String,
    #[serde(skip)]
    _phantom: std::marker::PhantomData<&'a ()>,
}

#[derive(Serialize)]
struct SignerJson<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    claimed_at: Option<&'a str>,
}

impl<'a> From<&'a SigningEnvelope> for EnvelopeJson<'a> {
    fn from(value: &'a SigningEnvelope) -> Self {
        let signer = if value.signer.label.is_some() || value.signer.claimed_at.is_some() {
            Some(SignerJson {
                label: value.signer.label.as_deref(),
                claimed_at: value.signer.claimed_at.as_deref(),
            })
        } else {
            None
        };
        Self {
            schema: SIGNATURE_SCHEMA,
            algorithm: SIGNING_ALGORITHM,
            digest: DigestJson {
                algorithm: DIGEST_ALGORITHM,
                value: encode_base64url(&value.digest_value),
                _phantom: std::marker::PhantomData,
            },
            signature: encode_base64url(&value.signature),
            public_key: encode_base64url(&value.public_key),
            key_fingerprint: encode_base64url(&value.key_fingerprint),
            signer,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seclusor_crypto::sign as primitive_sign;

    const V020_COMPATIBILITY_ASSET: &[u8] =
        include_bytes!("../testdata/v0.2.0/signing-compatibility-asset.txt");
    const V020_COMPATIBILITY_ENVELOPE: &[u8] =
        include_bytes!("../testdata/v0.2.0/signing-compatibility.secsig");
    const V020_COMPATIBILITY_PUBLIC_KEY: [u8; 32] = [
        0x21, 0x52, 0xf8, 0xd1, 0x9b, 0x79, 0x1d, 0x24, 0x45, 0x32, 0x42, 0xe1, 0x5f, 0x2e, 0xab,
        0x6c, 0xb7, 0xcf, 0xfa, 0x7b, 0x6a, 0x5e, 0xd3, 0x00, 0x97, 0x96, 0x0e, 0x06, 0x98, 0x81,
        0xdb, 0x12,
    ];
    const V020_COMPATIBILITY_DIGEST: [u8; 32] = [
        0x72, 0x0c, 0xce, 0xbe, 0x38, 0x74, 0x1d, 0xf8, 0xc4, 0x46, 0xc9, 0x46, 0x51, 0x17, 0x0d,
        0x52, 0xd3, 0xec, 0xde, 0x28, 0x4c, 0x21, 0x4e, 0x4e, 0x52, 0xb1, 0xae, 0xc8, 0xd2, 0x3d,
        0x92, 0x63,
    ];
    const V020_COMPATIBILITY_FINGERPRINT: [u8; 32] = [
        0x30, 0x97, 0xe2, 0xde, 0xe2, 0xcb, 0x4a, 0x34, 0xb5, 0x38, 0x40, 0xcd, 0xb7, 0x05, 0xae,
        0xd7, 0x10, 0x67, 0xc3, 0x6f, 0x68, 0xdb, 0x0e, 0x0f, 0x55, 0x9c, 0x3f, 0x3f, 0xa0, 0x43,
        0x31, 0x5f,
    ];
    const V020_COMPATIBILITY_PAYLOAD: &[u8] = &[
        0x73, 0x65, 0x63, 0x6c, 0x75, 0x73, 0x6f, 0x72, 0x2e, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74,
        0x75, 0x72, 0x65, 0x2e, 0x76, 0x31, 0x00, 0x00, 0x00, 0x00, 0x15, 0x73, 0x65, 0x63, 0x6c,
        0x75, 0x73, 0x6f, 0x72, 0x2e, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x2e,
        0x76, 0x31, 0x00, 0x00, 0x00, 0x07, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x00, 0x00,
        0x00, 0x07, 0x53, 0x48, 0x41, 0x2d, 0x32, 0x35, 0x36, 0x00, 0x00, 0x00, 0x20, 0x72, 0x0c,
        0xce, 0xbe, 0x38, 0x74, 0x1d, 0xf8, 0xc4, 0x46, 0xc9, 0x46, 0x51, 0x17, 0x0d, 0x52, 0xd3,
        0xec, 0xde, 0x28, 0x4c, 0x21, 0x4e, 0x4e, 0x52, 0xb1, 0xae, 0xc8, 0xd2, 0x3d, 0x92, 0x63,
        0x00, 0x00, 0x00, 0x20, 0x21, 0x52, 0xf8, 0xd1, 0x9b, 0x79, 0x1d, 0x24, 0x45, 0x32, 0x42,
        0xe1, 0x5f, 0x2e, 0xab, 0x6c, 0xb7, 0xcf, 0xfa, 0x7b, 0x6a, 0x5e, 0xd3, 0x00, 0x97, 0x96,
        0x0e, 0x06, 0x98, 0x81, 0xdb, 0x12, 0x00, 0x00, 0x00, 0x20, 0x30, 0x97, 0xe2, 0xde, 0xe2,
        0xcb, 0x4a, 0x34, 0xb5, 0x38, 0x40, 0xcd, 0xb7, 0x05, 0xae, 0xd7, 0x10, 0x67, 0xc3, 0x6f,
        0x68, 0xdb, 0x0e, 0x0f, 0x55, 0x9c, 0x3f, 0x3f, 0xa0, 0x43, 0x31, 0x5f, 0x01, 0x00, 0x00,
        0x00, 0x0f, 0x72, 0x65, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x2d, 0x73, 0x69, 0x67, 0x6e, 0x69,
        0x6e, 0x67, 0x01, 0x00, 0x00, 0x00, 0x14, 0x32, 0x30, 0x32, 0x36, 0x2d, 0x30, 0x35, 0x2d,
        0x31, 0x31, 0x54, 0x30, 0x30, 0x3a, 0x30, 0x30, 0x3a, 0x30, 0x30, 0x5a,
    ];

    fn keypair() -> (SigningSecretKey, [u8; 32]) {
        let kp = generate_signing_keypair().expect("generate");
        let public_key = signing_public_key_to_bytes(kp.public_key());
        let secret_key =
            signing_secret_key_from_bytes(&signing_secret_key_to_bytes(kp.secret_key()))
                .expect("secret");
        (secret_key, public_key)
    }

    fn signed_fixture() -> (Vec<u8>, SigningEnvelope, [u8; 32]) {
        let asset = b"release asset".to_vec();
        let (secret_key, public_key) = keypair();
        let envelope = sign_asset(
            asset.as_slice(),
            &secret_key,
            &SignOptions {
                signer: SignerMetadata {
                    label: Some("release-signing".to_string()),
                    claimed_at: Some("2026-05-17T12:00:00Z".to_string()),
                },
            },
        )
        .expect("sign");
        (asset, envelope, public_key)
    }

    fn verify_ok(asset: &[u8], envelope: &SigningEnvelope, public_key: [u8; 32]) {
        let json = envelope_to_json_pretty(envelope).expect("json");
        verify_asset(
            asset,
            json.as_bytes(),
            &VerifyOptions {
                expected_public_key: Some(public_key),
                expected_fingerprint: None,
                trust_embedded_key: false,
            },
        )
        .expect("verify");
    }

    fn verify_err(asset: &[u8], envelope_json: &[u8], public_key: [u8; 32]) -> SignError {
        verify_asset(
            asset,
            envelope_json,
            &VerifyOptions {
                expected_public_key: Some(public_key),
                expected_fingerprint: None,
                trust_embedded_key: false,
            },
        )
        .expect_err("verification must fail")
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let (asset, envelope, public_key) = signed_fixture();
        verify_ok(&asset, &envelope, public_key);
    }

    #[test]
    fn v020_signature_envelope_and_sha_vectors_are_byte_exact() {
        let envelope = parse_envelope(V020_COMPATIBILITY_ENVELOPE).expect("v0.2.0 envelope");
        assert_eq!(envelope.public_key, V020_COMPATIBILITY_PUBLIC_KEY);
        assert_eq!(envelope.digest_value, V020_COMPATIBILITY_DIGEST);
        assert_eq!(envelope.key_fingerprint, V020_COMPATIBILITY_FINGERPRINT);
        assert_eq!(
            fingerprint_public_key(&V020_COMPATIBILITY_PUBLIC_KEY),
            V020_COMPATIBILITY_FINGERPRINT
        );
        assert_eq!(
            canonical_payload_bytes(&envelope).expect("canonical payload"),
            V020_COMPATIBILITY_PAYLOAD
        );
        assert_eq!(
            format!(
                "{}\n",
                envelope_to_json_pretty(&envelope).expect("canonical envelope")
            )
            .as_bytes(),
            V020_COMPATIBILITY_ENVELOPE
        );

        let verification = verify_asset(
            V020_COMPATIBILITY_ASSET,
            V020_COMPATIBILITY_ENVELOPE,
            &VerifyOptions {
                expected_public_key: Some(V020_COMPATIBILITY_PUBLIC_KEY),
                expected_fingerprint: Some(V020_COMPATIBILITY_FINGERPRINT),
                trust_embedded_key: false,
            },
        )
        .expect("v0.2.0 fixture verifies with upgraded implementation");
        assert_eq!(verification.public_key, V020_COMPATIBILITY_PUBLIC_KEY);
        assert_eq!(verification.key_fingerprint, V020_COMPATIBILITY_FINGERPRINT);

        let secret = signing_secret_key_from_bytes(&[0x42_u8; 32]).expect("v0.2.0 fixed seed");
        let regenerated = sign_asset(
            V020_COMPATIBILITY_ASSET,
            &secret,
            &SignOptions {
                signer: SignerMetadata {
                    label: Some("release-signing".to_owned()),
                    claimed_at: Some("2026-05-11T00:00:00Z".to_owned()),
                },
            },
        )
        .expect("upgraded implementation signs fixed fixture");
        assert_eq!(regenerated, envelope);
    }

    #[test]
    fn json_reorder_and_whitespace_are_positive_cases() {
        let (asset, envelope, public_key) = signed_fixture();
        let json = format!(
            "{{\n  \"public_key\": \"{}\",\n  \"digest\": {{ \"value\": \"{}\", \"algorithm\": \"SHA-256\" }},\n  \"schema\": \"seclusor.signature.v1\",\n  \"key_fingerprint\": \"{}\",\n  \"algorithm\": \"Ed25519\",\n  \"signer\": {{ \"claimed_at\": \"2026-05-17T12:00:00Z\", \"label\": \"release-signing\" }},\n  \"signature\": \"{}\"\n}}",
            encode_base64url(&envelope.public_key),
            encode_base64url(&envelope.digest_value),
            encode_base64url(&envelope.key_fingerprint),
            encode_base64url(&envelope.signature)
        );

        verify_asset(
            asset.as_slice(),
            json.as_bytes(),
            &VerifyOptions {
                expected_public_key: Some(public_key),
                expected_fingerprint: None,
                trust_embedded_key: false,
            },
        )
        .expect("verify reordered json");
    }

    #[test]
    fn strict_parser_rejects_duplicate_unknown_null_and_padded_base64() {
        let (asset, envelope, public_key) = signed_fixture();
        let valid = envelope_to_json_pretty(&envelope).expect("json");
        let duplicate = valid.replace(
            "\"label\": \"release-signing\"",
            "\"label\": \"release-signing\", \"label\": \"other\"",
        );
        let unknown = valid.replace(
            "\"schema\": \"seclusor.signature.v1\"",
            "\"schema\": \"seclusor.signature.v1\", \"extra\": true",
        );
        let null_label = valid.replace("\"label\": \"release-signing\"", "\"label\": null");
        let padded = valid.replace(
            &format!(
                "\"signature\": \"{}\"",
                encode_base64url(&envelope.signature)
            ),
            &format!(
                "\"signature\": \"{}=\"",
                encode_base64url(&envelope.signature)
            ),
        );

        for json in [duplicate, unknown, null_label, padded] {
            let err = verify_asset(
                asset.as_slice(),
                json.as_bytes(),
                &VerifyOptions {
                    expected_public_key: Some(public_key),
                    expected_fingerprint: None,
                    trust_embedded_key: false,
                },
            )
            .expect_err("strict parse failure");
            assert!(matches!(err, SignError::ParserRejected));
        }
    }

    #[test]
    fn verification_failure_classes_follow_ddr_order() {
        let (asset, envelope, public_key) = signed_fixture();
        let json = envelope_to_json_pretty(&envelope).expect("json");

        let err = verify_asset(
            b"tampered asset".as_slice(),
            json.as_bytes(),
            &VerifyOptions {
                expected_public_key: Some(public_key),
                expected_fingerprint: None,
                trust_embedded_key: false,
            },
        )
        .expect_err("asset mismatch");
        assert!(matches!(err, SignError::AssetDigestMismatch));

        let mut invalid_public_key = envelope.clone();
        invalid_public_key.public_key = [0x02; 32];
        invalid_public_key.key_fingerprint = fingerprint_public_key(&invalid_public_key.public_key);
        let json = envelope_to_json_pretty(&invalid_public_key).expect("json");
        let err = verify_asset(
            b"different asset so digest would fail later".as_slice(),
            json.as_bytes(),
            &VerifyOptions {
                expected_public_key: Some(public_key),
                expected_fingerprint: None,
                trust_embedded_key: false,
            },
        )
        .expect_err("invalid public key first");
        assert!(matches!(err, SignError::PublicKeyInvalid));

        let (_, other_public_key) = keypair();
        let mut fingerprint_mismatch = envelope.clone();
        fingerprint_mismatch.public_key = other_public_key;
        let json = envelope_to_json_pretty(&fingerprint_mismatch).expect("json");
        let err = verify_asset(
            asset.as_slice(),
            json.as_bytes(),
            &VerifyOptions {
                expected_public_key: Some(public_key),
                expected_fingerprint: None,
                trust_embedded_key: false,
            },
        )
        .expect_err("fingerprint mismatch");
        assert!(matches!(err, SignError::FingerprintMismatch));

        let mut signature_invalid = envelope.clone();
        signature_invalid.signer.label = Some("other-label".to_string());
        let json = envelope_to_json_pretty(&signature_invalid).expect("json");
        let err = verify_asset(
            asset.as_slice(),
            json.as_bytes(),
            &VerifyOptions {
                expected_public_key: Some(public_key),
                expected_fingerprint: None,
                trust_embedded_key: false,
            },
        )
        .expect_err("signature invalid");
        assert!(matches!(err, SignError::SignatureInvalid));
    }

    #[test]
    fn ddr_negative_vectors_are_covered() {
        let (asset, envelope, public_key) = signed_fixture();
        let json = envelope_to_json_pretty(&envelope).expect("json");

        // 1. Asset bytes tampered.
        assert!(matches!(
            verify_err(b"tampered", json.as_bytes(), public_key),
            SignError::AssetDigestMismatch
        ));

        // 2. Digest value tampered.
        let mut tampered_digest = envelope.clone();
        tampered_digest.digest_value = [9_u8; 32];
        assert!(matches!(
            verify_err(
                &asset,
                envelope_to_json_pretty(&tampered_digest)
                    .expect("json")
                    .as_bytes(),
                public_key,
            ),
            SignError::AssetDigestMismatch
        ));

        // 3 and 13. Digest/algorithm exact literals.
        let bad_digest_algorithm = json.replace("\"SHA-256\"", "\"SHA-512\"");
        assert!(matches!(
            verify_err(&asset, bad_digest_algorithm.as_bytes(), public_key),
            SignError::ParserRejected
        ));
        let bad_algorithm = json.replace("\"Ed25519\"", "\"ed25519\"");
        assert!(matches!(
            verify_err(&asset, bad_algorithm.as_bytes(), public_key),
            SignError::ParserRejected
        ));

        // 4. Public key tampered but still structurally valid.
        let (_, other_public_key) = keypair();
        let mut tampered_public_key = envelope.clone();
        tampered_public_key.public_key = other_public_key;
        assert!(matches!(
            verify_err(
                &asset,
                envelope_to_json_pretty(&tampered_public_key)
                    .expect("json")
                    .as_bytes(),
                public_key,
            ),
            SignError::FingerprintMismatch
        ));

        // 5. Fingerprint tampered.
        let mut tampered_fingerprint = envelope.clone();
        tampered_fingerprint.key_fingerprint = [7_u8; 32];
        assert!(matches!(
            verify_err(
                &asset,
                envelope_to_json_pretty(&tampered_fingerprint)
                    .expect("json")
                    .as_bytes(),
                public_key,
            ),
            SignError::FingerprintMismatch
        ));

        // 6. Signer label changed.
        let mut label_changed = envelope.clone();
        label_changed.signer.label = Some("other".to_string());
        assert!(matches!(
            verify_err(
                &asset,
                envelope_to_json_pretty(&label_changed)
                    .expect("json")
                    .as_bytes(),
                public_key,
            ),
            SignError::SignatureInvalid
        ));

        // 7. Signer label absent -> empty.
        let (secret_key, public_key_no_signer) = keypair();
        let no_signer = sign_asset(asset.as_slice(), &secret_key, &SignOptions::default())
            .expect("sign without signer");
        let mut empty_label = no_signer.clone();
        empty_label.signer.label = Some(String::new());
        assert!(matches!(
            verify_err(
                &asset,
                envelope_to_json_pretty(&empty_label)
                    .expect("json")
                    .as_bytes(),
                public_key_no_signer,
            ),
            SignError::SignatureInvalid
        ));

        // 8. Signer label empty -> absent.
        let empty_label_signed = sign_asset(
            asset.as_slice(),
            &secret_key,
            &SignOptions {
                signer: SignerMetadata {
                    label: Some(String::new()),
                    claimed_at: None,
                },
            },
        )
        .expect("sign with empty label");
        let mut absent_label = empty_label_signed.clone();
        absent_label.signer.label = None;
        assert!(matches!(
            verify_err(
                &asset,
                envelope_to_json_pretty(&absent_label)
                    .expect("json")
                    .as_bytes(),
                public_key_no_signer,
            ),
            SignError::SignatureInvalid
        ));

        // 9. claimed_at altered.
        let mut claimed_at_changed = envelope.clone();
        claimed_at_changed.signer.claimed_at = Some("2026-05-17T12:00:01Z".to_string());
        assert!(matches!(
            verify_err(
                &asset,
                envelope_to_json_pretty(&claimed_at_changed)
                    .expect("json")
                    .as_bytes(),
                public_key,
            ),
            SignError::SignatureInvalid
        ));

        // 10. claimed_at absent -> present.
        let mut claimed_at_added = no_signer.clone();
        claimed_at_added.signer.claimed_at = Some("2026-05-17T12:00:00Z".to_string());
        assert!(matches!(
            verify_err(
                &asset,
                envelope_to_json_pretty(&claimed_at_added)
                    .expect("json")
                    .as_bytes(),
                public_key_no_signer,
            ),
            SignError::SignatureInvalid
        ));

        // 14. Unicode normalization variant changes signed bytes.
        let composed = sign_asset(
            asset.as_slice(),
            &secret_key,
            &SignOptions {
                signer: SignerMetadata {
                    label: Some("é".to_string()),
                    claimed_at: None,
                },
            },
        )
        .expect("sign composed label");
        let decomposed_json = envelope_to_json_pretty(&composed)
            .expect("json")
            .replace("é", "e\u{0301}");
        assert!(matches!(
            verify_err(&asset, decomposed_json.as_bytes(), public_key_no_signer),
            SignError::SignatureInvalid
        ));

        // 15. Domain separator altered by signing over a non-v1 payload.
        let mut wrong_domain = envelope.clone();
        let mut payload = canonical_payload_bytes(&wrong_domain).expect("payload");
        payload[0] ^= 0x01;
        let bad_signature = primitive_sign(&secret_key, &payload).expect("sign bad domain");
        wrong_domain.signature = signature_to_bytes(&bad_signature);
        assert!(matches!(
            verify_err(
                &asset,
                envelope_to_json_pretty(&wrong_domain)
                    .expect("json")
                    .as_bytes(),
                public_key,
            ),
            SignError::SignatureInvalid
        ));

        // 16-20. Strict parser/encoding vectors.
        let padded = json.replace(
            &format!(
                "\"signature\": \"{}\"",
                encode_base64url(&envelope.signature)
            ),
            &format!(
                "\"signature\": \"{}=\"",
                encode_base64url(&envelope.signature)
            ),
        );
        let duplicate = json.replace(
            "\"label\": \"release-signing\"",
            "\"label\": \"release-signing\", \"label\": \"other\"",
        );
        let null_signer = json.replace("\"signer\": {", "\"signer\": null, \"signer_shadow\": {");
        let unknown = json.replace(
            "\"schema\": \"seclusor.signature.v1\"",
            "\"schema\": \"seclusor.signature.v1\", \"extra\": true",
        );
        let malformed_claimed_at =
            json.replace("2026-05-17T12:00:00Z", "2026-05-17T12:00:00+00:00");
        for parser_rejected in [
            padded,
            duplicate,
            null_signer,
            unknown,
            malformed_claimed_at,
        ] {
            assert!(matches!(
                verify_err(&asset, parser_rejected.as_bytes(), public_key),
                SignError::ParserRejected
            ));
        }

        // 21. Invalid 32-byte public key with recomputed matching fingerprint.
        let mut invalid_public_key = envelope.clone();
        invalid_public_key.public_key = [0x02_u8; 32];
        invalid_public_key.key_fingerprint = fingerprint_public_key(&invalid_public_key.public_key);
        assert!(matches!(
            verify_err(
                b"also tampered, but public-key-invalid must win",
                envelope_to_json_pretty(&invalid_public_key)
                    .expect("json")
                    .as_bytes(),
                public_key,
            ),
            SignError::PublicKeyInvalid
        ));
    }

    #[test]
    fn binary_size_and_expected_key_mismatch_are_distinct() {
        let (asset, envelope, public_key) = signed_fixture();
        let json = envelope_to_json_pretty(&envelope).expect("json");
        let short_signature = json.replace(
            &encode_base64url(&envelope.signature),
            &encode_base64url(&envelope.signature[..SIGNATURE_LEN - 1]),
        );
        assert!(matches!(
            verify_err(&asset, short_signature.as_bytes(), public_key),
            SignError::BinarySizeRejected
        ));

        let (_, other_public_key) = keypair();
        let err = verify_asset(
            asset.as_slice(),
            json.as_bytes(),
            &VerifyOptions {
                expected_public_key: Some(other_public_key),
                expected_fingerprint: None,
                trust_embedded_key: false,
            },
        )
        .expect_err("expected key mismatch");
        assert!(matches!(err, SignError::ExpectedKeyMismatch));
    }

    #[test]
    fn expected_key_required_by_default() {
        let (asset, envelope, _public_key) = signed_fixture();
        let json = envelope_to_json_pretty(&envelope).expect("json");
        let err = verify_asset(asset.as_slice(), json.as_bytes(), &VerifyOptions::default())
            .expect_err("expected key required");
        assert!(matches!(err, SignError::ExpectedKeyRequired));

        verify_asset(
            asset.as_slice(),
            json.as_bytes(),
            &VerifyOptions {
                trust_embedded_key: true,
                ..VerifyOptions::default()
            },
        )
        .expect("embedded trust opt-in");
    }

    #[test]
    fn signing_key_file_roundtrip() {
        let dir = tempfile::tempdir().expect("temp dir");
        let identity = Identity::generate();
        let recipient = identity.to_public();
        let path = dir.path().join("signing.key.age");
        let generated =
            generate_signing_key_file(&path, &[recipient]).expect("generate signing key file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let secret = load_signing_key_file(&path, &[identity]).expect("load signing key");
        let public_key = signing_public_key_to_bytes(&signing_public_key(&secret));
        assert_eq!(public_key, generated.public_key);
        assert_eq!(
            fingerprint_public_key(&public_key),
            generated.key_fingerprint
        );
    }

    #[test]
    fn malformed_signing_key_file_uses_key_file_error_class() {
        let dir = tempfile::tempdir().expect("temp dir");
        let identity = Identity::generate();
        let recipient = identity.to_public();
        let path = dir.path().join("signing.key.age");
        let plaintext = br#"{"schema":"seclusor.signing-key.v1","algorithm":"Ed25519","secret_key":"not valid!"}"#;
        let ciphertext = seclusor_crypto::encrypt(plaintext, &[recipient]).expect("encrypt");
        fs::write(&path, ciphertext).expect("write key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        }

        match load_signing_key_file(&path, &[identity]) {
            Err(SignError::SigningKeyFileInvalid) => {}
            Err(err) => panic!("unexpected error class: {err}"),
            Ok(_) => panic!("invalid key file loaded"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn signing_key_file_owner_uid_check_rejects_mismatch() {
        assert!(validate_owner_uids(1000, 1000).is_ok());
        let err = validate_owner_uids(1001, 1000).expect_err("uid mismatch");
        assert!(matches!(
            err,
            SignError::SigningKeyFileWrongOwner {
                file_uid: 1001,
                current_uid: 1000
            }
        ));
    }

    #[test]
    fn claimed_at_requires_valid_utc_timestamp_ranges() {
        for valid in [
            "2026-01-01T00:00:00Z",
            "2024-02-29T23:59:59Z",
            "2000-02-29T12:30:45Z",
        ] {
            assert!(is_strict_claimed_at(valid), "{valid}");
        }

        for invalid in [
            "2026-00-01T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-04-31T00:00:00Z",
            "2026-02-29T00:00:00Z",
            "2100-02-29T00:00:00Z",
            "2026-01-01T24:00:00Z",
            "2026-01-01T00:60:00Z",
            "2026-01-01T00:00:60Z",
            "2026-99-99T99:99:99Z",
        ] {
            assert!(!is_strict_claimed_at(invalid), "{invalid}");
        }
    }

    #[test]
    fn claimed_at_and_label_validation() {
        let (asset, mut envelope, public_key) = signed_fixture();
        envelope.signer.claimed_at = Some("2026-05-17T12:00:00+00:00".to_string());
        let json = envelope_to_json_pretty(&envelope).expect("json");
        let err = verify_asset(
            asset.as_slice(),
            json.as_bytes(),
            &VerifyOptions {
                expected_public_key: Some(public_key),
                expected_fingerprint: None,
                trust_embedded_key: false,
            },
        )
        .expect_err("bad claimed_at");
        assert!(matches!(err, SignError::ParserRejected));

        envelope.signer.claimed_at = Some("2026-05-17T12:00:00Z".to_string());
        envelope.signer.label = Some(" release-signing".to_string());
        let json = envelope_to_json_pretty(&envelope).expect("json");
        let err = verify_asset(
            asset.as_slice(),
            json.as_bytes(),
            &VerifyOptions {
                expected_public_key: Some(public_key),
                expected_fingerprint: None,
                trust_embedded_key: false,
            },
        )
        .expect_err("bad label");
        assert!(matches!(err, SignError::ParserRejected));
    }
}
