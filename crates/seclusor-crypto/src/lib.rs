//! seclusor-crypto
//!
//! Encryption boundary for seclusor (age wrapper). Library consumers (e.g.
//! lanyte-attest) will link this crate directly.

mod error;
#[cfg(feature = "signing")]
mod signing;

use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use age::secrecy::ExposeSecret;
use age::secrecy::SecretString;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use seclusor_core::constants::{
    INLINE_CIPHERTEXT_PREFIX, MAX_BUNDLE_PLAINTEXT_BYTES, MAX_DECRYPT_PLAINTEXT_BYTES,
    MAX_INLINE_CIPHERTEXT_BYTES, MAX_INLINE_PLAINTEXT_BYTES,
};

const MAX_IDENTITY_FILE_BYTES: u64 = 1024 * 1024;

pub use error::{CryptoError, Result};
#[cfg(feature = "signing")]
pub use signing::{
    generate_signing_keypair, sign, signature_from_bytes, signature_to_bytes, signing_public_key,
    signing_public_key_from_bytes, signing_public_key_to_bytes, signing_secret_key_from_bytes,
    signing_secret_key_to_bytes, verify, Signature, SigningKeypair, SigningPublicKey,
    SigningSecretKey, SIGNATURE_LEN, SIGNING_PUBLIC_KEY_LEN, SIGNING_SECRET_KEY_LEN,
};

/// Type alias for X25519 recipient.
pub type Recipient = age::x25519::Recipient;

/// Type alias for X25519 identity.
pub type Identity = age::x25519::Identity;

/// Render an identity as plaintext string for identity-file persistence.
pub fn identity_to_string(identity: &Identity) -> String {
    identity.to_string().expose_secret().to_owned()
}

/// Parse recipient strings into X25519 recipients.
pub fn parse_recipients<I, S>(recipients: I) -> Result<Vec<Recipient>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut parsed = Vec::new();
    for (index, recipient) in recipients.into_iter().enumerate() {
        let recipient = recipient.as_ref().trim();
        if recipient.is_empty() {
            return Err(CryptoError::InvalidRecipient { index });
        }
        let parsed_recipient = recipient
            .parse::<Recipient>()
            .map_err(|_| CryptoError::InvalidRecipient { index })?;
        parsed.push(parsed_recipient);
    }

    if parsed.is_empty() {
        return Err(CryptoError::MissingRecipients);
    }

    Ok(parsed)
}

/// Parse identity strings into X25519 identities.
pub fn parse_identities<I, S>(identities: I) -> Result<Vec<Identity>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut parsed = Vec::new();
    for (index, identity) in identities.into_iter().enumerate() {
        let identity = identity.as_ref().trim();
        if identity.is_empty() {
            return Err(CryptoError::InvalidIdentity { index });
        }
        let parsed_identity = identity
            .parse::<Identity>()
            .map_err(|_| CryptoError::InvalidIdentity { index })?;
        parsed.push(parsed_identity);
    }

    if parsed.is_empty() {
        return Err(CryptoError::MissingIdentities);
    }

    Ok(parsed)
}

/// Parse age identities from file contents.
///
/// Empty lines and comment lines beginning with `#` are ignored.
pub fn parse_identity_file_contents(contents: &str) -> Result<Vec<Identity>> {
    let mut identities = Vec::new();

    for (line_number, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let identity =
            line.parse::<Identity>()
                .map_err(|_| CryptoError::InvalidIdentityFileLine {
                    line: line_number + 1,
                })?;
        identities.push(identity);
    }

    if identities.is_empty() {
        return Err(CryptoError::EmptyIdentityFile);
    }

    Ok(identities)
}

/// Load and parse age identities from a file.
///
/// On Unix, file permissions must be exactly `0600`.
pub fn load_identity_file(path: impl AsRef<Path>) -> Result<Vec<Identity>> {
    let path = path.as_ref();
    assert_secure_permissions(path)?;
    let contents = read_identity_file_with_limit(path, MAX_IDENTITY_FILE_BYTES)?;
    parse_identity_file_contents(&contents)
}

/// Encrypt plaintext for one or more recipients.
pub fn encrypt(plaintext: &[u8], recipients: &[Recipient]) -> Result<Vec<u8>> {
    if recipients.is_empty() {
        return Err(CryptoError::MissingRecipients);
    }
    ensure_size_limit("plaintext", plaintext.len(), MAX_BUNDLE_PLAINTEXT_BYTES)?;

    let encryptor =
        age::Encryptor::with_recipients(recipients.iter().map(|r| r as &dyn age::Recipient))
            .map_err(|_| CryptoError::EncryptionFailed)?;

    let mut ciphertext = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut ciphertext)
        .map_err(|_| CryptoError::EncryptionFailed)?;
    writer
        .write_all(plaintext)
        .map_err(|_| CryptoError::EncryptionFailed)?;
    writer.finish().map_err(|_| CryptoError::EncryptionFailed)?;

    Ok(ciphertext)
}

/// Encrypt plaintext for recipients specified as string values.
pub fn encrypt_with_recipient_strings<I, S>(plaintext: &[u8], recipients: I) -> Result<Vec<u8>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let recipients = parse_recipients(recipients)?;
    encrypt(plaintext, &recipients)
}

/// Decrypt ciphertext with one or more identities.
pub fn decrypt(ciphertext: &[u8], identities: &[Identity]) -> Result<Vec<u8>> {
    decrypt_with_limit(ciphertext, identities, MAX_DECRYPT_PLAINTEXT_BYTES)
}

/// Decrypt ciphertext with identities specified as string values.
pub fn decrypt_with_identity_strings<I, S>(ciphertext: &[u8], identities: I) -> Result<Vec<u8>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let identities = parse_identities(identities)?;
    decrypt(ciphertext, &identities)
}

/// Encrypt plaintext using a human passphrase (scrypt mode).
pub fn encrypt_with_passphrase(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    ensure_size_limit("plaintext", plaintext.len(), MAX_BUNDLE_PLAINTEXT_BYTES)?;
    let encryptor = age::Encryptor::with_user_passphrase(SecretString::from(passphrase.to_owned()));

    let mut ciphertext = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut ciphertext)
        .map_err(|_| CryptoError::EncryptionFailed)?;
    writer
        .write_all(plaintext)
        .map_err(|_| CryptoError::EncryptionFailed)?;
    writer.finish().map_err(|_| CryptoError::EncryptionFailed)?;

    Ok(ciphertext)
}

/// Decrypt ciphertext using a human passphrase (scrypt mode).
pub fn decrypt_with_passphrase(ciphertext: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    let decryptor =
        age::Decryptor::new_buffered(ciphertext).map_err(|_| CryptoError::InvalidCiphertext)?;
    let passphrase_identity = age::scrypt::Identity::new(SecretString::from(passphrase.to_owned()));
    let mut reader = decryptor
        .decrypt(std::iter::once(&passphrase_identity as &dyn age::Identity))
        .map_err(|_| CryptoError::DecryptionFailed)?;
    read_to_vec_with_limit(&mut reader, MAX_DECRYPT_PLAINTEXT_BYTES, "plaintext")
}

/// Encrypt a single inline value into `sec:age:v1:<base64>`.
pub fn encrypt_inline_value(plaintext: &[u8], recipients: &[Recipient]) -> Result<String> {
    ensure_size_limit(
        "inline plaintext",
        plaintext.len(),
        MAX_INLINE_PLAINTEXT_BYTES,
    )?;
    let ciphertext = encrypt(plaintext, recipients)?;
    ensure_size_limit(
        "inline ciphertext",
        ciphertext.len(),
        MAX_INLINE_CIPHERTEXT_BYTES,
    )?;
    let encoded = BASE64_STANDARD.encode(ciphertext);
    Ok(format!("{INLINE_CIPHERTEXT_PREFIX}{encoded}"))
}

/// Decrypt a `sec:age:v1:<base64>` inline value.
pub fn decrypt_inline_value(ciphertext: &str, identities: &[Identity]) -> Result<Vec<u8>> {
    let raw = decode_inline_ciphertext(ciphertext)?;
    decrypt_with_limit(&raw, identities, MAX_INLINE_PLAINTEXT_BYTES)
}

/// Decrypt a `sec:age:v1:<base64>` inline value using passphrase mode.
pub fn decrypt_inline_value_with_passphrase(ciphertext: &str, passphrase: &str) -> Result<Vec<u8>> {
    let raw = decode_inline_ciphertext(ciphertext)?;
    let plaintext = decrypt_with_passphrase(&raw, passphrase)?;
    ensure_size_limit(
        "inline plaintext",
        plaintext.len(),
        MAX_INLINE_PLAINTEXT_BYTES,
    )?;
    Ok(plaintext)
}

fn decrypt_with_limit(
    ciphertext: &[u8],
    identities: &[Identity],
    max_plaintext: usize,
) -> Result<Vec<u8>> {
    if identities.is_empty() {
        return Err(CryptoError::MissingIdentities);
    }

    let decryptor =
        age::Decryptor::new_buffered(ciphertext).map_err(|_| CryptoError::DecryptionFailed)?;
    let mut reader = decryptor
        .decrypt(identities.iter().map(|i| i as &dyn age::Identity))
        .map_err(|_| CryptoError::DecryptionFailed)?;

    read_to_vec_with_limit(&mut reader, max_plaintext, "plaintext")
}

fn decode_inline_ciphertext(ciphertext: &str) -> Result<Vec<u8>> {
    if !ciphertext.starts_with(INLINE_CIPHERTEXT_PREFIX) {
        return Err(CryptoError::InvalidInlineCiphertextPrefix);
    }
    let encoded = &ciphertext[INLINE_CIPHERTEXT_PREFIX.len()..];
    let max_encoded_len = max_base64_encoded_len(MAX_INLINE_CIPHERTEXT_BYTES);
    if encoded.len() > max_encoded_len {
        return Err(CryptoError::SizeLimitExceeded {
            kind: "inline ciphertext (base64)",
            actual: encoded.len(),
            max: max_encoded_len,
        });
    }
    let decoded = BASE64_STANDARD
        .decode(encoded)
        .map_err(|_| CryptoError::InvalidInlineCiphertextEncoding)?;
    ensure_size_limit(
        "inline ciphertext",
        decoded.len(),
        MAX_INLINE_CIPHERTEXT_BYTES,
    )?;
    Ok(decoded)
}

fn max_base64_encoded_len(max_decoded_len: usize) -> usize {
    max_decoded_len.div_ceil(3) * 4
}

fn read_to_vec_with_limit<R: Read>(
    reader: &mut R,
    max: usize,
    kind: &'static str,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = [0_u8; 8192];
    loop {
        let n = reader.read(&mut buf).map_err(CryptoError::Io)?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
        if out.len() > max {
            return Err(CryptoError::SizeLimitExceeded {
                kind,
                actual: out.len(),
                max,
            });
        }
    }
    Ok(out)
}

fn ensure_size_limit(kind: &'static str, actual: usize, max: usize) -> Result<()> {
    if actual > max {
        return Err(CryptoError::SizeLimitExceeded { kind, actual, max });
    }
    Ok(())
}

/// Check that an identity file has secure permissions (0600 on Unix).
///
/// On non-Unix platforms this is a no-op.
pub fn assert_secure_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = fs::metadata(path)?.permissions().mode() & 0o777;
        if mode != 0o600 {
            return Err(CryptoError::InsecureIdentityFilePermissions { actual: mode });
        }
    }

    #[cfg(not(unix))]
    {
        let _ = path;
    }

    Ok(())
}

fn read_identity_file_with_limit(path: &Path, max: u64) -> Result<String> {
    let actual = fs::metadata(path)?.len();
    if actual > max {
        return Err(CryptoError::IdentityFileTooLarge { actual, max });
    }

    let mut file = std::fs::File::open(path)?;
    let mut limited = std::io::Read::by_ref(&mut file).take(max + 1);
    let mut contents = String::new();
    limited.read_to_string(&mut contents)?;

    if contents.len() as u64 > max {
        return Err(CryptoError::IdentityFileTooLarge {
            actual: contents.len() as u64,
            max,
        });
    }

    Ok(contents)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    #[cfg(feature = "signing")]
    use zeroize::Zeroize;

    const TEST_IDENTITY: &str =
        "AGE-SECRET-KEY-1GQ9778VQXMMJVE8SK7J6VT8UJ4HDQAJUVSFCWCM02D8GEWQ72PVQ2Y5J33";

    fn parsed_identity() -> Identity {
        parse_identities([TEST_IDENTITY]).expect("test identity must parse")[0].clone()
    }

    fn parsed_recipient() -> Recipient {
        parsed_identity().to_public()
    }

    fn raw_encrypt_with_passphrase(plaintext: &[u8], passphrase: &str) -> Vec<u8> {
        let encryptor =
            age::Encryptor::with_user_passphrase(SecretString::from(passphrase.to_owned()));
        let mut ciphertext = Vec::new();
        let mut writer = encryptor
            .wrap_output(&mut ciphertext)
            .expect("raw encryptor should wrap output");
        writer
            .write_all(plaintext)
            .expect("raw encryptor should write plaintext");
        writer.finish().expect("raw encryptor should finalize");
        ciphertext
    }

    #[test]
    fn recipient_roundtrip_known_vector() {
        let recipient = parsed_recipient();
        let identity = parsed_identity();
        let plaintext = b"test payload";

        let ciphertext = encrypt(plaintext, &[recipient]).expect("encrypt should succeed");
        let decrypted = decrypt(&ciphertext, &[identity]).expect("decrypt should succeed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn passphrase_roundtrip() {
        let plaintext = b"passphrase test payload";
        let passphrase = "correct horse battery staple";

        let ciphertext =
            encrypt_with_passphrase(plaintext, passphrase).expect("encrypt should succeed");
        let decrypted =
            decrypt_with_passphrase(&ciphertext, passphrase).expect("decrypt should succeed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_identity_fails_without_leaking_plaintext() {
        let recipient = parsed_recipient();
        let wrong_identity = age::x25519::Identity::generate();
        let plaintext = b"supersecret-plaintext";

        let ciphertext = encrypt(plaintext, &[recipient]).expect("encrypt should succeed");
        let err = decrypt(&ciphertext, &[wrong_identity]).expect_err("decrypt must fail");
        let msg = err.to_string();

        assert!(matches!(err, CryptoError::DecryptionFailed));
        assert!(!msg.contains("supersecret-plaintext"));
    }

    #[test]
    fn wrong_passphrase_fails_without_leaking_passphrase() {
        let plaintext = b"payload";
        let ciphertext =
            encrypt_with_passphrase(plaintext, "good passphrase").expect("encrypt should succeed");
        let err = decrypt_with_passphrase(&ciphertext, "bad passphrase").expect_err("must fail");
        let msg = err.to_string();

        assert!(matches!(err, CryptoError::DecryptionFailed));
        assert!(!msg.contains("bad passphrase"));
    }

    #[test]
    fn parse_identity_file_contents_handles_comments_and_blank_lines() {
        let contents = format!("# comment\n\n{TEST_IDENTITY}\n");
        let identities = parse_identity_file_contents(&contents).expect("parse should succeed");
        assert_eq!(identities.len(), 1);
    }

    #[test]
    fn parse_identity_file_contents_reports_line_number() {
        let contents = "not-an-identity";
        let err = match parse_identity_file_contents(contents) {
            Ok(_) => panic!("parse must fail"),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            CryptoError::InvalidIdentityFileLine { line: 1 }
        ));
    }

    #[test]
    fn inline_prefix_validation() {
        let identity = parsed_identity();
        let err = decrypt_inline_value("bad-prefix", &[identity]).expect_err("must fail");
        assert!(matches!(err, CryptoError::InvalidInlineCiphertextPrefix));
    }

    #[test]
    fn inline_invalid_base64_validation() {
        let identity = parsed_identity();
        let err = decrypt_inline_value("sec:age:v1:%%%not-base64%%%", &[identity])
            .expect_err("must fail");
        assert!(matches!(err, CryptoError::InvalidInlineCiphertextEncoding));
    }

    #[test]
    fn inline_encoded_length_prechecked_before_decode() {
        let identity = parsed_identity();
        let oversized = "A".repeat(max_base64_encoded_len(MAX_INLINE_CIPHERTEXT_BYTES) + 1);
        let inline = format!("{INLINE_CIPHERTEXT_PREFIX}{oversized}");

        let err = decrypt_inline_value(&inline, &[identity]).expect_err("must fail");
        assert!(matches!(
            err,
            CryptoError::SizeLimitExceeded {
                kind: "inline ciphertext (base64)",
                ..
            }
        ));
    }

    #[test]
    fn inline_roundtrip() {
        let recipient = parsed_recipient();
        let identity = parsed_identity();
        let plaintext = b"inline-value";

        let inline = encrypt_inline_value(plaintext, &[recipient]).expect("encrypt should succeed");
        assert!(inline.starts_with(INLINE_CIPHERTEXT_PREFIX));

        let decrypted = decrypt_inline_value(&inline, &[identity]).expect("decrypt should succeed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn inline_plaintext_limit_enforced() {
        let recipient = parsed_recipient();
        let plaintext = vec![b'a'; MAX_INLINE_PLAINTEXT_BYTES + 1];
        let err = encrypt_inline_value(&plaintext, &[recipient]).expect_err("must fail");
        assert!(matches!(err, CryptoError::SizeLimitExceeded { .. }));
    }

    #[test]
    fn inline_ciphertext_limit_enforced_before_decrypt() {
        let too_large = vec![0_u8; MAX_INLINE_CIPHERTEXT_BYTES + 1];
        let encoded = BASE64_STANDARD.encode(too_large);
        let inline = format!("{INLINE_CIPHERTEXT_PREFIX}{encoded}");
        let identity = parsed_identity();
        let err = decrypt_inline_value(&inline, &[identity]).expect_err("must fail");
        assert!(matches!(err, CryptoError::SizeLimitExceeded { .. }));
    }

    #[test]
    fn decrypt_plaintext_limit_enforced() {
        let passphrase = "passphrase";
        let plaintext = vec![b'x'; MAX_DECRYPT_PLAINTEXT_BYTES + 1];
        let ciphertext = raw_encrypt_with_passphrase(&plaintext, passphrase);
        let err = decrypt_with_passphrase(&ciphertext, passphrase).expect_err("must fail");
        assert!(matches!(err, CryptoError::SizeLimitExceeded { .. }));
    }

    #[test]
    #[cfg(unix)]
    fn identity_file_permissions_checked() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("identity.txt");
        let mut file = std::fs::File::create(&path).expect("create file");
        writeln!(file, "{TEST_IDENTITY}").expect("write identity");
        drop(file);

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("set permissions");
        let err = match load_identity_file(&path) {
            Ok(_) => panic!("must fail"),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            CryptoError::InsecureIdentityFilePermissions { .. }
        ));
    }

    #[test]
    fn load_identity_file_success() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("identity.txt");
        let mut file = std::fs::File::create(&path).expect("create file");
        writeln!(file, "{TEST_IDENTITY}").expect("write identity");
        drop(file);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("set permissions");
        }

        let identities = load_identity_file(&path).expect("load should succeed");
        assert_eq!(identities.len(), 1);
    }

    #[test]
    fn load_identity_file_rejects_oversized_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("identity.txt");
        let file = std::fs::File::create(&path).expect("create file");
        file.set_len(MAX_IDENTITY_FILE_BYTES + 1)
            .expect("set file length");
        drop(file);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("set permissions");
        }

        let err = match load_identity_file(&path) {
            Ok(_) => panic!("must fail"),
            Err(err) => err,
        };
        assert!(matches!(err, CryptoError::IdentityFileTooLarge { .. }));
    }

    #[cfg(feature = "signing")]
    #[test]
    fn signing_roundtrip_and_byte_contract() {
        let kp = generate_signing_keypair().expect("generate keypair");
        let message = b"signing payload";

        let sig = sign(kp.secret_key(), message).expect("sign");
        verify(kp.public_key(), message, &sig).expect("verify");

        let secret = signing_secret_key_to_bytes(kp.secret_key());
        let public = signing_public_key_to_bytes(kp.public_key());
        let signature = signature_to_bytes(&sig);
        assert_eq!(secret.len(), SIGNING_SECRET_KEY_LEN);
        assert_eq!(public.len(), SIGNING_PUBLIC_KEY_LEN);
        assert_eq!(signature.len(), SIGNATURE_LEN);
    }

    #[cfg(feature = "signing")]
    #[test]
    fn signing_from_bytes_and_verify_follow_error_contract() {
        let err = signing_secret_key_from_bytes(&[7_u8; SIGNING_SECRET_KEY_LEN - 1])
            .err()
            .expect("bad secret");
        assert!(matches!(err, CryptoError::InvalidSecretKeyBytes));

        let err = match signing_public_key_from_bytes(&[7_u8; SIGNING_PUBLIC_KEY_LEN - 1]) {
            Ok(_) => panic!("bad public must fail"),
            Err(err) => err,
        };
        assert!(matches!(err, CryptoError::InvalidPublicKeyBytes));

        let err = match signing_public_key_from_bytes(&[0x02_u8; SIGNING_PUBLIC_KEY_LEN]) {
            Ok(_) => panic!("malformed public key must fail"),
            Err(err) => err,
        };
        assert!(matches!(err, CryptoError::InvalidPublicKeyBytes));

        let err = match signature_from_bytes(&[7_u8; SIGNATURE_LEN - 1]) {
            Ok(_) => panic!("bad signature must fail"),
            Err(err) => err,
        };
        assert!(matches!(err, CryptoError::InvalidSignatureBytes));

        let kp = generate_signing_keypair().expect("generate");
        let sig = sign(kp.secret_key(), b"message-a").expect("sign");
        let err = verify(kp.public_key(), b"message-b", &sig).expect_err("must fail verify");
        assert!(matches!(err, CryptoError::SignatureVerificationFailed));

        let malformed_signature =
            signature_from_bytes(&[0xff_u8; SIGNATURE_LEN]).expect("64-byte signature parses");
        let err = verify(kp.public_key(), b"message-a", &malformed_signature)
            .expect_err("malformed signature must fail verify");
        assert!(matches!(err, CryptoError::SignatureVerificationFailed));
    }

    #[cfg(feature = "signing")]
    #[test]
    fn signing_key_at_rest_roundtrip() {
        let recipient = parsed_recipient();
        let identity = parsed_identity();
        let message = b"jwt payload bytes";

        let kp = generate_signing_keypair().expect("generate");
        let mut encoded = signing_secret_key_to_bytes(kp.secret_key()).to_vec();
        let ciphertext = encrypt(&encoded, &[recipient]).expect("encrypt signing key");
        encoded.zeroize();
        assert!(encoded.iter().all(|b| *b == 0));

        let mut decrypted = decrypt(&ciphertext, &[identity]).expect("decrypt signing key");
        let secret_key = signing_secret_key_from_bytes(&decrypted).expect("rebuild signing key");
        decrypted.zeroize();
        assert!(decrypted.iter().all(|b| *b == 0));

        let signature = sign(&secret_key, message).expect("sign");
        let public_key = signing_public_key(&secret_key);
        verify(&public_key, message, &signature).expect("verify");
    }
}
