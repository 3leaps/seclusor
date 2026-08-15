use ed25519_dalek::Signature as DalekSignature;
use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey as DalekSigningKey;
use ed25519_dalek::Verifier;
use ed25519_dalek::VerifyingKey as DalekVerifyingKey;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[cfg(test)]
use std::{cell::RefCell, rc::Rc};

use crate::{CryptoError, Result};

/// Length of an Ed25519 secret key (seed) in bytes.
pub const SIGNING_SECRET_KEY_LEN: usize = 32;
/// Length of an Ed25519 public key in bytes.
pub const SIGNING_PUBLIC_KEY_LEN: usize = 32;
/// Length of an Ed25519 signature in bytes.
pub const SIGNATURE_LEN: usize = 64;

/// An Ed25519 signing keypair containing both the secret and public key.
///
/// Access the components via [`secret_key()`](Self::secret_key) and
/// [`public_key()`](Self::public_key) accessors. Does not implement `Debug`
/// to prevent accidental secret-key exposure in logs.
pub struct SigningKeypair {
    secret_key: SigningSecretKey,
    public_key: SigningPublicKey,
}

/// An Ed25519 secret key stored as the canonical 32-byte seed.
///
/// Backend signing state is derived ephemerally for each operation.
/// Implements `Zeroize` and `ZeroizeOnDrop` to clear key material on drop.
/// Does not implement `Debug`, `Display`, `Clone`, or serde.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SigningSecretKey([u8; SIGNING_SECRET_KEY_LEN]);

/// An Ed25519 public (verifying) key.
///
/// Safe to clone, log, and compare. Use [`signing_public_key_to_bytes`] to
/// export the canonical 32-byte form for storage or transmission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningPublicKey(DalekVerifyingKey);

/// An Ed25519 signature (64 bytes).
///
/// Use [`signature_to_bytes`] to export the canonical form. Use [`verify`]
/// to check a signature against a public key and message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature(DalekSignature);

struct TransientSigningSeed {
    bytes: Zeroizing<[u8; SIGNING_SECRET_KEY_LEN]>,
    #[cfg(test)]
    drop_observer: Option<Rc<RefCell<Option<[u8; SIGNING_SECRET_KEY_LEN]>>>>,
}

impl TransientSigningSeed {
    fn new() -> Self {
        Self {
            bytes: Zeroizing::new([0_u8; SIGNING_SECRET_KEY_LEN]),
            #[cfg(test)]
            drop_observer: None,
        }
    }

    #[cfg(test)]
    fn observed(drop_observer: Rc<RefCell<Option<[u8; SIGNING_SECRET_KEY_LEN]>>>) -> Self {
        Self {
            bytes: Zeroizing::new([0_u8; SIGNING_SECRET_KEY_LEN]),
            drop_observer: Some(drop_observer),
        }
    }
}

impl Drop for TransientSigningSeed {
    fn drop(&mut self) {
        self.bytes.zeroize();
        #[cfg(test)]
        if let Some(observer) = &self.drop_observer {
            observer.replace(Some(*self.bytes));
        }
    }
}

impl SigningKeypair {
    /// Returns a reference to the secret key.
    pub fn secret_key(&self) -> &SigningSecretKey {
        &self.secret_key
    }

    /// Returns a reference to the public key.
    pub fn public_key(&self) -> &SigningPublicKey {
        &self.public_key
    }
}

/// Generate a new Ed25519 signing keypair using OS-provided randomness.
///
/// The secret key is a 32-byte seed generated directly from OS entropy. The
/// transient seed buffer is zeroized on both success and failure.
///
/// # Errors
///
/// Returns [`CryptoError::Io`] if OS entropy is unavailable. Backend error
/// details are not exposed.
pub fn generate_signing_keypair() -> Result<SigningKeypair> {
    let seed = TransientSigningSeed::new();
    generate_signing_keypair_with_entropy(seed, getrandom::fill)
}

fn signing_key_generation_error() -> CryptoError {
    CryptoError::Io(std::io::Error::other("signing key generation failed"))
}

fn generate_signing_keypair_with_entropy<E>(
    mut seed: TransientSigningSeed,
    fill: impl FnOnce(&mut [u8]) -> std::result::Result<(), E>,
) -> Result<SigningKeypair> {
    fill(seed.bytes.as_mut()).map_err(|_| signing_key_generation_error())?;
    let secret_key = SigningSecretKey(*seed.bytes);
    seed.bytes.zeroize();
    let public_key = signing_public_key(&secret_key);
    Ok(SigningKeypair {
        secret_key,
        public_key,
    })
}

/// Sign a message with an Ed25519 secret key.
///
/// Derives the backend signing key ephemerally from the stored seed,
/// signs the message, and returns the 64-byte signature.
///
/// The message is treated as opaque bytes with no text assumptions.
pub fn sign(secret_key: &SigningSecretKey, message: &[u8]) -> Result<Signature> {
    let signing_key = DalekSigningKey::from_bytes(&secret_key.0);
    Ok(Signature(signing_key.sign(message)))
}

/// Verify an Ed25519 signature against a message and public key.
///
/// # Errors
///
/// Returns [`CryptoError::SignatureVerificationFailed`] if the signature
/// does not verify. This includes both cryptographically incorrect
/// signatures and semantically invalid 64-byte values that only fail at
/// verify time. No key or message content is included in the error.
pub fn verify(public_key: &SigningPublicKey, message: &[u8], signature: &Signature) -> Result<()> {
    public_key
        .0
        .verify(message, &signature.0)
        .map_err(|_| CryptoError::SignatureVerificationFailed)
}

/// Derive the Ed25519 public key from a secret key.
///
/// Consumers should store and distribute the public key separately for
/// verification-only use cases rather than requiring the secret key.
pub fn signing_public_key(secret_key: &SigningSecretKey) -> SigningPublicKey {
    let signing_key = DalekSigningKey::from_bytes(&secret_key.0);
    SigningPublicKey(signing_key.verifying_key())
}

/// Construct a [`SigningSecretKey`] from the canonical 32-byte seed form.
///
/// The input buffer is copied and the caller is responsible for zeroizing
/// the source bytes if they contain sensitive material.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidSecretKeyBytes`] if `bytes` is not
/// exactly 32 bytes.
pub fn signing_secret_key_from_bytes(bytes: &[u8]) -> Result<SigningSecretKey> {
    if bytes.len() != SIGNING_SECRET_KEY_LEN {
        return Err(CryptoError::InvalidSecretKeyBytes);
    }

    let mut seed = [0_u8; SIGNING_SECRET_KEY_LEN];
    seed.copy_from_slice(bytes);
    let secret_key = SigningSecretKey(seed);
    seed.zeroize();
    Ok(secret_key)
}

/// Construct a [`SigningPublicKey`] from the canonical 32-byte form.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidPublicKeyBytes`] if `bytes` is not
/// exactly 32 bytes or is not a valid Ed25519 public key encoding.
pub fn signing_public_key_from_bytes(bytes: &[u8]) -> Result<SigningPublicKey> {
    let bytes: [u8; SIGNING_PUBLIC_KEY_LEN] = bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidPublicKeyBytes)?;
    let key =
        DalekVerifyingKey::from_bytes(&bytes).map_err(|_| CryptoError::InvalidPublicKeyBytes)?;
    Ok(SigningPublicKey(key))
}

/// Construct a [`Signature`] from the canonical 64-byte form.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidSignatureBytes`] if `bytes` is not
/// exactly 64 bytes. Note that some structurally valid 64-byte values
/// may only fail at [`verify`] time.
pub fn signature_from_bytes(bytes: &[u8]) -> Result<Signature> {
    let bytes: [u8; SIGNATURE_LEN] = bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidSignatureBytes)?;
    Ok(Signature(DalekSignature::from_bytes(&bytes)))
}

/// Export a secret key as its canonical 32-byte seed.
///
/// The returned array contains sensitive material. The caller should
/// zeroize it after use (e.g., after encrypting with age for storage).
pub fn signing_secret_key_to_bytes(secret_key: &SigningSecretKey) -> [u8; SIGNING_SECRET_KEY_LEN] {
    secret_key.0
}

/// Export a public key as its canonical 32-byte form.
pub fn signing_public_key_to_bytes(public_key: &SigningPublicKey) -> [u8; SIGNING_PUBLIC_KEY_LEN] {
    public_key.0.to_bytes()
}

/// Export a signature as its canonical 64-byte form.
pub fn signature_to_bytes(signature: &Signature) -> [u8; SIGNATURE_LEN] {
    signature.0.to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXED_SEED: [u8; SIGNING_SECRET_KEY_LEN] = [0x42; SIGNING_SECRET_KEY_LEN];
    const FIXED_PUBLIC_KEY: [u8; SIGNING_PUBLIC_KEY_LEN] = [
        0x21, 0x52, 0xf8, 0xd1, 0x9b, 0x79, 0x1d, 0x24, 0x45, 0x32, 0x42, 0xe1, 0x5f, 0x2e, 0xab,
        0x6c, 0xb7, 0xcf, 0xfa, 0x7b, 0x6a, 0x5e, 0xd3, 0x00, 0x97, 0x96, 0x0e, 0x06, 0x98, 0x81,
        0xdb, 0x12,
    ];
    const FIXED_SIGNATURE: [u8; SIGNATURE_LEN] = [
        0xb4, 0x41, 0x19, 0x66, 0x3e, 0x5c, 0x91, 0x40, 0xec, 0x20, 0x2c, 0x96, 0x00, 0x13, 0x44,
        0xfa, 0x1f, 0x8b, 0x99, 0x60, 0xdf, 0x1d, 0x10, 0x38, 0xbb, 0x62, 0x91, 0x1d, 0x76, 0xe2,
        0x9e, 0x4c, 0xb5, 0xb2, 0x61, 0x8e, 0xf4, 0x54, 0xcd, 0x56, 0x92, 0xb1, 0xec, 0x24, 0x07,
        0xaf, 0x65, 0xb0, 0xad, 0xf3, 0xa1, 0x1b, 0xd2, 0x25, 0xc7, 0x35, 0x20, 0xdd, 0xf6, 0x32,
        0xbb, 0xdd, 0x7f, 0x03,
    ];

    fn observed_seed() -> (
        TransientSigningSeed,
        Rc<RefCell<Option<[u8; SIGNING_SECRET_KEY_LEN]>>>,
    ) {
        let observer = Rc::new(RefCell::new(None));
        (
            TransientSigningSeed::observed(Rc::clone(&observer)),
            observer,
        )
    }

    fn assert_seed_was_cleared(observer: &Rc<RefCell<Option<[u8; SIGNING_SECRET_KEY_LEN]>>>) {
        assert_eq!(
            observer.borrow().as_ref(),
            Some(&[0_u8; SIGNING_SECRET_KEY_LEN])
        );
    }

    #[test]
    fn fixed_seed_preserves_public_key_and_signature_bytes() {
        let secret_key = signing_secret_key_from_bytes(&FIXED_SEED).expect("fixed seed");
        let public_key = signing_public_key(&secret_key);
        let signature = sign(
            &secret_key,
            b"seclusor v0.2.0 primitive compatibility vector",
        )
        .expect("fixed signature");

        assert_eq!(signing_public_key_to_bytes(&public_key), FIXED_PUBLIC_KEY);
        assert_eq!(signature_to_bytes(&signature), FIXED_SIGNATURE);
        verify(
            &public_key,
            b"seclusor v0.2.0 primitive compatibility vector",
            &signature,
        )
        .expect("fixed signature verifies");
    }

    #[test]
    fn entropy_partial_write_failure_is_generic_and_clears_seed() {
        let (seed, observer) = observed_seed();
        let err = match generate_signing_keypair_with_entropy(seed, |bytes| {
            bytes[..8].fill(0xa5);
            Err("backend=probe errno=5 partial=a5")
        }) {
            Ok(_) => panic!("entropy failure must fail closed"),
            Err(err) => err,
        };

        match &err {
            CryptoError::Io(source) => assert_eq!(source.kind(), std::io::ErrorKind::Other),
            _ => panic!("entropy failure must preserve the existing I/O error class"),
        }
        assert_eq!(err.to_string(), "I/O error: signing key generation failed");
        assert!(!err.to_string().contains("probe"));
        assert!(!err.to_string().contains("errno"));
        assert_seed_was_cleared(&observer);
    }

    #[test]
    fn entropy_success_clears_transient_seed_and_preserves_private_wrapper() {
        fn assert_zeroizing_secret<T: Zeroize + ZeroizeOnDrop>() {}

        assert_zeroizing_secret::<SigningSecretKey>();
        assert_eq!(
            std::mem::size_of::<SigningSecretKey>(),
            SIGNING_SECRET_KEY_LEN
        );

        let (seed, observer) = observed_seed();
        let keypair = generate_signing_keypair_with_entropy(seed, |bytes| {
            bytes.copy_from_slice(&FIXED_SEED);
            Ok::<_, std::convert::Infallible>(())
        })
        .expect("fixed entropy succeeds");

        assert_eq!(
            signing_public_key_to_bytes(keypair.public_key()),
            FIXED_PUBLIC_KEY
        );
        assert_seed_was_cleared(&observer);
    }
}
