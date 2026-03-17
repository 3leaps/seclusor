use ed25519_dalek::Signature as DalekSignature;
use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey as DalekSigningKey;
use ed25519_dalek::Verifier;
use ed25519_dalek::VerifyingKey as DalekVerifyingKey;
use rand_core::{OsRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

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
/// The secret key is a 32-byte seed generated from `OsRng`. The transient
/// seed buffer is zeroized immediately after construction.
///
/// # Errors
///
/// Returns `CryptoError` if keypair generation fails (should not occur
/// under normal OS conditions).
pub fn generate_signing_keypair() -> Result<SigningKeypair> {
    let mut seed = [0_u8; SIGNING_SECRET_KEY_LEN];
    OsRng.fill_bytes(&mut seed);
    let secret_key = SigningSecretKey(seed);
    seed.zeroize();
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
