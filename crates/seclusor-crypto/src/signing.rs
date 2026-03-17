use ed25519_dalek::Signature as DalekSignature;
use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey as DalekSigningKey;
use ed25519_dalek::Verifier;
use ed25519_dalek::VerifyingKey as DalekVerifyingKey;
use rand_core::{OsRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{CryptoError, Result};

pub const SIGNING_SECRET_KEY_LEN: usize = 32;
pub const SIGNING_PUBLIC_KEY_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;

pub struct SigningKeypair {
    secret_key: SigningSecretKey,
    public_key: SigningPublicKey,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SigningSecretKey([u8; SIGNING_SECRET_KEY_LEN]);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningPublicKey(DalekVerifyingKey);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature(DalekSignature);

impl SigningKeypair {
    pub fn secret_key(&self) -> &SigningSecretKey {
        &self.secret_key
    }

    pub fn public_key(&self) -> &SigningPublicKey {
        &self.public_key
    }
}

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

pub fn sign(secret_key: &SigningSecretKey, message: &[u8]) -> Result<Signature> {
    let signing_key = DalekSigningKey::from_bytes(&secret_key.0);
    Ok(Signature(signing_key.sign(message)))
}

pub fn verify(public_key: &SigningPublicKey, message: &[u8], signature: &Signature) -> Result<()> {
    public_key
        .0
        .verify(message, &signature.0)
        .map_err(|_| CryptoError::SignatureVerificationFailed)
}

pub fn signing_public_key(secret_key: &SigningSecretKey) -> SigningPublicKey {
    let signing_key = DalekSigningKey::from_bytes(&secret_key.0);
    SigningPublicKey(signing_key.verifying_key())
}

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

pub fn signing_public_key_from_bytes(bytes: &[u8]) -> Result<SigningPublicKey> {
    let bytes: [u8; SIGNING_PUBLIC_KEY_LEN] = bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidPublicKeyBytes)?;
    let key =
        DalekVerifyingKey::from_bytes(&bytes).map_err(|_| CryptoError::InvalidPublicKeyBytes)?;
    Ok(SigningPublicKey(key))
}

pub fn signature_from_bytes(bytes: &[u8]) -> Result<Signature> {
    let bytes: [u8; SIGNATURE_LEN] = bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidSignatureBytes)?;
    Ok(Signature(DalekSignature::from_bytes(&bytes)))
}

pub fn signing_secret_key_to_bytes(secret_key: &SigningSecretKey) -> [u8; SIGNING_SECRET_KEY_LEN] {
    secret_key.0
}

pub fn signing_public_key_to_bytes(public_key: &SigningPublicKey) -> [u8; SIGNING_PUBLIC_KEY_LEN] {
    public_key.0.to_bytes()
}

pub fn signature_to_bytes(signature: &Signature) -> [u8; SIGNATURE_LEN] {
    signature.0.to_bytes()
}
