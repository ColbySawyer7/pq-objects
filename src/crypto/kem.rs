//! ML-KEM-768 key generation, encapsulation, and secret handling.

use ml_kem::array::Array;
use ml_kem::kem::{Decapsulate, Encapsulate, FromSeed, Kem, KeyExport};
use ml_kem::{EncapsulationKey, MlKem768};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};

/// Length of an ML-KEM-768 encapsulation (public) key in bytes.
pub const PUBLIC_KEY_LEN: usize = 1184;

/// Length of an ML-KEM-768 ciphertext in bytes.
pub const CIPHERTEXT_LEN: usize = 1088;

/// Length of the preferred ML-KEM-768 seed encoding in bytes.
pub const SEED_LEN: usize = 64;

/// Length of an ML-KEM shared secret in bytes.
pub const SHARED_SECRET_LEN: usize = 32;

/// ML-KEM-768 public (encapsulation) key bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey(pub(crate) Vec<u8>);

impl PublicKey {
    /// Create a public key from raw ML-KEM-768 encapsulation key bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] if the length is incorrect or the key fails
    /// validation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PUBLIC_KEY_LEN {
            return Err(Error::crypto(format!(
                "public key must be {PUBLIC_KEY_LEN} bytes, got {}",
                bytes.len()
            )));
        }
        let arr: Array<u8, _> = bytes
            .try_into()
            .map_err(|_| Error::crypto("invalid public key length"))?;
        EncapsulationKey::<MlKem768>::new(&arr).map_err(|_| Error::crypto("invalid public key"))?;
        Ok(Self(bytes.to_vec()))
    }

    /// Borrow the raw public key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicKey")
            .field("len", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// ML-KEM-768 private key material stored as a 64-byte seed.
///
/// This type intentionally does not implement `Clone`, `Debug` with key bytes,
/// or serialization traits.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; SEED_LEN]);

impl SecretKey {
    /// Create a secret key from a 64-byte seed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] if `bytes` is not exactly 64 bytes.
    pub fn from_seed(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SEED_LEN {
            return Err(Error::crypto(format!(
                "secret seed must be {SEED_LEN} bytes, got {}",
                bytes.len()
            )));
        }
        let mut seed = [0u8; SEED_LEN];
        seed.copy_from_slice(bytes);
        // Validate by reconstructing the keypair.
        let arr: Array<u8, _> = seed
            .as_slice()
            .try_into()
            .map_err(|_| Error::crypto("invalid seed length"))?;
        let _ = MlKem768::from_seed(&arr);
        Ok(Self(seed))
    }

    pub(crate) fn as_seed_array(&self) -> Array<u8, ml_kem::array::typenum::U64> {
        Array::try_from(self.0.as_slice()).expect("seed length is fixed at 64")
    }

    /// Borrow the 64-byte seed encoding.
    ///
    /// # Security
    ///
    /// This is private key material. Prefer keeping it in [`SecretKey`] rather
    /// than copying into application buffers.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SEED_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey([REDACTED])")
    }
}

/// Shared secret established by ML-KEM encapsulation.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret([u8; SHARED_SECRET_LEN]);

impl SharedSecret {
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SHARED_SECRET_LEN {
            return Err(Error::crypto("invalid shared secret length"));
        }
        let mut out = [0u8; SHARED_SECRET_LEN];
        out.copy_from_slice(bytes);
        Ok(Self(out))
    }

    pub(crate) fn as_bytes(&self) -> &[u8; SHARED_SECRET_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SharedSecret([REDACTED])")
    }
}

/// Generate a fresh ML-KEM-768 keypair.
///
/// # Security
///
/// Uses the operating-system CSPRNG. The returned [`SecretKey`] must be stored
/// outside object storage.
#[must_use]
pub fn generate_keypair() -> (SecretKey, PublicKey) {
    let (dk, ek) = MlKem768::generate_keypair();
    let seed = dk.to_seed().expect("generated keys always have a seed");
    let secret = SecretKey(seed.as_slice().try_into().expect("ML-KEM seed is 64 bytes"));
    let public = PublicKey(ek.to_bytes().to_vec());
    (secret, public)
}

/// Reconstruct a keypair from a 64-byte seed.
pub(crate) fn keypair_from_seed(
    secret: &SecretKey,
) -> (ml_kem::DecapsulationKey<MlKem768>, PublicKey) {
    let (dk, ek) = MlKem768::from_seed(&secret.as_seed_array());
    (dk, PublicKey(ek.to_bytes().to_vec()))
}

/// Encapsulate to `public`, returning `(kem_ciphertext, shared_secret)`.
///
/// # Errors
///
/// Returns [`Error::Crypto`] if the public key is invalid.
pub fn encapsulate(public: &PublicKey) -> Result<(Vec<u8>, SharedSecret)> {
    let arr: Array<u8, _> = public
        .as_bytes()
        .try_into()
        .map_err(|_| Error::crypto("invalid public key length"))?;
    let ek =
        EncapsulationKey::<MlKem768>::new(&arr).map_err(|_| Error::crypto("invalid public key"))?;
    let (ct, ss) = ek.encapsulate();
    Ok((ct.to_vec(), SharedSecret::from_bytes(ss.as_slice())?))
}

/// Decapsulate `ciphertext` with `secret`.
pub(crate) fn decapsulate(secret: &SecretKey, ciphertext: &[u8]) -> Result<SharedSecret> {
    if ciphertext.len() != CIPHERTEXT_LEN {
        return Err(Error::crypto(format!(
            "kem ciphertext must be {CIPHERTEXT_LEN} bytes, got {}",
            ciphertext.len()
        )));
    }
    let (dk, _) = keypair_from_seed(secret);
    let ss = dk
        .decapsulate_slice(ciphertext)
        .map_err(|_| Error::crypto("invalid kem ciphertext length"))?;
    SharedSecret::from_bytes(ss.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kem_round_trip() {
        let (sk, pk) = generate_keypair();
        let (ct, ss1) = encapsulate(&pk).unwrap();
        let ss2 = decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }

    #[test]
    fn secret_debug_redacted() {
        let (sk, _) = generate_keypair();
        let s = format!("{sk:?}");
        assert!(s.contains("REDACTED"));
        assert!(!s.contains(&hex_preview(sk.as_bytes())));
    }

    fn hex_preview(bytes: &[u8]) -> String {
        bytes
            .iter()
            .take(4)
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join("")
    }
}
